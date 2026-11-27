package balancer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/xray"
)

// trafficServerXray — in-process Xray с StatsService + policy (user/outbound
// counters), vless-inbound на loopback и freedom, разрешающим loopback-таргеты
// (ядро 26.11.9 по умолчанию блокирует private). Возвращает клиент и порт inbound.
func trafficServerXray(t *testing.T) (*xray.Client, int) {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	apiAddr := ln.Addr().String()
	ln.Close()
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	vlessPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()
	cfgJSON := fmt.Sprintf(`{
	 "log": {"loglevel": "error"},
	 "api": {"tag": "api", "listen": %q, "services": ["HandlerService", "RoutingService", "StatsService"]},
	 "stats": {},
	 "policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}},
	   "system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}},
	 "inbounds": [
	  {"tag": "api-in", "listen": "127.0.0.1", "port": 0, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}},
	  {"tag": "vless-in", "listen": "127.0.0.1", "port": %d, "protocol": "vless",
	   "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "client@example.com"}], "decryption": "none"}}
	 ],
	 "outbounds": [
	  {"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}},
	  {"tag": "api", "protocol": "freedom"},
	  {"tag": "node-nl-1", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}
	 ],
	 "routing": {"domainStrategy": "AsIs", "rules": [
	  {"type": "field", "inboundTag": ["api-in"], "outboundTag": "api", "ruleTag": "api"},
	  {"type": "field", "user": ["client@example.com"], "outboundTag": "node-nl-1", "ruleTag": "c:client@example.com:NL"}
	 ]}
	}`, apiAddr, vlessPort)
	return startXrayAPIWithConfig(t, cfgJSON), vlessPort
}

// vlessFetch — raw vless TCP CONNECT до target (без TLS/flow): шлём payload,
// читаем ответ. Гонит РЕАЛЬНЫЙ трафик через inbound/outbound ядра → counters.
func vlessFetch(t *testing.T, port int, targetHost string, targetPort int, payload []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil { t.Fatalf("vless dial: %v", err) }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	// request: ver(0) uuid(16) addonsLen(0) cmd(1=TCP) port(2,BE) addrType(1=IPv4) ip(4)
	var hdr bytes.Buffer
	hdr.WriteByte(0)
	uuidBytes := [16]byte{0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11}
	hdr.Write(uuidBytes[:])
	hdr.WriteByte(0) // addons len
	hdr.WriteByte(1) // TCP
	binary.Write(&hdr, binary.BigEndian, uint16(targetPort))
	hdr.WriteByte(1) // IPv4
	hdr.Write(net.ParseIP(targetHost).To4())
	if _, err := conn.Write(hdr.Bytes()); err != nil { t.Fatalf("hdr: %v", err) }
	// response-заголовок (ver+addonsLen) ядро буферизует до первого payload —
	// шлём запрос СРАЗУ, читаем 2 байта заголовка, затем тело ответа
	if _, err := conn.Write(payload); err != nil { t.Fatalf("payload: %v", err) }
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil { t.Fatalf("resp hdr: %v", err) }
	out, err := io.ReadAll(conn)
	if err != nil { t.Fatalf("read: %v", err) }
	return out
}

// TestTrafficAccumulationE2E — накопление lifetime-трафика клиента и ноды на
// РЕАЛЬНОМ ядре: дельты между опросами, повторный опрос не задваивает, сброс
// счётчика (QueryStats reset=true — как читает биллинг) не теряет накопленное.
// Сбросы моделируются ПОСЛЕ опроса коллектора (реальный сценарий: биллинг
// сбрасывает счётчик, следующий опрос видит рост с нуля); сброс+рост выше
// прошлого значения МЕЖДУ опросами неотличим от обычного роста — задокументировано.
func TestTrafficAccumulationE2E(t *testing.T) {
	s := testStore(t)
	xc, vlessPort := trafficServerXray(t)
	c := NewController(s, xc)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 1)); err != nil { t.Fatal(err) }

	// таргет «в интернете»: отвечает эхом побольше (downlink > uplink)
	payload := bytes.Repeat([]byte("x"), 4096)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write(bytes.Repeat([]byte("y"), 64*1024))
	}))
	defer target.Close()
	th, tp, _ := net.SplitHostPort(target.Listener.Addr().String())
	var tport int
	fmt.Sscanf(tp, "%d", &tport)

	fetch := func() {
		req := append([]byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(payload))), payload...)
		out := vlessFetch(t, vlessPort, th, tport, req)
		if !bytes.Contains(out, []byte("200")) { t.Fatalf("не 200 через туннель: %.80q", out) }
	}

	// 1) первый трафик + сбор
	fetch()
	c.collectTraffic(t.Context())
	c.collectNodeTraffic(t.Context(), time.Now().Unix())
	cl1 := s.GetTrafficTotal("client", "client@example.com")
	nd1 := s.GetTrafficTotal("node", "node-nl-1")
	if cl1 == nil || cl1.Total() < 60*1024 { t.Fatalf("client после 1 fetch: %+v", cl1) }
	if nd1 == nil || nd1.Total() < 60*1024 { t.Fatalf("node после 1 fetch: %+v", nd1) }

	// 2) повторный сбор БЕЗ нового трафика — не задваиваем
	c.collectTraffic(t.Context())
	c.collectNodeTraffic(t.Context(), time.Now().Unix())
	if got := s.GetTrafficTotal("client", "client@example.com"); got.Total() != cl1.Total() {
		t.Fatalf("client задвоился: %d → %d", cl1.Total(), got.Total())
	}
	if got := s.GetTrafficTotal("node", "node-nl-1"); got.Total() != nd1.Total() {
		t.Fatalf("node задвоился: %d → %d", nd1.Total(), got.Total())
	}

	// 3) рестарт-сброс: коллектор УЖЕ снял показания, затем счётчики обнулены
	// (внешний reset=true / рестарт xray). Следующий fetch даёт малый кумулятив
	// (< last) → вся величина считается новой дельтой, история НЕ теряется.
	if _, err := xc.QueryStats(t.Context(), "user>>>client@example.com>>>traffic>>>", true); err != nil { t.Fatal(err) }
	// таргет поменьше, чтобы кумулятив после сброса гарантированно < предыдущего
	small := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write(bytes.Repeat([]byte("z"), 1024))
	}))
	defer small.Close()
	sh, sp, _ := net.SplitHostPort(small.Listener.Addr().String())
	var sport int
	fmt.Sscanf(sp, "%d", &sport)
	smallFetch := func() {
		p := []byte("hello")
		req := append([]byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(p))), p...)
		out := vlessFetch(t, vlessPort, sh, sport, req)
		if !bytes.Contains(out, []byte("200")) { t.Fatalf("small не 200: %.80q", out) }
	}
	smallFetch()
	c.collectTraffic(t.Context())
	cl3 := s.GetTrafficTotal("client", "client@example.com")
	if cl3.Total() <= cl1.Total() || cl3.Total() >= cl1.Total()+60*1024 {
		t.Fatalf("client после reset+small fetch: %d, want (%d, %d) — история+малая дельта", cl3.Total(), cl1.Total(), cl1.Total()+60*1024)
	}
	// ноды: биллинг читает reset=true → дельта. После smallFetch (шаг 3 клиент)
	// следующий сбор ноды снимает его дельту; повторный цикл без трафика не растёт.
	c.collectNodeTraffic(t.Context(), time.Now().Unix())
	nd2 := s.GetTrafficTotal("node", "node-nl-1")
	if nd2.Total() <= nd1.Total() { t.Fatalf("node не снял дельту smallFetch: %d → %d", nd1.Total(), nd2.Total()) }
	c.collectNodeTraffic(t.Context(), time.Now().Unix())
	if got := s.GetTrafficTotal("node", "node-nl-1"); got.Total() != nd2.Total() {
		t.Fatalf("node задвоился без трафика: %d → %d", nd2.Total(), got.Total())
	}
	smallFetch() // через node-nl-1 (то же per-user правило)
	c.collectNodeTraffic(t.Context(), time.Now().Unix())
	nd3 := s.GetTrafficTotal("node", "node-nl-1")
	if nd3.Total() <= nd2.Total() { t.Fatalf("node не вырос после small fetch: %d → %d", nd2.Total(), nd3.Total()) }
	// up/down раздельно непустые
	if cl3.UpBytes == 0 || cl3.DownBytes == 0 { t.Fatalf("up/down не разделены: %+v", cl3) }
	if nd3.UpBytes == 0 || nd3.DownBytes == 0 { t.Fatalf("node up/down: %+v", nd3) }

	// 4) сброс квоты (SetUsedBytes=0, как при продлении) не трогает lifetime
	s.SetUsedBytes("client@example.com", 0)
	if got := s.GetTrafficTotal("client", "client@example.com"); got.Total() != cl3.Total() {
		t.Fatalf("lifetime изменился после сброса квоты: %+v", got)
	}
	// 5) hour-бакеты зеркалят lifetime (те же дельты, включая рестарт-сброс);
	// периоды из бакетов непустые — реальный трафик попал в текущий час.
	var cu, cd, nu, nd int64
	if err := s.DB().QueryRow(`SELECT COALESCE(SUM(up),0),COALESCE(SUM(down),0) FROM traffic_hourly WHERE kind='client' AND id='client@example.com'`).Scan(&cu, &cd); err != nil { t.Fatal(err) }
	if cu != cl3.UpBytes || cd != cl3.DownBytes { t.Fatalf("бакеты клиента разошлись с lifetime: %d/%d vs %+v", cu, cd, cl3) }
	if err := s.DB().QueryRow(`SELECT COALESCE(SUM(up),0),COALESCE(SUM(down),0) FROM traffic_hourly WHERE kind='node' AND id='node-nl-1'`).Scan(&nu, &nd); err != nil { t.Fatal(err) }
	if nu != nd3.UpBytes || nd != nd3.DownBytes { t.Fatalf("бакеты ноды разошлись с lifetime: %d/%d vs %+v", nu, nd, nd3) }
	cp := s.AllTrafficPeriods("client")["client@example.com"]
	if cp.Today != cl3.Total() || cp.Week != cl3.Total() || cp.Month != cl3.Total() {
		t.Fatalf("периоды клиента не равны lifetime (весь трафик свежий): %+v vs %d", cp, cl3.Total())
	}
	np := s.AllTrafficPeriods("node")["node-nl-1"]
	if np.Today != nd3.Total() { t.Fatalf("today ноды: %+v vs %d", np, nd3.Total()) }
	_ = store.Client{}
}
