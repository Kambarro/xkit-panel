package balancer

// E2E sticky-переделки antifilter на РЕАЛЬНОМ xray 26.11.9 (XKIT_XRAY_BIN):
//   - 2 ноды одной страны: blocked-трафик клиента идёт на ОДНУ ноду стабильно
//     (не скачет между соединениями — корень жалобы владельца на random XKIT_AF),
//     лучшую по quality-score;
//   - смерть ноды → failover на другую, дальше снова sticky;
//   - reconnect (offline→online): клиент выключил VPN, лучшая нода сменилась,
//     включил → соединения идут на лучшую СЕЙЧАС;
//   - mid-session sticky: пока соединение ЖИВО, смена quality-score НЕ дёргает
//     клиента (reevaluate видит online через GetAllOnlineUsers);
//   - any → выбор из ВСЕГО пула.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	routercmd "github.com/xtls/xray-core/app/router/command"

	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/xray"
)

// afStickyMasterConfig — config.json мастера: vless-inbound (raw-клиент),
// freedom-ноды с разрешённым loopback, statsUserOnline ОБЯЗАТЕЛЕН (детект
// reconnect в reevaluate), dns.hosts резолвит blocked-домен в loopback-таргет.
func afStickyMasterConfig(t *testing.T, apiPort, vlessPort int) string {
	t.Helper()
	allowLoopback := `"settings":{"domainStrategy":"UseIPv4","finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}`
	return fmt.Sprintf(`{
	 "log": {"loglevel": "info"},
	 "dns": {"hosts": {"youtube.com": "127.0.0.1"}, "queryStrategy": "UseIPv4"},
	 "api": {"tag": "api", "listen": "127.0.0.1:%d", "services": ["HandlerService", "RoutingService", "StatsService"]},
	 "stats": {},
	 "policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true}},
	   "system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}},
	 "inbounds": [
	  {"tag": "api-in", "listen": "127.0.0.1", "port": 0, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}},
	  {"tag": "vless-in", "listen": "127.0.0.1", "port": %d, "protocol": "vless",
	   "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "client@example.com"}], "decryption": "none"}}
	 ],
	 "outbounds": [
	  {"tag": "direct", "protocol": "freedom", %s},
	  {"tag": "api", "protocol": "freedom"},
	  {"tag": "node-nl-1", "protocol": "freedom", %s},
	  {"tag": "node-nl-2", "protocol": "freedom", %s},
	  {"tag": "node-de-1", "protocol": "freedom", %s},
	  {"tag": "node-us-1", "protocol": "freedom", %s}
	 ],
	 "routing": {"domainStrategy": "AsIs", "rules": [
	  {"type": "field", "inboundTag": ["api-in"], "outboundTag": "api", "ruleTag": "api"},
	  {"type": "field", "port": "0-65535", "outboundTag": "direct"}
	 ]}
	}`, apiPort, vlessPort, allowLoopback, allowLoopback, allowLoopback, allowLoopback, allowLoopback)
}

// afStickySetup — общий стенд: store с 2 NL-нодами (+DE/US из testStore),
// реальный xray, контроллер. mode/клиент/настройка качества — на вызывающем.
func afStickySetup(t *testing.T) (*store.Store, *xray.Client, *Controller, int, string, string) {
	t.Helper()
	bin := afRealXrayBin(t)
	dir := writeTestGeoFiles(t)
	writeTestBlockedFiles(t, dir)
	s := testStore(t)
	// вторая NL-нода (в testStore NL одна) — приоритет ниже, качество задаст тест
	if err := s.UpsertNode(store.Node{ID: "node-nl-2", Name: "Amsterdam-2", Country: "NL", CountryCode: 2,
		Priority: 2, Price: 1.2, Host: "nl2.test", Tunnel: "xhttp", Health: "alive", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRoutingMode("antifilter"); err != nil {
		t.Fatal(err)
	}
	s.SetAntifilterState(antifilterStateForTest("xkit-blocked.dat", 1))
	s.SetSetting("bal_select_by_quality", "1")

	apiPort, vlessPort := freeTCPPort(t), freeTCPPort(t)
	apiAddr := fmt.Sprintf("127.0.0.1:%d", apiPort)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(afStickyMasterConfig(t, apiPort, vlessPort)), 0644); err != nil {
		t.Fatal(err)
	}
	oldPath := masterConfigPath
	masterConfigPath = cfgPath
	t.Cleanup(func() { masterConfigPath = oldPath })
	afStartXray(t, bin, cfgPath, dir, apiAddr)
	xc, err := xray.Dial(apiAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { xc.Close() })
	c := NewController(s, xc)
	return s, xc, c, vlessPort, cfgPath, bin
}

// afTargetServer — таргет blocked-сайта (маркер в ответе).
func afTargetServer(t *testing.T) (int, func()) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write([]byte("200-OK"))
	}))
	_, tpStr, _ := net.SplitHostPort(target.Listener.Addr().String())
	var port int
	fmt.Sscanf(tpStr, "%d", &port)
	return port, target.Close
}

// afRouteBlocked — TestRoute blocked-домена для клиента (персистентный роутер).
func afRouteBlocked(t *testing.T, xc *xray.Client, email string) string {
	t.Helper()
	resp, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
		InboundTag: "vless-in", User: email, TargetPort: 443, TargetDomain: "youtube.com",
	}})
	if err != nil {
		t.Fatalf("TestRoute: %v", err)
	}
	return resp.GetOutboundTag()
}

// afLocalIP — нелокальный loopback-адрес источника. УРОК ядра 26.11.9:
// OnlineMap.AddIP ИГНОРИРУЕТ 127.0.0.1/::1 (online_map.go) — с loopback-источника
// клиент НИКОГДА не попадёт в GetAllOnlineUsers. Dial с 127.0.0.2 (весь 127/8
// локален на Linux) — источник нелокальный для OnlineMap, детект работает.
func afLocalIP(t *testing.T) string {
	t.Helper()
	// проверяем bind 127.0.0.2 (Linux: весь 127/8 на lo)
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("127.0.0.2 не биндится (не Linux?) — online-детект с loopback невозможен")
	}
	ln.Close()
	return "127.0.0.2"
}

// afOpenSession —raw vless TCP CONNECT к blocked-домену, соединение ОСТАЁТСЯ
// открытым (живая сессия для online-детекта). Вернуть закрывашку.
func afOpenSession(t *testing.T, vlessPort, targetPort int) func() {
	t.Helper()
	srcIP := afLocalIP(t)
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(srcIP)}, Timeout: 3 * time.Second}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", vlessPort))
	if err != nil {
		t.Fatalf("vless dial: %v", err)
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	var hdr bytes.Buffer
	hdr.WriteByte(0)
	uuidBytes := [16]byte{0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11}
	hdr.Write(uuidBytes[:])
	hdr.WriteByte(0)
	hdr.WriteByte(1)
	binary.Write(&hdr, binary.BigEndian, uint16(targetPort))
	hdr.WriteByte(2) // domain
	hdr.WriteByte(byte(len("youtube.com")))
	hdr.WriteString("youtube.com")
	if _, err := conn.Write(hdr.Bytes()); err != nil {
		conn.Close()
		t.Fatalf("hdr: %v", err)
	}
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: youtube.com\r\n\r\n")); err != nil {
		conn.Close()
		t.Fatalf("payload: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		t.Fatalf("resp hdr (трафик порезан?): %v", err)
	}
	return func() { conn.Close() }
}

// afWaitOnline — ждём появления/исчезновения email в GetAllOnlineUsers.
func afWaitOnline(t *testing.T, xc *xray.Client, email string, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		users, err := xc.OnlineUsers(t.Context())
		if err == nil {
			has := false
			for _, u := range users {
				if u == email {
					has = true
				}
			}
			if has == want {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("online(%s)=%v не достигнут за 5с", email, want)
}

// TestAntifilterStickyNoJumpsE2E — ГЛАВНАЯ регрессия владельца: 2 ноды одной
// страны, клиент blocked-трафик → ОДНА нода (лучшая по score) на ВСЕХ соединениях.
// Random-балансир XKIT_AF давал скачки per-connection; per-user sticky — нет.
func TestAntifilterStickyNoJumpsE2E(t *testing.T) {
	s, xc, c, vlessPort, cfgPath, bin := afStickySetup(t)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatal(err)
	}
	// nl-2 лучшая по quality-score (приоритет у nl-1 ниже числом, но score решает)
	s.SetNodeQuality("node-nl-1", 50, 99, 60)
	s.SetNodeQuality("node-nl-2", 10, 100, 95)
	if _, err := c.PushAssignment(t.Context(), "client@example.com", "NL"); err != nil {
		t.Fatal(err)
	}
	a, _ := s.GetAssignment("client@example.com", "NL")
	if a == nil || a.NodeID != "node-nl-2" {
		t.Fatalf("назначение: %+v, want node-nl-2 (лучшая по score)", a)
	}
	targetPort, closeTarget := afTargetServer(t)
	defer closeTarget()

	// 10 последовательных соединений: ВСЕ на одной ноде (не скачет)
	req := []byte("GET / HTTP/1.1\r\nHost: youtube.com\r\nConnection: close\r\n\r\n")
	for i := 0; i < 10; i++ {
		out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req)
		if err != nil || !bytes.Contains(out, []byte("200-OK")) {
			t.Fatalf("conn#%d: %v %.40q", i, err, out)
		}
		if got := afRouteBlocked(t, xc, "client@example.com"); got != "node-nl-2" {
			t.Fatalf("conn#%d: маршрут скакнул на %q (want node-nl-2 стабильно)", i, got)
		}
	}
	// доказательство по логу ядра: все blocked-запросы через node-nl-2, ни одного nl-1
	logData, _ := os.ReadFile(cfgPath + ".log")
	logStr := string(logData)
	if !strings.Contains(logStr, "node-nl-2") {
		t.Fatalf("лог без node-nl-2:\n%s", logStr)
	}
	for _, line := range strings.Split(logStr, "\n") {
		if strings.Contains(line, "youtube.com") && strings.Contains(line, "accepted") && strings.Contains(line, "node-nl-1") {
			t.Fatalf("скачок на node-nl-1 в логе: %s", line)
		}
	}
	// персистентный конфиг: per-user правило, XKIT_AF отсутствует
	cfgData, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(cfgData), afBalancerTag) {
		t.Fatal("XKIT_AF в конфиге")
	}
	if out, err := afRunTest(t, bin, cfgPath, os.Getenv("xray.location.asset")); err != nil {
		t.Fatalf("run -test: %v\n%s", err, out)
	}
}

// TestAntifilterFailoverStickyE2E — смерть ноды → failover на другую ноду страны,
// дальше снова sticky (все соединения на новой ноде).
func TestAntifilterFailoverStickyE2E(t *testing.T) {
	s, xc, c, vlessPort, _, _ := afStickySetup(t)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatal(err)
	}
	s.SetNodeQuality("node-nl-1", 50, 99, 60)
	s.SetNodeQuality("node-nl-2", 10, 100, 95)
	if _, err := c.PushAssignment(t.Context(), "client@example.com", "NL"); err != nil {
		t.Fatal(err)
	}
	targetPort, closeTarget := afTargetServer(t)
	defer closeTarget()
	req := []byte("GET / HTTP/1.1\r\nHost: youtube.com\r\nConnection: close\r\n\r\n")
	if out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req); err != nil || !bytes.Contains(out, []byte("200-OK")) {
		t.Fatalf("до failover: %v %.40q", err, out)
	}
	if got := afRouteBlocked(t, xc, "client@example.com"); got != "node-nl-2" {
		t.Fatalf("до failover маршрут %q", got)
	}
	// нода умерла: 3 неудачных пробы (гистерезис) → down → FailoverNode
	loads := map[string]NodeLoad{}
	for i := 0; i < 3; i++ {
		if _, err := c.bal.RecordProbe(t.Context(), "node-nl-2", false); err != nil {
			t.Fatal(err)
		}
	}
	moved, err := c.bal.FailoverNode(t.Context(), "node-nl-2", loads)
	if err != nil || moved != 1 {
		t.Fatalf("failover: moved=%d err=%v", moved, err)
	}
	c.SyncRulesNow(t.Context())
	a, _ := s.GetAssignment("client@example.com", "NL")
	if a == nil || a.NodeID != "node-nl-1" {
		t.Fatalf("после failover назначение %+v, want node-nl-1", a)
	}
	// 5 соединений после failover: все на node-nl-1 (sticky на новой ноде)
	for i := 0; i < 5; i++ {
		if out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req); err != nil || !bytes.Contains(out, []byte("200-OK")) {
			t.Fatalf("после failover conn#%d: %v %.40q", i, err, out)
		}
		if got := afRouteBlocked(t, xc, "client@example.com"); got != "node-nl-1" {
			t.Fatalf("после failover скачок на %q", got)
		}
	}
}

// TestAntifilterReconnectBestNowE2E — reconnect: клиент offline, лучшая нода
// сменилась → reevaluate переназначает; при возврате клиента трафик идёт на
// лучшую СЕЙЧАС. Mid-session (online) — не дёргаем даже при смене score.
func TestAntifilterReconnectBestNowE2E(t *testing.T) {
	s, xc, c, vlessPort, _, _ := afStickySetup(t)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatal(err)
	}
	s.SetNodeQuality("node-nl-1", 50, 99, 60)
	s.SetNodeQuality("node-nl-2", 10, 100, 95)
	if _, err := c.PushAssignment(t.Context(), "client@example.com", "NL"); err != nil {
		t.Fatal(err)
	}
	targetPort, closeTarget := afTargetServer(t)
	defer closeTarget()
	req := []byte("GET / HTTP/1.1\r\nHost: youtube.com\r\nConnection: close\r\n\r\n")

	// 1) MID-SESSION STICKY: живое соединение + score перевернулся → НЕ дёргаем
	closeSession := afOpenSession(t, vlessPort, targetPort)
	afWaitOnline(t, xc, "client@example.com", true)
	s.SetNodeQuality("node-nl-1", 5, 100, 99) // теперь nl-1 «лучше»
	s.SetNodeQuality("node-nl-2", 80, 90, 30)
	c.reevaluate(t.Context())
	if got := afRouteBlocked(t, xc, "client@example.com"); got != "node-nl-2" {
		t.Fatalf("mid-session скачок: %q (клиент online, обязан остаться на node-nl-2)", got)
	}
	// живая сессия продолжает работать на той же ноде
	if out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req); err != nil || !bytes.Contains(out, []byte("200-OK")) {
		t.Fatalf("mid-session conn: %v %.40q", err, out)
	}

	// 2) RECONNECT: клиент выключил VPN (сессия закрыта → offline)
	closeSession()
	afWaitOnline(t, xc, "client@example.com", false)
	c.reevaluate(t.Context())
	a, _ := s.GetAssignment("client@example.com", "NL")
	if a == nil || a.NodeID != "node-nl-1" {
		t.Fatalf("reconnect: назначение %+v, want node-nl-1 (лучшая СЕЙЧАС)", a)
	}
	// клиент включил VPN: новые соединения → лучшая сейчас
	for i := 0; i < 3; i++ {
		if out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req); err != nil || !bytes.Contains(out, []byte("200-OK")) {
			t.Fatalf("после reconnect conn#%d: %v %.40q", i, err, out)
		}
		if got := afRouteBlocked(t, xc, "client@example.com"); got != "node-nl-1" {
			t.Fatalf("после reconnect маршрут %q, want node-nl-1", got)
		}
	}
}

// TestAntifilterAnyWholePoolE2E — страна any: лучшая из ВСЕГО пула (не только NL).
func TestAntifilterAnyWholePoolE2E(t *testing.T) {
	s, xc, c, vlessPort, _, _ := afStickySetup(t)
	if err := s.UpsertClient(testClient("client@example.com", "any", 0)); err != nil {
		t.Fatal(err)
	}
	// лучшая во всём пуле — US-нода (score выше всех NL/DE)
	s.SetNodeQuality("node-nl-1", 50, 99, 60)
	s.SetNodeQuality("node-nl-2", 10, 100, 70)
	s.SetNodeQuality("node-de-1", 20, 100, 80)
	s.SetNodeQuality("node-us-1", 5, 100, 99)
	if _, err := c.PushAssignment(t.Context(), "client@example.com", "any"); err != nil {
		t.Fatal(err)
	}
	a, _ := s.GetAssignment("client@example.com", "any")
	if a == nil || a.NodeID != "node-us-1" {
		t.Fatalf("any: назначение %+v, want node-us-1 (лучшая из всего пула)", a)
	}
	targetPort, closeTarget := afTargetServer(t)
	defer closeTarget()
	req := []byte("GET / HTTP/1.1\r\nHost: youtube.com\r\nConnection: close\r\n\r\n")
	for i := 0; i < 3; i++ {
		if out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req); err != nil || !bytes.Contains(out, []byte("200-OK")) {
			t.Fatalf("any conn#%d: %v %.40q", i, err, out)
		}
		if got := afRouteBlocked(t, xc, "client@example.com"); got != "node-us-1" {
			t.Fatalf("any conn#%d: маршрут %q, want node-us-1", i, got)
		}
	}
	// инверсия при any: незаблокированный IP → direct
	resp, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
		InboundTag: "vless-in", User: "client@example.com", TargetPort: 443, TargetIPs: [][]byte{[]byte{93, 184, 216, 34}},
	}})
	if err != nil || resp.GetOutboundTag() != "direct" {
		t.Fatalf("any инверсия: %v %v, want direct", resp, err)
	}
}