package balancer

// Регрессия блокирующего бага деплоя 13f7965 (Ops, xray 26.11.9):
//  1. правила af-domain/af-ip/always-proxy писались с outboundTag=XKIT_AF —
//     диспетчер ищет тег среди outbound-хендлеров, балансир не резолвится
//     («non existing outTag: XKIT_AF»), blocked-трафик рвётся;
//  2. балансир XKIT_AF с fallbackTag у random-стратегии требует observatory
//     (strategy_random.go InjectContext) → старт ядра из config.json падает
//     «not all dependencies are resolved» (crash-loop при рестарте).
//     При runtime ReplaceRules зависимость лишь откладывается — in-process
//     тесты были зелёными, а реальный бинарь на старте умирал. Здесь E2E
//     гоняет РЕАЛЬНЫЙ бинарь 26.11.9: run -test, старт с antifilter-конфигом,
//     живой трафик blocked→нода ЧЕРЕЗ БАЛАНСИР, повторный рестарт без crash-loop.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	routercmd "github.com/xtls/xray-core/app/router/command"

	"github.com/kambarro/xkit-panel/internal/routing"
	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/xray"
)

// afRealXrayBin — реальный бинарь xray 26.11.9 (env XKIT_XRAY_BIN или ops-workspace).
// Без бинаря тест пропускается: in-process ядро НЕ ловит старт-зависимости fallbackTag.
func afRealXrayBin(t *testing.T) string {
	t.Helper()
	candidates := []string{os.Getenv("XKIT_XRAY_BIN")}
	home, _ := os.UserHomeDir()
	if home != "" {
		candidates = append(candidates,
			home+"/.hermes/profiles/ops/workspace/xkit-13f7965-deploy/bin/xray")
	}
	candidates = append(candidates, "/usr/local/bin/xray", "/usr/bin/xray")
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("xray"); err == nil {
		return p
	}
	t.Skip("реальный бинарь xray не найден (XKIT_XRAY_BIN)")
	return ""
}

// afProc — процесс реального xray с логом (для диагностики падений).
type afProc struct {
	cmd     *exec.Cmd
	logPath string
}

func (p *afProc) stop() {
	if p.cmd.Process != nil {
		p.cmd.Process.Kill()
		p.cmd.Wait()
	}
}

func (p *afProc) logTail() string {
	b, _ := os.ReadFile(p.logPath)
	if len(b) > 6000 {
		b = b[len(b)-6000:]
	}
	return string(b)
}

// afStartXray — xray run с конфигом; ждёт готовности gRPC API (dial).
// Падение на старте (crash) → мгновенный Fatal с логом ядра.
func afStartXray(t *testing.T, bin, cfgPath, assetDir, apiAddr string) *afProc {
	t.Helper()
	logPath := cfgPath + ".log"
	lf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Env = append(os.Environ(), "xray.location.asset="+assetDir, "XRAY_LOCATION_ASSET="+assetDir)
	cmd.Stdout, cmd.Stderr = lf, lf
	if err := cmd.Start(); err != nil {
		lf.Close()
		t.Fatalf("xray start: %v", err)
	}
	p := &afProc{cmd: cmd, logPath: logPath}
	t.Cleanup(func() { p.stop(); lf.Close() })
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", apiAddr, 300*time.Millisecond); err == nil {
			conn.Close()
			return p
		}
		// процесс умер на старте — не ждём таймаут, показываем причину
		if cmd.ProcessState != nil {
			t.Fatalf("xray умер на старте:\n%s", p.logTail())
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("xray API не поднялся за 10с:\n%s", p.logTail())
	return p
}

// afRunTest — xray run -test (валидация конфига БЕЗ старта), возвращает вывод.
func afRunTest(t *testing.T, bin, cfgPath, assetDir string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, "run", "-test", "-c", cfgPath)
	cmd.Env = append(os.Environ(), "xray.location.asset="+assetDir, "XRAY_LOCATION_ASSET="+assetDir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// freeTCPPort — свободный loopback-порт.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

// afMasterConfig — полный config.json мастера для реального бинаря: vless-inbound
// (raw-клиент без TLS), freedom-ноды с маркерным payload (sendThrough не нужен —
// различаем ноды по access-log + счётчикам), dns.hosts резолвит blocked-домен в
// loopback таргета.Routing-секция минимальная (api + catch-all): af-правила и
// балансир строит контроллер через штатный syncAllRules.
func afMasterConfig(t *testing.T, apiPort, vlessPort, targetPort int) string {
	t.Helper()
	allowLoopback := `"settings":{"domainStrategy":"UseIPv4","finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}`
	cfg := fmt.Sprintf(`{
	 "log": {"loglevel": "info"},
	 "dns": {"hosts": {"youtube.com": "127.0.0.1", "t.me": "127.0.0.1"}, "queryStrategy": "UseIPv4"},
	 "api": {"tag": "api", "listen": "127.0.0.1:%d", "services": ["HandlerService", "RoutingService", "StatsService"]},
	 "stats": {},
	 "policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}},
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
	  {"tag": "node-de-1", "protocol": "freedom", %s},
	  {"tag": "node-us-1", "protocol": "freedom", %s}
	 ],
	 "routing": {"domainStrategy": "AsIs", "rules": [
	  {"type": "field", "inboundTag": ["api-in"], "outboundTag": "api", "ruleTag": "api"},
	  {"type": "field", "port": "0-65535", "outboundTag": "direct"}
	 ]}
	}`, apiPort, vlessPort, allowLoopback, allowLoopback, allowLoopback, allowLoopback)
	_ = targetPort
	return cfg
}

// afVlessFetchDomain — raw vless TCP CONNECT к ДОМЕНУ (addrType=3): ядро резолвит
// через dns.hosts → routing матчит af-domain по имени. Шлём payload сразу (ядро
// буферизует response-заголовок до первого payload — урок traffic E2E).
func afVlessFetchDomain(t *testing.T, port int, domain string, targetPort int, payload []byte) ([]byte, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("vless dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	var hdr bytes.Buffer
	hdr.WriteByte(0)
	uuidBytes := [16]byte{0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11}
	hdr.Write(uuidBytes[:])
	hdr.WriteByte(0) // addons len
	hdr.WriteByte(1) // TCP
	binary.Write(&hdr, binary.BigEndian, uint16(targetPort))
	hdr.WriteByte(2) // domain (vless: 1=IPv4, 2=domain, 3=IPv6)
	hdr.WriteByte(byte(len(domain)))
	hdr.WriteString(domain)
	if _, err := conn.Write(hdr.Bytes()); err != nil {
		return nil, fmt.Errorf("hdr: %w", err)
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("resp hdr (обрыв = трафик порезан): %w", err)
	}
	out, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return out, nil
}

// TestAntifilterRealXrayE2E — sticky-переделка против РЕАЛЬНОГО ядра 26.11.9:
// run -test OK с antifilter-конфигом, blocked-домен идёт через PER-USER правило
// на ноду назначения (общего random-балансира XKIT_AF НЕТ — он давал скачки
// per-connection), инверсия сохранена, повторный рестарт — без crash-loop.
func TestAntifilterRealXrayE2E(t *testing.T) {
	bin := afRealXrayBin(t)
	dir := writeTestGeoFiles(t) // + env xray.location.asset
	writeTestBlockedFiles(t, dir)
	s := testStore(t)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRoutingMode("antifilter"); err != nil {
		t.Fatal(err)
	}
	s.SetAntifilterState(antifilterStateForTest("xkit-blocked.dat", 1))
	s.SetAlwaysRules(routing.AlwaysRules{ProxyDomains: []string{"t.me"}})
	// назначение нашим балансиром (reevaluate/PickNode/Assign — весь механизм)
	if err := s.SetAssignment(storeAssignment("client@example.com", "NL", "node-nl-1")); err != nil {
		t.Fatal(err)
	}

	// таргет «заблокированного сайта»: отвечает 200 + маркер
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write([]byte("200-BLOCKED-VIA-NODE"))
	}))
	defer target.Close()
	_, tpStr, _ := net.SplitHostPort(target.Listener.Addr().String())
	var targetPort int
	fmt.Sscanf(tpStr, "%d", &targetPort)

	apiPort, vlessPort := freeTCPPort(t), freeTCPPort(t)
	apiAddr := fmt.Sprintf("127.0.0.1:%d", apiPort)
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(afMasterConfig(t, apiPort, vlessPort, targetPort)), 0644); err != nil {
		t.Fatal(err)
	}
	oldPath := masterConfigPath
	masterConfigPath = cfgPath
	t.Cleanup(func() { masterConfigPath = oldPath })

	// 1) СТАРТ реального ядра + syncAllRules: per-user af-правила в config.json
	p1 := afStartXray(t, bin, cfgPath, dir, apiAddr)
	xc, err := xray.Dial(apiAddr)
	if err != nil {
		t.Fatalf("dial: %v\n%s", err, p1.logTail())
	}
	c := NewController(s, xc)
	c.SyncRulesNow(t.Context())

	// 2) персистентный config.json: blocked/always-proxy адресуют PER-USER ноду
	// назначения (outboundTag=node-nl-1 + user), balancerTag/XKIT_AF отсутствует
	cfgData, _ := os.ReadFile(cfgPath)
	var cfg map[string]any
	json.Unmarshal(cfgData, &cfg)
	rt := cfg["routing"].(map[string]any)
	for _, rl := range rt["rules"].([]any) {
		rm := rl.(map[string]any)
		tag, _ := rm["ruleTag"].(string)
		if _, bad := rm["balancerTag"]; bad {
			t.Errorf("%s: balancerTag — общий random-балансир удалён", tag)
		}
		if tag == "afpd:client@example.com" || tag == "afpi:client@example.com" || tag == "apd:client@example.com" {
			if rm["outboundTag"] != "node-nl-1" {
				t.Errorf("%s: outboundTag=%v, want node-nl-1 (нода назначения)", tag, rm["outboundTag"])
			}
		}
	}
	if strings.Contains(string(cfgData), afBalancerTag) {
		t.Fatalf("легаси %s в конфиге", afBalancerTag)
	}

	// 3) run -test РЕАЛЬНЫМ бинарём с antifilter-конфигом
	if out, err := afRunTest(t, bin, cfgPath, dir); err != nil {
		t.Fatalf("xray run -test с antifilter-конфигом: %v\n%s", err, out)
	}

	// 4) ЖИВОЙ трафик: blocked-домен (youtube.com в geosite RU-BLOCKED) через
	// vless-inbound → per-user afpd → нода назначения → 200.
	req := []byte("GET / HTTP/1.1\r\nHost: youtube.com\r\nConnection: close\r\n\r\n")
	out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req)
	if err != nil {
		t.Fatalf("blocked-трафик через per-user правило: %v\nлог ядра:\n%s", err, p1.logTail())
	}
	if !bytes.Contains(out, []byte("200-BLOCKED-VIA-NODE")) {
		t.Fatalf("ответ blocked-таргета: %.100q\nлог ядра:\n%s", out, p1.logTail())
	}
	// доказательство маршрута: лог ядра → правило afpd, нода назначения
	logNow := p1.logTail()
	if !strings.Contains(logNow, "afpd:client@example.com") || !strings.Contains(logNow, "node-nl-1") {
		t.Fatalf("лог не содержит afpd→node-nl-1:\n%s", logNow)
	}
	// TestRoute резолвит per-user правило на ноду назначения
	resp, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
		InboundTag: "vless-in", User: "client@example.com", TargetPort: 443, TargetDomain: "youtube.com",
	}})
	if err != nil {
		t.Fatalf("TestRoute blocked: %v", err)
	}
	if got := resp.GetOutboundTag(); got != "node-nl-1" {
		t.Fatalf("blocked → %q, want node-nl-1 (нода назначения)", got)
	}
	// инверсия: незаблокированный IP → direct (catch-all), RU IP → direct
	for _, tc := range []struct{ ip []byte; want string }{
		{[]byte{93, 184, 216, 34}, "direct"}, // world unblocked
		{[]byte{10, 77, 1, 1}, "direct"},     // geoip:ru
	} {
		r, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
			InboundTag: "vless-in", User: "client@example.com", TargetPort: 443, TargetIPs: [][]byte{tc.ip},
		}})
		if err != nil || r.GetOutboundTag() != tc.want {
			t.Fatalf("инверсия %v: %v %v, want %s", tc.ip, r, err, tc.want)
		}
	}
	// always-proxy домен тоже через ноду назначения (per-user apd)
	rAlways, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
		InboundTag: "vless-in", User: "client@example.com", TargetPort: 443, TargetDomain: "t.me",
	}})
	if err != nil || rAlways.GetOutboundTag() != "node-nl-1" {
		t.Fatalf("always-proxy: %v %v, want node-nl-1", rAlways, err)
	}
	xc.Close()

	// 5) РЕСТАРТ ядра с antifilter-конфигом: процесс обязан стартовать с
	// персистентного config.json (per-user правила), жить и обслуживать
	// blocked-трафик БЕЗ панели/ReplaceRules.
	p1.stop()
	p2 := afStartXray(t, bin, cfgPath, dir, apiAddr)
	// несколько тиков: crash-loop проявился бы повторными смертями процесса
	time.Sleep(1500 * time.Millisecond)
	if p2.cmd.ProcessState != nil {
		t.Fatalf("xray умер после рестарта (crash-loop):\n%s", p2.logTail())
	}
	out2, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req)
	if err != nil || !bytes.Contains(out2, []byte("200-BLOCKED-VIA-NODE")) {
		t.Fatalf("blocked-трафик после рестарта: %v %.60q\n%s", err, out2, p2.logTail())
	}
	// второй рестарт подряд — NRestarts-эквивалент: оба живы
	p2.stop()
	p3 := afStartXray(t, bin, cfgPath, dir, apiAddr)
	time.Sleep(500 * time.Millisecond)
	if p3.cmd.ProcessState != nil {
		t.Fatalf("xray умер на втором рестарте:\n%s", p3.logTail())
	}
	if out, err := afRunTest(t, bin, cfgPath, dir); err != nil {
		t.Fatalf("run -test после рестартов: %v\n%s", err, out)
	}
	_ = store.Node{}
}

// TestAntifilterAllNodesDownE2E — все ноды down: per-user af-правила не строятся,
// blocked-трафик деградирует в direct (catch-all), без балансира и без crash.
func TestAntifilterAllNodesDownE2E(t *testing.T) {
	writeTestGeoFiles(t)
	writeTestBlockedFiles(t, os.Getenv("xray.location.asset"))
	s := testStore(t)
	s.SetRoutingMode("antifilter")
	s.SetAntifilterState(antifilterStateForTest("xkit-blocked.dat", 1))
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAssignment(storeAssignment("client@example.com", "NL", "node-nl-1")); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"node-de-1", "node-de-2", "node-nl-1", "node-us-1"} {
		if err := s.SetNodeHealth(id, "down", 3); err != nil {
			t.Fatal(err)
		}
	}
	routingJSON := `{"domainStrategy":"AsIs","rules":[
		{"type":"field","inboundTag":["api-in"],"outboundTag":"api","ruleTag":"api"},
		{"type":"field","port":"0-65535","outboundTag":"direct"}
	]}`
	xc := startXrayAPI(t, routingJSON)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(cfgPath, []byte(`{"routing":`+routingJSON+`}`), 0644)
	oldPath := masterConfigPath
	masterConfigPath = cfgPath
	t.Cleanup(func() { masterConfigPath = oldPath })
	c := NewController(s, xc)
	c.SyncRulesNow(t.Context())
	// все ноды down → per-user af-правил нет, blocked → direct (деградация)
	resp, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
		InboundTag: "vless-in", User: "client@example.com", TargetPort: 443, TargetIPs: [][]byte{[]byte{9, 9, 9, 9}},
	}})
	if err != nil {
		t.Fatalf("TestRoute: %v", err)
	}
	if got := resp.GetOutboundTag(); got != "direct" {
		t.Fatalf("all-down blocked → %q, want direct (деградация)", got)
	}
	data, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(data), afBalancerTag) {
		t.Fatalf("балансир %s остался при всех нодах down:\n%s", afBalancerTag, data)
	}
}
