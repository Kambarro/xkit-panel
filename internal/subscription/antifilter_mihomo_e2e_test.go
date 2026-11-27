package subscription

// Регрессия QA AF-BUG-4 (HIGH): clash antifilter rule-provider отдавал ГОЛЫЕ
// домены в behavior:domain format:text — mihomo трактует их как ТОЧНЫЙ матч,
// поддомены (www.youtube.com) утекали в MATCH,DIRECT (для РФ-клиента YouTube
// мёртв). Фикс: BlockedDomainText отдаёт '+.domain' (суффикс-trie mihomo).
// E2E на РЕАЛЬНОМ mihomo: полная цепочка antifilter.Manager → ServeBlocked →
// rule-provider fetch → -t OK → живой run: ПОДДОМЕН blocked-домена → нода
// (лог 'match RuleSet using PROXY' + маркер in-path), точный домен → нода,
// незаблокированный → DIRECT. Бинари: XKIT_MIHOMO_BIN / workspace QA; нет — skip.

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"

	"github.com/kambarro/xkit-panel/internal/antifilter"
	"github.com/kambarro/xkit-panel/internal/store"
)

func findMihomoBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("XKIT_MIHOMO_BIN"); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	home, _ := os.UserHomeDir()
	p := filepath.Join(home, ".hermes", "profiles", "qa", "workspace", "xkit-full-qa", "parsers", "mihomo")
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}

// afTestManager — РЕАЛЬНЫЙ antifilter.Manager с тестовыми dat-ассетами:
// blocked-наборы отдаются тем же кодом, что и панелью (ServeBlocked).
func afTestManager(t *testing.T) *antifilter.Manager {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "af.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	asset := t.TempDir()
	gs := &geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{Code: "RU-BLOCKED", Domain: []*geodata.Domain{
			{Type: geodata.Domain_Domain, Value: "youtube.com"},
			{Type: geodata.Domain_Domain, Value: "instagram.com"},
		}},
	}}
	gsb, err := proto.Marshal(gs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(asset, antifilter.GeositeFile), gsb, 0644); err != nil {
		t.Fatal(err)
	}
	// blocked-ip НЕ содержит loopback/таргет: матч должен доказать ДОМЕННЫЙ слой
	ipdat, err := antifilter.GenerateDat([]netip.Prefix{netip.MustParsePrefix("9.9.9.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(asset, antifilter.DatFileA), ipdat, 0644); err != nil {
		t.Fatal(err)
	}
	return antifilter.NewManager(st, t.TempDir(), asset)
}

// copyMihomoGeo — локальные geo-ассеты ускоряют старт (иначе mihomo качает сам).
func copyMihomoGeo(dir string) {
	home, _ := os.UserHomeDir()
	src := filepath.Join(home, ".hermes", "profiles", "developer", "cache", "scratch", "mhprobe")
	for _, name := range []string{"GeoSite.dat", "geoip.metadb"} {
		if b, err := os.ReadFile(filepath.Join(src, name)); err == nil {
			os.WriteFile(filepath.Join(dir, name), b, 0644)
		}
	}
}

func TestClashAntifilterSubdomainMihomoE2E(t *testing.T) {
	mh := findMihomoBinary(t)
	if mh == "" {
		t.Skip("mihomo не найден (XKIT_MIHOMO_BIN / workspace QA)")
	}
	xray := findXrayBinary(t)
	if xray == "" {
		t.Skip("xray бинарь не найден (XKIT_XRAY_BIN)")
	}
	m := afTestManager(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/antifilter/", func(w http.ResponseWriter, r *http.Request) {
		m.ServeBlocked(w, r, strings.TrimPrefix(r.URL.Path, "/antifilter/"))
	})
	provSrv := httptest.NewServer(mux)
	t.Cleanup(provSrv.Close)

	// «нода»: vless-ws tls inbound; dns.hosts СУФФИКС (domain:) — поддомены
	// blocked-домена резолвятся нодой в loopback-таргет (урок AF-BUG-1: домен,
	// ушедший в туннель, резолвит DNS НОДЫ). freedom finalRules allow loopback.
	assetDir := writeAFClientGeoSub(t)
	cert, key := testCertPEMSub(t)
	certLines := strings.Split(strings.TrimSpace(cert), "\n")
	keyLines := strings.Split(strings.TrimSpace(key), "\n")
	nodePort := freePortSub(t)
	nodeLog := filepath.Join(t.TempDir(), "node-access.log")
	nodeCfg := fmt.Sprintf(`{
	 "log": {"loglevel": "info", "access": %q},
	 "dns": {"hosts": {"domain:youtube.com": "127.0.0.1"}, "queryStrategy": "UseIPv4"},
	 "inbounds": [{
	  "tag": "vless-ws", "listen": "127.0.0.1", "port": %d, "protocol": "vless",
	  "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "client@example.com"}], "decryption": "none"},
	  "streamSettings": {"network": "ws", "security": "tls", "wsSettings": {"path": "/ws"},
	   "tlsSettings": {"certificates": [{"certificate": %s, "key": %s}]}}
	 }],
	 "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4", "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
	}`, nodeLog, nodePort, mustJSONLines(certLines), mustJSONLines(keyLines))
	nodeProc := startClientSubAsset(t, xray, nodeCfg, assetDir)
	defer nodeProc.kill()
	waitTCPSub(t, nodePort)

	// таргет «заблокированного сайта»: маркер доказывает проход через ноду
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "200-VIA-NODE")
	}))
	defer target.Close()
	_, tpStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	var targetPort int
	fmt.Sscanf(tpStr, "%d", &targetPort)
	// «чистый» таргет для незаблокированного (direct мимо ноды)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "200-DIRECT")
	}))
	defer plain.Close()
	phost, pport, _ := net.SplitHostPort(strings.TrimPrefix(plain.URL, "http://"))

	link := fmt.Sprintf("vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:%d?encryption=none&security=tls&sni=test.local&type=ws&path=%%2Fws#NODE", nodePort)
	cy := ClashYAMLAntifilter([]string{link}, nil, AntifilterRules{}, provSrv.URL+"/antifilter")

	// test-only адаптация: свободный mixed-port + доверие self-signed серту
	// ноды (skip-cert-verify). dns/routing/rule-providers НЕ трогаются.
	mixedPort := freePortSub(t)
	cy = strings.Replace(cy, "mixed-port: 7890", fmt.Sprintf("mixed-port: %d", mixedPort), 1)
	cy = strings.Replace(cy, "    tls: true\n", "    tls: true\n    skip-cert-verify: true\n", 1)

	dir := t.TempDir()
	copyMihomoGeo(dir)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cy), 0644); err != nil {
		t.Fatal(err)
	}
	// 1) mihomo -t: конфиг подписки валиден, провайдеры загружаются
	if out, err := exec.Command(mh, "-t", "-d", dir, "-f", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("mihomo -t: %v\n%s", err, out)
	}
	// 2) живой run
	logPath := filepath.Join(dir, "run.log")
	lf, _ := os.Create(logPath)
	cmd := exec.Command(mh, "-d", dir, "-f", cfgPath)
	cmd.Stdout, cmd.Stderr = lf, lf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); lf.Close() })
	deadline := time.Now().Add(60 * time.Second) // geo-ассеты могут докачиваться
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", mixedPort), 500*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(logPath)
			t.Fatalf("mihomo не поднял mixed-port за 60с:\n%s", b)
		}
		time.Sleep(200 * time.Millisecond)
	}
	socksAddr := fmt.Sprintf("127.0.0.1:%d", mixedPort)

	// 3) ПОДДОМЕН blocked-домена (корень AF-BUG-4) → RuleSet → PROXY → нода
	for _, host := range []string{"www.youtube.com", "a.b.youtube.com", "youtube.com"} {
		code, body, err := socksGETSub(socksAddr, fmt.Sprintf("http://%s:%d/", host, targetPort), 15*time.Second)
		if err != nil || code != 200 || body != "200-VIA-NODE" {
			b, _ := os.ReadFile(logPath)
			t.Fatalf("%s → нода: code=%d body=%q err=%v\nmihomo log:\n%s", host, code, body, err, b)
		}
	}
	// 4) инверсия: незаблокированный IP-литерал → DIRECT (мимо ноды)
	code, body, err := socksGETSub(socksAddr, fmt.Sprintf("http://%s:%s/", phost, pport), 15*time.Second)
	if err != nil || code != 200 || body != "200-DIRECT" {
		b, _ := os.ReadFile(logPath)
		t.Fatalf("unblocked → direct: code=%d body=%q err=%v\n%s", code, body, err, b)
	}
	cmd.Process.Kill()
	cmd.Wait()
	lf.Close()

	// 5) доказательство маршрута по ЛОГУ mihomo (не по HTTP-коду — урок QA:
	// с не-РФ egress 200 маскирует неверный маршрут)
	lb, _ := os.ReadFile(logPath)
	mlog := string(lb)
	for _, host := range []string{"www.youtube.com", "a.b.youtube.com", "youtube.com"} {
		want := fmt.Sprintf("--> %s:%d match RuleSet(xkit-blocked-domains) using PROXY", host, targetPort)
		if !strings.Contains(mlog, want) {
			t.Fatalf("нет матч-строки %q в логе mihomo:\n%s", want, mlog)
		}
	}
	if strings.Contains(mlog, fmt.Sprintf("--> www.youtube.com:%d match Match using DIRECT", targetPort)) {
		t.Fatal("www.youtube.com утёк в MATCH,DIRECT (AF-BUG-4 не закрыт)")
	}
	// нода реально видела поддомен (access-log)
	nlog, _ := os.ReadFile(nodeLog)
	if !strings.Contains(string(nlog), "www.youtube.com") {
		t.Fatalf("access-log ноды без www.youtube.com:\n%s", nlog)
	}
}
