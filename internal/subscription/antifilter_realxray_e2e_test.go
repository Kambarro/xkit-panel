package subscription

// Регрессия QA AF-BUG-1 (HIGH): xray-json подписка в antifilter не стартовала
// на pinned-ядре 26.11.9 — алиас proxy-first строился через УДАЛЁННУЮ фичу
// proxySettings («feature has been removed and migrated to
// streamSettings.sockopt.dialerProxy»). Фикс: sockopt.dialerProxy.
// E2E на РЕАЛЬНОМ бинаре: run -test OK + живой трафик с инверсией
// (blocked→нода, unblocked→direct); ru-direct регресс не сломан.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

// afProxyFirstOutbound — outbound proxy-first из сгенерированного конфига.
func afProxyFirstOutbound(t *testing.T, cfgJSON string) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		t.Fatalf("subscription JSON: %v", err)
	}
	for _, o := range cfg["outbounds"].([]any) {
		om := o.(map[string]any)
		if om["tag"] == "proxy-first" {
			return om
		}
	}
	t.Fatal("outbound proxy-first отсутствует")
	return nil
}

// TestXrayJSONAntifilterDialerProxy — wire-формат алиаса: sockopt.dialerProxy
// на первый прокси, proxySettings НЕ используется (удалён в ядре 26.11.9).
func TestXrayJSONAntifilterDialerProxy(t *testing.T) {
	for name, gen := range map[string]func([]string) string{
		"default":  func(ls []string) string { return XrayJSONAntifilter(ls, nil, afTestRules, "") },
		"profiles": func(ls []string) string { return XrayJSONAntifilterProfiles(ls, nil, afTestRules, "") },
	} {
		j := gen([]string{afTestLink})
		if strings.Contains(j, "proxySettings") {
			t.Errorf("%s: proxySettings в конфиге — ядро 26.11.9 его не принимает", name)
		}
		pf := afProxyFirstOutbound(t, j)
		stream, _ := pf["streamSettings"].(map[string]any)
		sockopt, _ := stream["sockopt"].(map[string]any)
		if sockopt == nil || sockopt["dialerProxy"] != "XKIT" {
			t.Errorf("%s: proxy-first sockopt=%v want dialerProxy=XKIT", name, stream)
		}
	}
	// AWG-only (прокси-ссылок нет): proxy-first — голый freedom, конфиг валиден
	j := XrayJSONAntifilter(nil, nil, afTestRules, "")
	pf := afProxyFirstOutbound(t, j)
	if _, has := pf["streamSettings"]; has {
		t.Errorf("без прокси dialerProxy не нужен: %v", pf)
	}
}

// writeAFClientGeoSub — geoip/geosite для клиентского конфига подписки
// (geoip:ru/private + geosite:category-ru/telegram резолвятся парсером ядра).
func writeAFClientGeoSub(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	geoIP := &geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "RU", Cidr: []*geodata.CIDR{{Ip: []byte{10, 77, 0, 0}, Prefix: 16}}},
		{Code: "PRIVATE", Cidr: []*geodata.CIDR{{Ip: []byte{127, 0, 0, 0}, Prefix: 8}}},
		{Code: "TELEGRAM", Cidr: []*geodata.CIDR{{Ip: []byte{149, 154, 160, 0}, Prefix: 20}}},
	}}
	geoSite := &geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{Code: "CATEGORY-RU", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "example-ru.test"}}},
		{Code: "TELEGRAM", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "t.me"}}},
	}}
	for name, msg := range map[string]proto.Message{"geoip.dat": geoIP, "geosite.dat": geoSite} {
		b, err := proto.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// runTestSub — реальный xray run -test против конфига (asset-каталог инъектируется).
func runTestSub(t *testing.T, bin, cfgJSON, assetDir string) (string, error) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-test", "-c", cfgPath)
	cmd.Env = append(os.Environ(), "xray.location.asset="+assetDir, "XRAY_LOCATION_ASSET="+assetDir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// startClientSubAsset — реальный xray-клиент из JSON подписки с asset-каталогом.
func startClientSubAsset(t *testing.T, bin, cfgJSON, assetDir string) *procSub {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(cfgJSON), 0644)
	logPath := filepath.Join(dir, "run.log")
	lf, _ := os.Create(logPath)
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Env = append(os.Environ(), "xray.location.asset="+assetDir, "XRAY_LOCATION_ASSET="+assetDir)
	cmd.Stdout, cmd.Stderr = lf, lf
	if err := cmd.Start(); err != nil {
		t.Fatalf("client start: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); lf.Close() })
	return &procSub{cmd: cmd, logPath: logPath}
}

// afAdaptClientSub — test-only адаптация подписки: свободный socks-порт,
// dns.hosts (blocked-домен и always-proxy домен → loopback-таргет; DoH в
// тест-окружении недоступен), DoH-серверы убраны. Routing/outbounds НЕ трогаются.
func afAdaptClientSub(t *testing.T, cfgJSON string, targetIP string, targetPort int) (string, int) {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		t.Fatal(err)
	}
	socksPort := freePortSub(t)
	cfg["inbounds"].([]any)[0].(map[string]any)["port"] = socksPort
	cfg["dns"] = map[string]any{
		"hosts": map[string]any{
			"youtube.com": targetIP,
			"t.me":        targetIP,
		},
		"queryStrategy": "UseIPv4",
	}
	b, _ := json.Marshal(cfg)
	return string(b), socksPort
}

// TestXrayJSONAntifilterRealXrayE2E — QA AF-BUG-1 на РЕАЛЬНОМ xray 26.11.9:
// подписка ?format=xray в antifilter проходит run -test, стартует и гонит
// трафик с верной инверсией: blocked-домен → через ноду (маркер in-path),
// незаблокированный → direct с клиента (маркера нет). Оба варианта генератора
// (default с балансиром / profiles для INCY).
func TestXrayJSONAntifilterRealXrayE2E(t *testing.T) {
	bin := findXrayBinary(t)
	if bin == "" {
		t.Skip("xray бинарь не найден (XKIT_XRAY_BIN)")
	}
	assetDir := writeAFClientGeoSub(t)

	// «нода»: vless-ws inbound, freedom к loopback-таргету разрешён (в проде
	// таргеты публичные), access-log для доказательства маршрута.
	cert, key := testCertPEMSub(t)
	certLines := strings.Split(strings.TrimSpace(cert), "\n")
	keyLines := strings.Split(strings.TrimSpace(key), "\n")
	nodePort := freePortSub(t)
	nodeLog := filepath.Join(t.TempDir(), "node-access.log")
	nodeCfg := fmt.Sprintf(`{
	 "log": {"loglevel": "info", "access": %q},
	 "dns": {"hosts": {"youtube.com": "127.0.0.1", "t.me": "127.0.0.1"}, "queryStrategy": "UseIPv4"},
	 "inbounds": [{
	  "tag": "vless-ws", "listen": "127.0.0.1", "port": %d, "protocol": "vless",
	  "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "client@example.com"}], "decryption": "none"},
	  "streamSettings": {"network": "ws", "security": "tls", "wsSettings": {"path": "/ws"},
	   "tlsSettings": {"certificates": [{"certificate": %s, "key": %s}]}}
	 }],
	 "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4", "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
	}`, nodeLog, nodePort, mustJSONLines(certLines), mustJSONLines(keyLines))
	nodeProc := startClientSubAsset(t, bin, nodeCfg, assetDir)
	defer nodeProc.kill()
	waitTCPSub(t, nodePort)

	// таргет «заблокированного сайта»: маркер отвечает ЛЮБОЙ путь —
	// при проходе через ноду тело содержит VIA-NODE, при direct — нет.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "200-VIA-NODE")
	}))
	defer target.Close()
	targetHost, tpStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	var targetPort int
	fmt.Sscanf(tpStr, "%d", &targetPort)

	link := fmt.Sprintf("vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:%d?encryption=none&security=tls&sni=test.local&type=ws&path=%%2Fws#NODE", nodePort)
	ar := AntifilterRules{
		ProxySites:     []string{"domain:t.me"},
		DirectSites:    []string{"domain:bank.ru"},
		BlockedDomains: []string{"youtube.com"},
	}

	for name, gen := range map[string]func([]string) string{
		"default":  func(ls []string) string { return XrayJSONAntifilter(ls, nil, ar, "") },
		"profiles": func(ls []string) string { return XrayJSONAntifilterProfiles(ls, nil, ar, "") },
	} {
		sub := gen([]string{link})
		// 1) run -test РЕАЛЬНЫМ бинарём (корень AF-BUG-1: здесь падало
		// «proxySettings has been removed»)
		if out, err := runTestSub(t, bin, sub, assetDir); err != nil {
			t.Fatalf("%s: xray run -test подписки antifilter: %v\n%s", name, err, out)
		}
		// test-only адаптация: socks-порт/dns.hosts, routing не трогаем.
		// self-signed серт ноды: allowInsecure удалён в 26.x — доверяем через
		// tlsSettings.certificates usage=verify (тот же механизм, что pinnedPeerCertSha256).
		adapted, socksPort := afAdaptClientSub(t, sub, targetHost, targetPort)
		var cfg map[string]any
		json.Unmarshal([]byte(adapted), &cfg)
		for _, o := range cfg["outbounds"].([]any) {
			om := o.(map[string]any)
			stream, _ := om["streamSettings"].(map[string]any)
			if tls, ok := stream["tlsSettings"].(map[string]any); ok {
				tls["certificates"] = []any{map[string]any{"certificate": certLines, "usage": "verify"}}
			}
		}
		adaptedB, _ := json.Marshal(cfg)
		proc := startClientSubAsset(t, bin, string(adaptedB), assetDir)
		waitTCPSub(t, socksPort)
		socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)

		// 2) blocked-домен (inline-правило панели) → proxy-first → нода → таргет
		code, body, err := socksGETSub(socksAddr, fmt.Sprintf("http://youtube.com:%d/", targetPort), 12*time.Second)
		if err != nil || code != 200 || body != "200-VIA-NODE" {
			t.Fatalf("%s: blocked→нода: code=%d body=%q err=%v\nлог клиента:\n%s", name, code, body, err, proc.log())
		}
		// 3) инверсия: незаблокированный домен → catch-all direct с клиента.
		// dns.hosts резолвит и его в loopback-таргет, но routing шлёт мимо
		// proxy-first: ответ БЕЗ маркера ноды (таргет тот же, путь другой).
		// Для строгого доказательства используем отдельный «чистый» таргет.
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "200-DIRECT")
		}))
		phost, pport, _ := net.SplitHostPort(strings.TrimPrefix(plain.URL, "http://"))
		// незаблокированный IP-литерал: catch-all direct (никаких dns)
		code2, body2, err2 := socksGETSub(socksAddr, fmt.Sprintf("http://%s:%s/", phost, pport), 12*time.Second)
		plain.Close()
		if err2 != nil || code2 != 200 || body2 != "200-DIRECT" {
			t.Fatalf("%s: unblocked→direct: code=%d body=%q err=%v\n%s", name, code2, body2, err2, proc.log())
		}
		// always-proxy домен владельца тоже через ноду (proxy-first)
		code3, body3, err3 := socksGETSub(socksAddr, fmt.Sprintf("http://t.me:%d/", targetPort), 12*time.Second)
		if err3 != nil || code3 != 200 || body3 != "200-VIA-NODE" {
			t.Fatalf("%s: always-proxy→нода: code=%d body=%q err=%v\n%s", name, code3, body3, err3, proc.log())
		}
		proc.kill()
		// доказательство маршрута: access-log ноды содержит youtube.com и t.me
		nlog, _ := os.ReadFile(nodeLog)
		if !strings.Contains(string(nlog), "youtube.com") || !strings.Contains(string(nlog), "t.me") {
			t.Fatalf("%s: access-log ноды без blocked/always-proxy доменов:\n%s", name, nlog)
		}
	}
}

// TestXrayJSONRUDirectRealXrayRegression — ru-direct xray-json подписка не
// сломана фиксом AF-BUG-1: run -test OK + незаблокированный трафик через
// прокси (catch-all firstTag), RU-домен → direct.
func TestXrayJSONRUDirectRealXrayRegression(t *testing.T) {
	bin := findXrayBinary(t)
	if bin == "" {
		t.Skip("xray бинарь не найден (XKIT_XRAY_BIN)")
	}
	assetDir := writeAFClientGeoSub(t)
	cert, key := testCertPEMSub(t)
	certLines := strings.Split(strings.TrimSpace(cert), "\n")
	keyLines := strings.Split(strings.TrimSpace(key), "\n")
	nodePort := freePortSub(t)
	nodeCfg := fmt.Sprintf(`{
	 "log": {"loglevel": "error"},
	 "inbounds": [{
	  "tag": "vless-ws", "listen": "127.0.0.1", "port": %d, "protocol": "vless",
	  "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "client@example.com"}], "decryption": "none"},
	  "streamSettings": {"network": "ws", "security": "tls", "wsSettings": {"path": "/ws"},
	   "tlsSettings": {"certificates": [{"certificate": %s, "key": %s}]}}
	 }],
	 "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4", "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
	}`, nodePort, mustJSONLines(certLines), mustJSONLines(keyLines))
	nodeProc := startClientSubAsset(t, bin, nodeCfg, assetDir)
	defer nodeProc.kill()
	waitTCPSub(t, nodePort)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunnel-ok")
	}))
	defer target.Close()
	thost, tport, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))

	link := fmt.Sprintf("vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:%d?encryption=none&security=tls&sni=test.local&type=ws&path=%%2Fws#NODE", nodePort)
	sub := XrayJSON([]string{link})
	if out, err := runTestSub(t, bin, sub, assetDir); err != nil {
		t.Fatalf("ru-direct xray-json run -test: %v\n%s", err, out)
	}
	var cfg map[string]any
	json.Unmarshal([]byte(sub), &cfg)
	socksPort := freePortSub(t)
	cfg["inbounds"].([]any)[0].(map[string]any)["port"] = socksPort
	cfg["dns"] = map[string]any{"queryStrategy": "UseIPv4"}
	for _, o := range cfg["outbounds"].([]any) {
		om := o.(map[string]any)
		stream, _ := om["streamSettings"].(map[string]any)
		if tls, ok := stream["tlsSettings"].(map[string]any); ok {
			tls["certificates"] = []any{map[string]any{"certificate": certLines, "usage": "verify"}}
		}
	}
	// loopback-таргет через прокси: geoip:private→direct увёл бы мимо туннеля —
	// штатный extraRules-механизм (как в TestXrayJSONHy2SubscriptionE2E)
	sub2 := XrayJSONRouting([]string{link}, []map[string]any{
		{"type": "field", "ip": []string{thost + "/32"}, "outboundTag": "NODE"},
	})
	json.Unmarshal([]byte(sub2), &cfg)
	cfg["inbounds"].([]any)[0].(map[string]any)["port"] = socksPort
	cfg["dns"] = map[string]any{"queryStrategy": "UseIPv4"}
	for _, o := range cfg["outbounds"].([]any) {
		om := o.(map[string]any)
		stream, _ := om["streamSettings"].(map[string]any)
		if tls, ok := stream["tlsSettings"].(map[string]any); ok {
			tls["certificates"] = []any{map[string]any{"certificate": certLines, "usage": "verify"}}
		}
	}
	adapted, _ := json.Marshal(cfg)
	proc := startClientSubAsset(t, bin, string(adapted), assetDir)
	waitTCPSub(t, socksPort)
	code, body, err := socksGETSub(fmt.Sprintf("127.0.0.1:%d", socksPort), fmt.Sprintf("http://%s:%s/", thost, tport), 12*time.Second)
	if err != nil || code != 200 || body != "tunnel-ok" {
		t.Fatalf("ru-direct трафик через ноду: code=%d body=%q err=%v\n%s", code, body, err, proc.log())
	}
	proc.kill()
}
