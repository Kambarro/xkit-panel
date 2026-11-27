package subscription

// AF-BUG-4 аудит других форматов: blocked-домен И его ПОДДОМЕН обязаны уходить
// через ноду в xray-json (domain: = суффикс-матч, сверено с исходниками
// geodata/strmatcher DomainMatcher.Match) и sing-box (domain_suffix в remote
// source rule-set — суффикс по semantics). Реальные ядра, живой трафик;
// бинари не найдены — skip. Clash-вариант — antifilter_mihomo_e2e_test.go.

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
)

// afSubNode — тестовая нода vless-ws tls с ИЗВЕСТНЫМ сертом (клиент доверяет
// ему через certificates/insecure) + маркер-таргеты. dns.hosts ноды — СУФФИКС
// domain:youtube.com: поддомен, ушедший в туннель, резолвит DNS НОДЫ.
func afSubNode(t *testing.T, bin string) (link string, certLines []string, targetPort int, plainURL, nodeLog string, cleanup func()) {
	t.Helper()
	assetDir := writeAFClientGeoSub(t)
	cert, key := testCertPEMSub(t)
	certLines = strings.Split(strings.TrimSpace(cert), "\n")
	keyLines := strings.Split(strings.TrimSpace(key), "\n")
	nodePort := freePortSub(t)
	nodeLog = filepath.Join(t.TempDir(), "node-access.log")
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
	nodeProc := startClientSubAsset(t, bin, nodeCfg, assetDir)
	waitTCPSub(t, nodePort)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "200-VIA-NODE")
	}))
	_, tpStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	fmt.Sscanf(tpStr, "%d", &targetPort)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "200-DIRECT")
	}))
	plainURL = plain.URL
	link = fmt.Sprintf("vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:%d?encryption=none&security=tls&sni=test.local&type=ws&path=%%2Fws#NODE", nodePort)
	cleanup = func() { nodeProc.kill(); target.Close(); plain.Close() }
	return
}

// TestXrayJSONAntifilterSubdomainE2E — domain:youtube.com матчит www.youtube.com
// (суффикс). Поддомен и апекс → proxy-first → нода; unblocked IP → direct.
func TestXrayJSONAntifilterSubdomainE2E(t *testing.T) {
	bin := findXrayBinary(t)
	if bin == "" {
		t.Skip("xray бинарь не найден (XKIT_XRAY_BIN)")
	}
	link, certLines, targetPort, plainURL, nodeLog, cleanup := afSubNode(t, bin)
	defer cleanup()
	ar := AntifilterRules{BlockedDomains: []string{"youtube.com"}}
	sub := XrayJSONAntifilter([]string{link}, nil, ar, "")
	assetDir := writeAFClientGeoSub(t)
	if out, err := runTestSub(t, bin, sub, assetDir); err != nil {
		t.Fatalf("xray run -test: %v\n%s", err, out)
	}
	// test-only адаптация: socks-порт, dns.hosts суффикс, доверие серту ноды
	var cfg map[string]any
	json.Unmarshal([]byte(sub), &cfg)
	socksPort := freePortSub(t)
	cfg["inbounds"].([]any)[0].(map[string]any)["port"] = socksPort
	cfg["dns"] = map[string]any{"hosts": map[string]any{"domain:youtube.com": "127.0.0.1"}, "queryStrategy": "UseIPv4"}
	for _, o := range cfg["outbounds"].([]any) {
		om := o.(map[string]any)
		stream, _ := om["streamSettings"].(map[string]any)
		if tls, ok := stream["tlsSettings"].(map[string]any); ok {
			tls["certificates"] = []any{map[string]any{"certificate": certLines, "usage": "verify"}}
		}
	}
	adapted, _ := json.Marshal(cfg)
	proc := startClientSubAsset(t, bin, string(adapted), assetDir)
	defer proc.kill()
	waitTCPSub(t, socksPort)
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	for _, host := range []string{"www.youtube.com", "youtube.com"} {
		code, body, err := socksGETSub(socksAddr, fmt.Sprintf("http://%s:%d/", host, targetPort), 15*time.Second)
		if err != nil || code != 200 || body != "200-VIA-NODE" {
			t.Fatalf("%s → нода: code=%d body=%q err=%v\n%s", host, code, body, err, proc.log())
		}
	}
	phost, pport, _ := net.SplitHostPort(strings.TrimPrefix(plainURL, "http://"))
	code, body, err := socksGETSub(socksAddr, fmt.Sprintf("http://%s:%s/", phost, pport), 15*time.Second)
	if err != nil || code != 200 || body != "200-DIRECT" {
		t.Fatalf("unblocked → direct: code=%d body=%q err=%v\n%s", code, body, err, proc.log())
	}
	nlog, _ := os.ReadFile(nodeLog)
	if !strings.Contains(string(nlog), "www.youtube.com") {
		t.Fatalf("access-log ноды без www.youtube.com:\n%s", nlog)
	}
}

// TestSingboxAntifilterSubdomainE2E — sing-box domain_suffix (remote source
// rule-set от РЕАЛЬНОГО antifilter.Manager) матчит поддомены. check+run+трафик
// на 1.11.15 и 1.12.0. Поддомен и апекс → select → нода; unblocked IP → direct.
func TestSingboxAntifilterSubdomainE2E(t *testing.T) {
	bins := findSingboxBinaries(t)
	if len(bins) == 0 {
		t.Skip("sing-box бинари не найдены (XKIT_SINGBOX_BIN / workspace QA)")
	}
	xray := findXrayBinary(t)
	if xray == "" {
		t.Skip("xray бинарь не найден (XKIT_XRAY_BIN)")
	}
	link, _, targetPort, plainURL, nodeLog, cleanup := afSubNode(t, xray)
	defer cleanup()
	// blocked-наборы тем же кодом, что панель (Manager.ServeBlocked)
	m := afTestManager(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/antifilter/", func(w http.ResponseWriter, r *http.Request) {
		m.ServeBlocked(w, r, strings.TrimPrefix(r.URL.Path, "/antifilter/"))
	})
	provSrv := httptest.NewServer(mux)
	defer provSrv.Close()
	sub := SingboxJSONAntifilter([]string{link}, AntifilterRules{}, provSrv.URL+"/antifilter")

	for _, bin := range bins {
		t.Run(filepath.Base(filepath.Dir(bin)), func(t *testing.T) {
			var cfg map[string]any
			json.Unmarshal([]byte(sub), &cfg)
			port := freePortSub(t)
			cfg["inbounds"].([]any)[0].(map[string]any)["listen_port"] = port
			// test-only DNS: DoH через туннель в тесте не работает (нода режет
			// не-loopback) — системный резолвер напрямую (урок C-1 test-конфиг).
			cfg["dns"] = map[string]any{"servers": []any{map[string]any{"tag": "local", "address": "local", "detour": "direct"}}, "final": "local", "strategy": "ipv4_only"}
			for _, o := range cfg["outbounds"].([]any) {
				om := o.(map[string]any)
				if tls, ok := om["tls"].(map[string]any); ok {
					tls["insecure"] = true // self-signed тестовой ноды
					delete(tls, "utls")
				}
			}
			adapted, _ := json.Marshal(cfg)
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.json")
			os.WriteFile(cfgPath, adapted, 0644)
			if out, err := exec.Command(bin, "check", "-c", cfgPath).CombinedOutput(); err != nil {
				t.Fatalf("check: %v\n%s", err, out)
			}
			logPath := filepath.Join(dir, "run.log")
			lf, _ := os.Create(logPath)
			cmd := exec.Command(bin, "run", "-c", cfgPath)
			cmd.Stdout, cmd.Stderr = lf, lf
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait(); lf.Close() }()
			waitTCPSub(t, port)
			socksAddr := fmt.Sprintf("127.0.0.1:%d", port)
			for _, host := range []string{"www.youtube.com", "youtube.com"} {
				code, body, err := socksGETSub(socksAddr, fmt.Sprintf("http://%s:%d/", host, targetPort), 15*time.Second)
				if err != nil || code != 200 || body != "200-VIA-NODE" {
					b, _ := os.ReadFile(logPath)
					t.Fatalf("%s → нода: code=%d body=%q err=%v\nsing-box log:\n%s", host, code, body, err, b)
				}
			}
			phost, pport, _ := net.SplitHostPort(strings.TrimPrefix(plainURL, "http://"))
			code, body, err := socksGETSub(socksAddr, fmt.Sprintf("http://%s:%s/", phost, pport), 15*time.Second)
			if err != nil || code != 200 || body != "200-DIRECT" {
				b, _ := os.ReadFile(logPath)
				t.Fatalf("unblocked → direct: code=%d body=%q err=%v\n%s", code, body, err, b)
			}
			nlog, _ := os.ReadFile(nodeLog)
			if !strings.Contains(string(nlog), "www.youtube.com") {
				t.Fatalf("access-log ноды без www.youtube.com:\n%s", nlog)
			}
		})
	}
}
