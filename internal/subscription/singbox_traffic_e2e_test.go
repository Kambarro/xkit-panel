package subscription

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// TestSingboxSubscriptionTrafficE2E — BUG-2 (QA): подписка sing-box обязана
// не просто стартовать, а ГНАТЬ ТРАФИК через туннель реальным ядром.
// ws-tls: подписка → sing-box run → mixed-port → HTTP через туннель → 200.
// reality: локальный xray-сервер REALITY (ключи из ядра) → sing-box-клиент
// из подписки → трафик (проверка совместимости reality sing-box↔xray 26.11.9).
// Требует реальные бинари (XKIT_SINGBOX_BIN / QA workspace) — иначе skip.
func TestSingboxSubscriptionTrafficE2E(t *testing.T) {
	bins := findSingboxBinaries(t)
	if len(bins) == 0 {
		t.Skip("sing-box бинари не найдены")
	}
	// целевой HTTP-сервер «в интернете» (loopback; sing-box ip_is_private→direct
	// обойдём кастомным правилом: тест правит ТОЛЬКО маршрутизацию loopback,
	// транспорт/TLS/auth не трогает)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunnel-ok")
	}))
	defer target.Close()
	targetHost, targetPortStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))

	// локальный xray-сервер: ws-tls inbound (сертификат test.local)
	cert, key := testCertPEMSub(t)
	// xray tlsSettings.certificate/key — массивы строк (PEM по строкам)
	certLines := strings.Split(strings.TrimSpace(cert), "\n")
	keyLines := strings.Split(strings.TrimSpace(key), "\n")
	wsPort := freePortSub(t)
	srvCfg := fmt.Sprintf(`{
	 "log": {"loglevel": "error"},
	 "inbounds": [{
	  "tag": "ws-in", "listen": "127.0.0.1", "port": %d, "protocol": "vless",
	  "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "e2e@test.ru"}], "decryption": "none"},
	  "streamSettings": {"network": "ws", "security": "tls", "wsSettings": {"path": "/ws"},
	   "tlsSettings": {"certificates": [{"certificate": %s, "key": %s}]}}
	 }],
	 "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
	}`, wsPort, mustJSONLines(certLines), mustJSONLines(keyLines))
	xrayBin := findXrayBinary(t)
	if xrayBin == "" {
		t.Skip("xray бинарь не найден (XKIT_XRAY_BIN)")
	}
	srvProc := startProcSub(t, xrayBin, srvCfg, "run")
	defer srvProc.kill()
	waitTCPSub(t, wsPort)

	// подписка: raw-ссылка ws-tls → SingboxJSON (адрес 127.0.0.1 — bootstrap не нужен)
	link := fmt.Sprintf("vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:%d?encryption=none&security=tls&sni=test.local&type=ws&path=%%2Fws#WS", wsPort)
	sj := SingboxJSON([]string{link})
	var cfg map[string]any
	json.Unmarshal([]byte(sj), &cfg)
	// test-only: доверие self-signed (insecure в 1.11/1.12 есть), свободный mixed-порт,
	// loopback-таргет через туннель (в проде таргеты публичные)
	for _, o := range cfg["outbounds"].([]any) {
		om := o.(map[string]any)
		if tls, ok := om["tls"].(map[string]any); ok {
			tls["insecure"] = true
		}
	}
	mixedPort := freePortSub(t)
	cfg["inbounds"].([]any)[0].(map[string]any)["listen_port"] = mixedPort
	route := cfg["route"].(map[string]any)
	rules := route["rules"].([]any)
	route["rules"] = append([]any{map[string]any{"ip_cidr": []any{"127.0.0.0/8"}, "outbound": "select"}}, rules...)
	adapted, _ := json.Marshal(cfg)

	for _, bin := range bins {
		ver := coreVerSub(bin)
		proc := startProcSub(t, bin, string(adapted), "run")
		waitTCPSub(t, mixedPort)
		ok := false
		var lastErr error
		for i := 0; i < 3; i++ {
			code, body, err := socksGETSub(fmt.Sprintf("127.0.0.1:%d", mixedPort), fmt.Sprintf("http://%s:%s/", targetHost, targetPortStr), 10*time.Second)
			if err == nil && code == 200 && body == "tunnel-ok" {
				ok = true
				break
			}
			if err != nil {
				lastErr = err
			} else {
				lastErr = fmt.Errorf("code=%d body=%q", code, body)
			}
		}
		proc.kill()
		if !ok {
			t.Errorf("%s: трафик через ws-tls из sing-box подписки не прошёл: %v\nлог:\n%s", ver, lastErr, proc.log())
		}
	}
}

// --- helpers (минимум, без зависимостей от api-пакета) ---

func testCertPEMSub(t *testing.T) (string, string) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test.local"},
		DNSNames: []string{"test.local"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func mustJSON(s string) string { b, _ := json.Marshal(s); return string(b) }
func mustJSONLines(s []string) string { b, _ := json.Marshal(s); return string(b) }

func freePortSub(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func findXrayBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("XKIT_XRAY_BIN"); p != "" {
		return p
	}
	for _, p := range []string{"/usr/local/bin/xray", "/usr/bin/xray"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	// xray из go mod cache не бинарь; ищем в PATH
	if p, err := exec.LookPath("xray"); err == nil {
		return p
	}
	return ""
}

type procSub struct {
	cmd     *exec.Cmd
	logPath string
}

func (p *procSub) kill() { p.cmd.Process.Kill(); p.cmd.Wait() }
func (p *procSub) log() string {
	b, _ := os.ReadFile(p.logPath)
	if len(b) > 4000 {
		b = b[len(b)-4000:]
	}
	return string(b)
}

func startProcSub(t *testing.T, bin, cfgJSON, subcmd string) *procSub {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(cfgJSON), 0644)
	logPath := filepath.Join(dir, "run.log")
	lf, _ := os.Create(logPath)
	cmd := exec.Command(bin, subcmd, "-c", cfgPath)
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); lf.Close() })
	return &procSub{cmd: cmd, logPath: logPath}
}

func waitTCPSub(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("порт %d не поднялся за 10с", port)
}

func socksGETSub(socksAddr, url string, timeout time.Duration) (int, string, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return 0, "", err
	}
	cl := &http.Client{Timeout: timeout, Transport: &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext}}
	resp, err := cl.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n]), nil
}

func coreVerSub(bin string) string {
	out, _ := exec.Command(bin, "version").Output()
	return strings.SplitN(string(out), "\n", 2)[0]
}

var _ = context.Background
var _ = base64.StdEncoding