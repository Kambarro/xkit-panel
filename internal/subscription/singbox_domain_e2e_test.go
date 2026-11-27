package subscription

// C-1 (Ops-деплой 147be19, 2026-11-26): подписка sing-box с ДОМЕННЫМ адресом
// сервера не работает живьём ни на 1.11, ни на 1.12: «DNS query loopback in
// transport[local]». Механика (исходники sing-box): dns local БЕЗ detour dial'ит
// через outboundManager.Default() = select → proxy → резолв домена сервера →
// снова local → петля. Фикс: legacy address + detour:"direct" у local.
// В 1.12 legacy-сервер апгрейдится с Legacy=true → LegacyDNSDialer пропускает
// проверку IsEmpty (FATAL «detour to an empty direct outbound» — только у
// new-format); в 1.11 проверки IsEmpty нет вовсе. Проверено по исходникам
// v1.11.15 (route/router.go) и v1.12.0 (option/dns.go Upgrade, common/dialer/detour.go).
// Unit-E2E со 127.0.0.1 баг не ловил (bootstrap не нужен) — здесь ДОМЕН + свой
// DNS-сервер, отдающий 127.0.0.1, и реальный run+трафик на ОБОИХ ядрах.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startTestDNS — UDP DNS на loopback: любой A-запрос → 127.0.0.1 (домен сервера
// «резолвится» на локальный xray). Возвращает адрес 127.0.0.1:port.
func startTestDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	srv := &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("127.0.0.1"),
				})
			}
		}
		w.WriteMsg(m)
	})}
	go srv.ListenAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	// ждём готовности
	deadline := time.Now().Add(5 * time.Second)
	c := new(dns.Client)
	m := new(dns.Msg).SetQuestion("probe.test.", dns.TypeA)
	for time.Now().Before(deadline) {
		_, _, err := c.Exchange(m, addr)
		if err == nil {
			return addr
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("тестовый DNS не поднялся")
	return ""
}

// TestSingboxDomainServerTrafficE2E — C-1: подписка с доменным адресом сервера
// обязана гнать трафик реальными 1.11 И 1.12 (check врёт — только run+трафик).
func TestSingboxDomainServerTrafficE2E(t *testing.T) {
	bins := findSingboxBinaries(t)
	if len(bins) == 0 {
		t.Skip("sing-box бинари не найдены (XKIT_SINGBOX_BIN / workspace QA)")
	}
	xrayBin := findXrayBinary(t)
	if xrayBin == "" {
		t.Skip("xray бинарь не найден (XKIT_XRAY_BIN)")
	}
	dnsAddr := startTestDNS(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunnel-ok")
	}))
	defer target.Close()
	targetHost, targetPortStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))

	// локальный xray-сервер ws-tls (серт test.local)
	cert, key := testCertPEMSub(t)
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
	srvProc := startProcSub(t, xrayBin, srvCfg, "run")
	defer srvProc.kill()
	waitTCPSub(t, wsPort)

	// подписка: адрес сервера — ДОМЕН (не IP!). .test не матчит RU-правила.
	const serverDomain = "server.e2e-domain.test"
	link := fmt.Sprintf("vless://b831381d-6324-4d53-ad4f-8cda48b30811@%s:%d?encryption=none&security=tls&sni=test.local&type=ws&path=%%2Fws#WS", serverDomain, wsPort)
	sj := SingboxJSON([]string{link})
	var cfg map[string]any
	if err := json.Unmarshal([]byte(sj), &cfg); err != nil {
		t.Fatalf("singbox JSON invalid: %v", err)
	}

	// структурные инварианты фикса (RED до правки генератора):
	// local dns — legacy address + detour=direct (запрос НЕ через Default()=select)
	dnsCfg := cfg["dns"].(map[string]any)
	var local map[string]any
	for _, sv := range dnsCfg["servers"].([]any) {
		m := sv.(map[string]any)
		if m["tag"] == "local" {
			local = m
		}
		if _, bad := m["type"]; bad {
			t.Errorf("dns server нового формата (1.11 не парсит): %v", m)
		}
	}
	if local == nil {
		t.Fatal("dns local отсутствует")
	}
	if local["detour"] != "direct" {
		t.Errorf("C-1: dns local без detour=direct — резолв через select→proxy→local = DNS query loopback (local=%v)", local)
	}
	// bootstrap-правило: домен сервера → local
	foundBootstrap := false
	for _, r := range dnsCfg["rules"].([]any) {
		rm := r.(map[string]any)
		if rm["server"] != "local" {
			continue
		}
		if doms, ok := rm["domain"].([]any); ok {
			for _, d := range doms {
				if d == serverDomain {
					foundBootstrap = true
				}
			}
		}
	}
	if !foundBootstrap {
		t.Error("dns.rules: домен сервера → local отсутствует")
	}

	// test-only адаптации (механизм bootstrap/detour НЕ трогаем): доверие
	// self-signed, свободный mixed-порт, loopback-таргет через туннель,
	// local DNS → тестовый сервер (в проде 77.88.8.8, домен резолвится наружу).
	for _, o := range cfg["outbounds"].([]any) {
		if tls, ok := o.(map[string]any)["tls"].(map[string]any); ok {
			tls["insecure"] = true
		}
	}
	mixedPort := freePortSub(t)
	cfg["inbounds"].([]any)[0].(map[string]any)["listen_port"] = mixedPort
	route := cfg["route"].(map[string]any)
	route["rules"] = append([]any{map[string]any{"ip_cidr": []any{"127.0.0.0/8"}, "outbound": "select"}}, route["rules"].([]any)...)
	local["address"] = "udp://" + dnsAddr
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
		log := proc.log()
		proc.kill()
		if strings.Contains(log, "DNS query loopback") {
			t.Errorf("%s: C-1 DNS query loopback в логе:\n%s", ver, log)
		}
		if !ok {
			t.Errorf("%s: трафик с ДОМЕННЫМ адресом сервера не прошёл: %v\nлог:\n%s", ver, lastErr, log)
		}
	}
}
