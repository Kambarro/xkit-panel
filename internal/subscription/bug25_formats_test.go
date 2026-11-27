package subscription

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestClashProxyServerNameserver — BUG-5 (QA 2026-11-26): clash без
// proxy-server-nameserver → DNS bootstrap-loop (домен прокси-сервера резолвится
// через туннель, который ещё не поднят) — mihomo из коробки мёртв.
// default-nameserver китайские (из РФ/ЕС могут не отвечать) → 1.1.1.1/8.8.8.8.
func TestClashProxyServerNameserver(t *testing.T) {
	cy := ClashYAML([]string{testVlessReality, testHy2})
	if !strings.Contains(cy, "proxy-server-nameserver:") {
		t.Fatal("proxy-server-nameserver отсутствует — DNS bootstrap-loop (BUG-5)")
	}
	// bootstrap-DNS резолвит адреса прокси напрямую (IP, без #PROXY)
	idx := strings.Index(cy, "proxy-server-nameserver:")
	rest := cy[idx+len("proxy-server-nameserver:"):]
	end := strings.Index(rest, "\n  nameserver:") // следующая dns-секция
	if end < 0 {
		end = len(rest)
	}
	section := rest[:end]
	if !strings.Contains(section, "1.1.1.1") || !strings.Contains(section, "8.8.8.8") {
		t.Errorf("proxy-server-nameserver без рабочих bootstrap-DNS: %s", section)
	}
	if strings.Contains(section, "#PROXY") {
		t.Error("proxy-server-nameserver через PROXY = тот же bootstrap-loop")
	}
	// default-nameserver: рабочие из РФ/ЕС, не китайские
	di := strings.Index(cy, "default-nameserver:")
	dsec := cy[di : di+120]
	if strings.Contains(dsec, "223.5.5.5") || strings.Contains(dsec, "119.29.29.29") {
		t.Errorf("default-nameserver китайские DNS (из РФ/ЕС могут молчать): %s", dsec)
	}
	if !strings.Contains(dsec, "1.1.1.1") {
		t.Errorf("default-nameserver без 1.1.1.1: %s", dsec)
	}
}

// TestSingboxRunsInRealCores — BUG-2 (QA 2026-11-26): подписка не запускалась
// реальным ядром: 1.12 run FATAL «detour to an empty direct outbound» (новый
// формат dns.servers + local detour=direct без domain_resolver), 1.11 не парсил
// новый формат вовсе; после обходов — DNS-loopback (DoH remote через select
// резолвил сам себя), hy2 «unsupported usage for uTLS».
// Проверка РЕАЛЬНЫМИ бинарями (skip если не найдены): check AND run.
func TestSingboxRunsInRealCores(t *testing.T) {
	bins := findSingboxBinaries(t)
	if len(bins) == 0 {
		t.Skip("sing-box бинари не найдены (XKIT_SINGBOX_BIN / workspace QA)")
	}
	// валидный x25519 reality-ключ (32 байта base64url) — ядро валидирует при check
	const realityPub = "mQghxPkdBvn4HPFr34mUhw0UcQG-t1kbuUZ8Fx1kUxU"
	realityLink := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vpn.example.com:443?encryption=none&security=reality&sni=vpn.example.com&fp=chrome&pbk=" + realityPub + "&sid=ab12&flow=xtls-rprx-vision&type=tcp#Reality"
	links := []string{realityLink, testVlessWS, testHy2,
		"vless://b831381d-6324-4d53-ad4f-8cda48b30811@vpn.example.com:8444?encryption=none&security=reality&sni=vpn.example.com&fp=chrome&pbk=" + realityPub + "&sid=ab12&type=xhttp&path=%2Fxh#XHTTP"}
	sj := SingboxJSON(links)
	var cfg map[string]any
	if err := json.Unmarshal([]byte(sj), &cfg); err != nil {
		t.Fatalf("singbox JSON invalid: %v", err)
	}
	// структурные инварианты фикса (RED до правки генератора):
	// 1) dns.servers — LEGACY address-формат (парсится и 1.11, и 1.12; новый
	//    type/server формат 1.11 не знает: «unknown field server»)
	dns := cfg["dns"].(map[string]any)
	for _, sv := range dns["servers"].([]any) {
		m := sv.(map[string]any)
		if _, bad := m["type"]; bad {
			t.Errorf("dns server нового формата (1.11 не парсит): %v", m)
		}
		if m["address"] == nil {
			t.Errorf("dns server без address (legacy): %v", m)
		}
	}
	// 2) detour: local ОБЯЗАН direct (C-1: без него DNS-запрос идёт через
	//    Default()=select→proxy = loopback при домене сервера); remote — через select.
	//    Legacy address + detour=direct безопасен в 1.12 (LegacyDNSDialer пропускает
	//    IsEmpty); FATAL «empty direct outbound» — только new-format, его нет (п.1).
	for _, sv := range dns["servers"].([]any) {
		m := sv.(map[string]any)
		if m["tag"] == "local" && m["detour"] != "direct" {
			t.Errorf("C-1: dns local без detour=direct — DNS query loopback с доменным адресом сервера: %v", m)
		}
	}
	// 3) bootstrap: домены прокси-серверов резолвятся local (не через туннель)
	foundBootstrap := false
	for _, r := range dns["rules"].([]any) {
		rm := r.(map[string]any)
		if rm["server"] != "local" {
			continue
		}
		if doms, ok := rm["domain"].([]any); ok {
			for _, d := range doms {
				if d == "vpn.example.com" {
					foundBootstrap = true
				}
			}
		}
	}
	if !foundBootstrap {
		t.Error("dns.rules: домен прокси-сервера → local отсутствует (DNS loopback)")
	}
	// 4) hy2 БЕЗ uTLS (QUIC: «unsupported usage for uTLS» в sing-box)
	for _, o := range cfg["outbounds"].([]any) {
		om := o.(map[string]any)
		if om["type"] == "hysteria2" {
			tls, _ := om["tls"].(map[string]any)
			if u, has := tls["utls"]; has {
				if um, ok := u.(map[string]any); ok && um["enabled"] == true {
					t.Error("hy2 tls.utls enabled — sing-box QUIC его запрещает")
				}
			}
		}
	}
	// 5) xhttp транслирован (иначе ссылка молча теряла транспорт)
	foundXHTTP := false
	for _, o := range cfg["outbounds"].([]any) {
		om := o.(map[string]any)
		if tr, ok := om["transport"].(map[string]any); ok && tr["type"] == "http" {
			foundXHTTP = true
		}
	}
	if !foundXHTTP {
		t.Error("xhttp не транслирован в transport type=http")
	}
	// реальные ядра: check + run (run — главный критерий QA, check врёт)
	for _, bin := range bins {
		runSingboxCore(t, bin, sj)
	}
}