package subscription

import (
	"encoding/json"
	"strings"
	"testing"
)

// antifilter-режим подписок (решение владельца): инверсия — blocked → proxy,
// остальное → direct. always-правила владельца доходят до клиентских конфигов.

const afTestLink = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@master.example.com:443?encryption=none&security=reality&sni=master.example.com&fp=chrome&pbk=mQghxPkdBvn4HPFr34mUhw0UcQG-t1kbuUZ8Fx1kUxU&sid=ab12&type=tcp&flow=xtls-rprx-vision#XKIT"

var afTestRules = AntifilterRules{
	ProxySites: []string{"geosite:telegram", "domain:custom.io"},
	ProxyIP:    []string{"geoip:telegram"},
	DirectSites: []string{"domain:bank.ru"},
	DirectIP:   []string{"geoip:private"},
	BlockedDomains: []string{"youtube.com"},
}

// TestClashAntifilter — MATCH,DIRECT (инверсия), RU-BLOCKED через rule-provider,
// always-правила выше af-правил, always-direct выше always-proxy.
func TestClashAntifilter(t *testing.T) {
	y := ClashYAMLAntifilter([]string{afTestLink}, nil, afTestRules, "https://master.example.com/s-x/abc/antifilter")
	if !strings.Contains(y, "MATCH,DIRECT") {
		t.Error("antifilter clash must end with MATCH,DIRECT (inversion)")
	}
	if strings.Contains(y, "MATCH,PROXY") {
		t.Error("MATCH,PROXY left in antifilter clash")
	}
	if !strings.Contains(y, "rule-providers:") || !strings.Contains(y, "xkit-blocked") {
		t.Error("blocked rule-provider missing")
	}
	if !strings.Contains(y, "RULE-SET,xkit-blocked-domains,PROXY") || !strings.Contains(y, "RULE-SET,xkit-blocked-ip,PROXY") {
		t.Error("RULE-SET blocked rules missing")
	}
	// RU-исключение direct ВЫШЕ blocked
	iRU := strings.Index(y, "GEOIP,RU,DIRECT")
	iBlocked := strings.Index(y, "RULE-SET,xkit-blocked-ip,PROXY")
	if iRU < 0 || iBlocked < 0 || iRU > iBlocked {
		t.Errorf("RU direct must precede blocked rules (ru=%d blocked=%d)", iRU, iBlocked)
	}
	// always-direct ВЫШЕ always-proxy
	iAD := strings.Index(y, "DOMAIN-SUFFIX,bank.ru,DIRECT")
	iAP := strings.Index(y, "DOMAIN-SUFFIX,custom.io,PROXY")
	if iAD < 0 || iAP < 0 || iAD > iAP {
		t.Errorf("always-direct must precede always-proxy (ad=%d ap=%d)", iAD, iAP)
	}
	// geoip:telegram multi-token → отдельные GEOIP-строки
	if !strings.Contains(y, "GEOIP,telegram,PROXY") {
		t.Error("always-proxy geoip category missing")
	}
	if !strings.Contains(y, "GEOSITE,telegram,PROXY") {
		t.Error("always-proxy geosite category missing")
	}
	// QUIC/STUN block сохранён (утечки не возвращаем)
	if !strings.Contains(y, "DOMAIN-SUFFIX,stun.l.google.com,REJECT") {
		t.Error("STUN block lost in antifilter clash")
	}
}

// TestXrayJSONAntifilter — catch-all direct, blocked через ext-файлы? нет —
// клиент не имеет xkit-blocked.dat: скачиваемые geo-ресурсы не поддерживаются
// xray-json подпиской → blocked-домены inline из ru-blocked.txt (limit),
// blocked-IP через remote rule-set не работает — используем загрузку dat?
// Решение: xray-json получает geosite:ru-blocked (клиентские .dat обновляются
// приложением) + inline-хвост не нужен: geosite/geoip ru-blocked есть в
// runetfreedom-совместимых сборках; для Loyalsoldier — fallback inline.
func TestXrayJSONAntifilter(t *testing.T) {
	j := XrayJSONAntifilter([]string{afTestLink}, nil, afTestRules, "https://master.example.com/s-x/abc/antifilter")
	var cfg map[string]any
	if err := json.Unmarshal([]byte(j), &cfg); err != nil {
		t.Fatal(err)
	}
	rt := cfg["routing"].(map[string]any)
	rules := rt["rules"].([]any)
	last := rules[len(rules)-1].(map[string]any)
	if last["outboundTag"] != "direct" {
		t.Errorf("catch-all must be direct (inversion), got %v", last)
	}
	// always-direct правило раньше always-proxy и раньше blocked
	var idxAD, idxAP, idxBlocked, idxRU = -1, -1, -1, -1
	for i, r := range rules {
		rm := r.(map[string]any)
		if doms, ok := rm["domain"].([]any); ok {
			for _, d := range doms {
				if d == "domain:bank.ru" {
					idxAD = i
				}
				if d == "domain:custom.io" {
					idxAP = i
				}
				if d == "domain:youtube.com" {
					idxBlocked = i
				}
			}
		}
		if ips, ok := rm["ip"].([]any); ok {
			for _, ip := range ips {
				if ip == "geoip:ru" {
					idxRU = i
				}
			}
		}
	}
	if idxAD < 0 || idxAP < 0 || idxAD > idxAP {
		t.Errorf("always-direct(%d) must precede always-proxy(%d)", idxAD, idxAP)
	}
	if idxBlocked < 0 {
		t.Error("blocked domains missing (ru-blocked payload)")
	}
	if idxRU < 0 || idxRU > idxBlocked {
		t.Errorf("RU-exception(%d) must precede blocked(%d)", idxRU, idxBlocked)
	}
}

// TestSingboxAntifilter — final=direct, blocked rule-set remote (.srs),
// always-direct выше always-proxy, RU-исключение сохранено.
func TestSingboxAntifilter(t *testing.T) {
	j := SingboxJSONAntifilter([]string{afTestLink}, afTestRules, "https://master.example.com/s-x/abc/antifilter")
	var cfg map[string]any
	if err := json.Unmarshal([]byte(j), &cfg); err != nil {
		t.Fatal(err)
	}
	rt := cfg["route"].(map[string]any)
	if rt["final"] != "direct" {
		t.Errorf("singbox final must be direct (inversion), got %v", rt["final"])
	}
	rs, ok := rt["rule_set"].([]any)
	if !ok || len(rs) == 0 {
		t.Fatal("remote rule_set missing (blocked source)")
	}
	foundBlocked := false
	for _, r := range rs {
		rm := r.(map[string]any)
		if rm["tag"] == "xkit-blocked-domains" || rm["tag"] == "xkit-blocked-ip" {
			foundBlocked = true
			if rm["type"] != "remote" || rm["format"] != "source" {
				t.Errorf("rule-set must be remote/source: %v", rm)
			}
			if !strings.HasPrefix(rm["url"].(string), "https://master.example.com/s-x/abc/antifilter") {
				t.Errorf("rule-set url must point to panel sub endpoint: %v", rm["url"])
			}
		}
	}
	if !foundBlocked {
		t.Error("blocked rule-sets not declared")
	}
	rules := rt["rules"].([]any)
	var idxAD, idxAP, idxBlocked = -1, -1, -1
	for i, r := range rules {
		rm := r.(map[string]any)
		if ds, ok := rm["domain_suffix"].([]any); ok {
			for _, d := range ds {
				if d == "bank.ru" {
					idxAD = i
				}
				if d == "custom.io" {
					idxAP = i
				}
			}
		}
		if rs, ok := rm["rule_set"].([]any); ok {
			for _, s := range rs {
				if s == "xkit-blocked-domains" {
					idxBlocked = i
				}
			}
		}
	}
	if idxAD < 0 || idxAP < 0 || idxAD > idxAP {
		t.Errorf("always-direct(%d) must precede always-proxy(%d)", idxAD, idxAP)
	}
	if idxBlocked < 0 {
		t.Error("blocked rule-set match rule missing")
	}
	if idxAP > idxBlocked {
		t.Errorf("always-proxy(%d) must precede blocked(%d)", idxAP, idxBlocked)
	}
	// RU-исключение direct сохранено
	if !strings.Contains(j, `"ru"`) {
		t.Error("RU suffix exception lost")
	}
}

// TestClashAntifilterNoProviderURL — без URL (страница подписки не знает хост?):
// blocked rule-set опускается, always-правила и инверсия остаются.
func TestClashAntifilterNoURL(t *testing.T) {
	y := ClashYAMLAntifilter([]string{afTestLink}, nil, afTestRules, "")
	if strings.Contains(y, "rule-providers:") {
		t.Error("provider without url must be omitted")
	}
	if !strings.Contains(y, "MATCH,DIRECT") {
		t.Error("inversion lost")
	}
	if !strings.Contains(y, "DOMAIN-SUFFIX,custom.io,PROXY") {
		t.Error("always rules must survive without provider url")
	}
}