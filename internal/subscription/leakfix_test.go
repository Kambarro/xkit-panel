package subscription

import (
	"encoding/json"
	"strings"
	"testing"
)

// Аудит #3/#4/#5/#11: dns-секции Clash/sing-box, block QUIC/STUN во всех форматах,
// udp:false на TCP-транспортах. Табличные проверки генераторов.

const testVlessReality = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vpn.example.com:443?encryption=none&security=reality&sni=vpn.example.com&fp=chrome&pbk=pub123&sid=ab12&flow=xtls-rprx-vision&type=tcp#Reality"
const testVlessWS = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vpn.example.com:443?encryption=none&security=tls&sni=vpn.example.com&type=ws&path=%2Fws#WS"
const testHy2 = "hysteria2://authpass@vpn.example.com:8443?sni=vpn.example.com&obfs=salamander&obfs-password=obfspass#Hy2"

// TestClashDNS — dns-блок: fake-ip, DoH через PROXY, fallback + geoip RU фильтр,
// GEOIP,RU,DIRECT,no-resolve (без резолва через системный DNS).
func TestClashDNS(t *testing.T) {
	cy := ClashYAML([]string{testVlessReality})
	for _, want := range []string{
		"dns:",
		"enable: true",
		"enhanced-mode: fake-ip",
		"nameserver:",
		"https://1.1.1.1/dns-query#PROXY",
		"fallback:",
		"fallback-filter:",
		"geoip: true",
		"geoip-code: RU",
		"GEOIP,RU,DIRECT,no-resolve",
	} {
		if !strings.Contains(cy, want) {
			t.Errorf("clash dns missing %q", want)
		}
	}
	// dns ДО rules (порядок секций не важен для YAML, но проверим наличие обеих)
	if !strings.Contains(cy, "rules:") {
		t.Error("clash rules missing")
	}
}

// TestClashBlockQUICSTUN — REJECT UDP/443 (QUIC) + STUN порты/домены ДО MATCH.
func TestClashBlockQUICSTUN(t *testing.T) {
	cy := ClashYAML([]string{testVlessReality})
	for _, want := range []string{
		"AND,((NETWORK,udp),(DST-PORT,443)),REJECT",
		"AND,((NETWORK,udp),(DST-PORT,3478)),REJECT",
		"AND,((NETWORK,udp),(DST-PORT,19302)),REJECT",
		"AND,((NETWORK,udp),(DST-PORT,5349)),REJECT",
		"DOMAIN-SUFFIX,stun.l.google.com,REJECT",
	} {
		if !strings.Contains(cy, want) {
			t.Errorf("clash block missing %q", want)
		}
	}
	// block-правила выше MATCH
	if strings.Index(cy, "REJECT") > strings.Index(cy, "MATCH,PROXY") {
		t.Error("block rules must precede MATCH")
	}
}

// TestClashUDPFlag — udp:false на TCP-транспортах (vision не несёт UDP),
// udp:true только на транспортах, реально несущих UDP (hysteria2).
func TestClashUDPFlag(t *testing.T) {
	cases := []struct {
		link string
		want string
	}{
		{testVlessReality, "udp: false"},
		{testVlessWS, "udp: false"},
		{testHy2, "udp: true"},
	}
	for _, c := range cases {
		cy := ClashYAML([]string{c.link})
		if !strings.Contains(cy, c.want) {
			t.Errorf("link %.30s…: want %q in clash yaml", c.link, c.want)
		}
	}
	// reality не должен нести udp:true
	if strings.Contains(ClashYAML([]string{testVlessReality}), "udp: true") {
		t.Error("reality+vision must not advertise udp:true")
	}
}

// TestSingboxDNS — dns.strategy ipv4_only, RU-домены → local, надёжные
// domain_suffix вместо мёртвых geosite без ресурсов, block-правило QUIC/STUN.
func TestSingboxDNS(t *testing.T) {
	sj := SingboxJSON([]string{testVlessReality})
	var cfg map[string]any
	if err := json.Unmarshal([]byte(sj), &cfg); err != nil {
		t.Fatalf("singbox JSON invalid: %v", err)
	}
	dns, _ := cfg["dns"].(map[string]any)
	if dns == nil {
		t.Fatal("dns section missing")
	}
	if dns["strategy"] != "ipv4_only" {
		t.Errorf("dns.strategy=%v want ipv4_only", dns["strategy"])
	}
	rules, _ := dns["rules"].([]any)
	if len(rules) == 0 {
		t.Fatal("dns.rules missing (RU → local)")
	}
	foundRU := false
	for _, r := range rules {
		rm, _ := r.(map[string]any)
		if rm["server"] == "local" {
			if suf, ok := rm["domain_suffix"].([]any); ok {
				for _, s := range suf {
					if s == ".ru" || s == "ru" {
						foundRU = true
					}
				}
			}
		}
	}
	if !foundRU {
		t.Error("dns.rules: RU domain_suffix → local missing")
	}
	// мёртвые geoip/geosite без ресурсов не используем
	if strings.Contains(sj, `"geoip": "ru"`) || strings.Contains(sj, `"geosite": "ru"`) {
		t.Error("geoip/geosite rules without declared resources are dead in sing-box 1.12+")
	}
	// RU-direct через domain_suffix в route.rules
	route, _ := cfg["route"].(map[string]any)
	rrules, _ := route["rules"].([]any)
	foundRUDirect := false
	foundBlockQUIC := false
	foundBlockSTUN := false
	foundDNSHijack := false
	for _, r := range rrules {
		rm, _ := r.(map[string]any)
		if rm["outbound"] == "direct" {
			if suf, ok := rm["domain_suffix"].([]any); ok {
				for _, s := range suf {
					if s == ".ru" || s == "ru" {
						foundRUDirect = true
					}
				}
			}
		}
		if rm["outbound"] == "block" || rm["action"] == "reject" {
			if rm["network"] == "udp" {
				switch p := rm["port"].(type) {
				case float64:
					if p == 443 {
						foundBlockQUIC = true
					}
				case []any:
					for _, pp := range p {
						if pp == float64(443) {
							foundBlockQUIC = true
						}
						if pp == float64(3478) || pp == float64(19302) {
							foundBlockSTUN = true
						}
					}
				}
			}
			if suf, ok := rm["domain_suffix"].([]any); ok {
				for _, s := range suf {
					if strings.Contains(s.(string), "stun") {
						foundBlockSTUN = true
					}
				}
			}
		}
		if rm["protocol"] == "dns" && (rm["action"] == "hijack-dns" || rm["outbound"] == "dns-out") {
			foundDNSHijack = true
		}
	}
	if !foundRUDirect {
		t.Error("route.rules: RU domain_suffix → direct missing")
	}
	if !foundBlockQUIC {
		t.Error("route.rules: block QUIC (udp/443) missing")
	}
	if !foundBlockSTUN {
		t.Error("route.rules: block STUN missing")
	}
	if !foundDNSHijack {
		t.Error("route.rules: dns hijack missing")
	}
	// block outbound объявлен
	obs, _ := cfg["outbounds"].([]any)
	hasBlock := false
	for _, o := range obs {
		om, _ := o.(map[string]any)
		if om["type"] == "block" {
			hasBlock = true
		}
	}
	if !hasBlock {
		t.Error("block outbound missing")
	}
}

// TestXrayJSONBlockQUICSTUN — xray-json: block udp/443 + STUN порты/домены,
// blackhole outbound всегда (дефолтные block-правила есть всегда).
func TestXrayJSONBlockQUICSTUN(t *testing.T) {
	for name, gen := range map[string]func([]string) string{
		"routing":  XrayJSON,
		"profiles": func(l []string) string { return XrayJSONProfiles(l, nil) },
	} {
		xj := gen([]string{testVlessReality})
		var cfg map[string]any
		if err := json.Unmarshal([]byte(xj), &cfg); err != nil {
			t.Fatalf("%s: JSON invalid: %v", name, err)
		}
		routing, _ := cfg["routing"].(map[string]any)
		rules, _ := routing["rules"].([]any)
		foundQUIC, foundSTUNPort, foundSTUNDomain := false, false, false
		for _, r := range rules {
			rm, _ := r.(map[string]any)
			if rm["outboundTag"] != "block" {
				continue
			}
			if rm["network"] == "udp" {
				port, _ := rm["port"].(string)
				if port == "443" {
					foundQUIC = true
				}
				if strings.Contains(port, "3478") && strings.Contains(port, "19302") && strings.Contains(port, "5349") {
					foundSTUNPort = true
				}
			}
			if doms, ok := rm["domain"].([]any); ok {
				for _, d := range doms {
					if strings.Contains(d.(string), "stun.") {
						foundSTUNDomain = true
					}
				}
			}
		}
		if !foundQUIC {
			t.Errorf("%s: block udp/443 missing", name)
		}
		if !foundSTUNPort {
			t.Errorf("%s: block STUN ports missing", name)
		}
		if !foundSTUNDomain {
			t.Errorf("%s: block stun.* domains missing", name)
		}
		obs, _ := cfg["outbounds"].([]any)
		hasBlackhole := false
		for _, o := range obs {
			om, _ := o.(map[string]any)
			if om["protocol"] == "blackhole" && om["tag"] == "block" {
				hasBlackhole = true
			}
		}
		if !hasBlackhole {
			t.Errorf("%s: block blackhole outbound missing", name)
		}
	}
}

// TestSingboxHy2SNI — hy2 c пустым sni: sing-box/clash/xray генераторы не должны
// отдавать пустой server_name (ParseLink fallback на address — аудит #7).
func TestHy2EmptySNIFallback(t *testing.T) {
	link := "hysteria2://authpass@vpn.example.com:8443?obfs=salamander&obfs-password=obfspass#Hy2"
	p := ParseLink(link)
	if p == nil {
		t.Fatal("parse nil")
	}
	if p.SNI != "vpn.example.com" {
		t.Errorf("ParseLink hy2 empty sni: got %q want address fallback", p.SNI)
	}
	sj := SingboxJSON([]string{link})
	if strings.Contains(sj, `"server_name": ""`) {
		t.Error("singbox hy2 empty server_name")
	}
}
