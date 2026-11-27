package routing

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// AlwaysRules — правила владельца «Всегда через ноду» / «Всегда напрямую».
// Приоритет (решение владельца): always-direct ВЫШЕ always-proxy.
// Пересечение доменов — не ошибка сохранения, а видимый конфликт + direct побеждает.

func TestAlwaysRulesValidation(t *testing.T) {
	// валидные категории (проверены по Loyalsoldier geosite.dat/geoip.dat)
	ar := AlwaysRules{
		ProxyCategories: []string{"geosite:telegram", "geosite:category-ai-!cn"},
		ProxyDomains:    []string{"Example.COM", "my-service.io"},
		DirectCategories: []string{"geosite:category-ru"},
		DirectDomains:   []string{"bank.ru", "банк.рф"},
	}
	norm, err := ValidateAlwaysRules(ar)
	if err != nil {
		t.Fatalf("valid rules rejected: %v", err)
	}
	if norm.ProxyDomains[0] != "example.com" {
		t.Errorf("domain not lowercased: %q", norm.ProxyDomains[0])
	}
	// кириллица → IDNA (Xray матчит punycode)
	found := false
	for _, d := range norm.DirectDomains {
		if d == "xn--80ab2al.xn--p1ai" {
			found = true
		}
	}
	if !found {
		t.Errorf("IDNA not applied: %v", norm.DirectDomains)
	}
	// мусор отклоняется
	bad := []AlwaysRules{
		{ProxyCategories: []string{"geosite:no-such-category"}},
		{ProxyCategories: []string{"telegram"}}, // без префикса geosite:/geoip: — не токен правила
		{ProxyDomains: []string{"bad domain.com"}},
		{ProxyDomains: []string{"http://x.com"}},
		{ProxyDomains: []string{"-bad.com"}},
		{ProxyDomains: []string{"x..com"}},
		{DirectDomains: []string{"*.x.com"}}, // wildcard не поддерживаем — суффикс матчит поддомены
		{ProxyDomains: []string{"$(id)"}},
	}
	for i, b := range bad {
		if _, err := ValidateAlwaysRules(b); err == nil {
			t.Errorf("bad rules #%d accepted: %+v", i, b)
		}
	}
	// дедуп + пустые строки игнорируются
	n2, err := ValidateAlwaysRules(AlwaysRules{ProxyDomains: []string{"a.com", " a.com ", "", "b.com"}})
	if err != nil || len(n2.ProxyDomains) != 2 {
		t.Fatalf("dedupe failed: %+v err=%v", n2, err)
	}
}

func TestAlwaysRulesConflicts(t *testing.T) {
	ar := AlwaysRules{
		ProxyCategories:  []string{"geosite:telegram", "geosite:google"},
		DirectCategories: []string{"geosite:telegram"},
		ProxyDomains:     []string{"dup.com", "only-proxy.com"},
		DirectDomains:    []string{"dup.com"},
	}
	conf := AlwaysConflicts(ar)
	if len(conf.Categories) != 1 || conf.Categories[0] != "geosite:telegram" {
		t.Errorf("category conflict not detected: %+v", conf)
	}
	if len(conf.Domains) != 1 || conf.Domains[0] != "dup.com" {
		t.Errorf("domain conflict not detected: %+v", conf)
	}
	// конфликт НЕ запрещает сохранение — direct приоритетнее (документировано в UI)
	if _, err := ValidateAlwaysRules(ar); err != nil {
		t.Errorf("conflicts must not block save: %v", err)
	}
}

func TestAlwaysRuleTokens(t *testing.T) {
	ar := AlwaysRules{
		ProxyCategories: []string{"geosite:telegram", "geosite:google"},
		ProxyDomains:    []string{"custom.io"},
		DirectCategories: []string{"geoip:private"},
		DirectDomains:   []string{"bank.ru"},
	}
	dom, ip := ar.ProxyTokens()
	// несколько категорий в ОДНОМ токене (geosite:telegram,google — решение владельца)
	if len(dom) != 2 || dom[0] != "geosite:telegram,google" || dom[1] != "domain:custom.io" {
		t.Errorf("proxy domain tokens: %v", dom)
	}
	if len(ip) != 0 {
		t.Errorf("unexpected proxy ip tokens: %v", ip)
	}
	dom2, ip2 := ar.DirectTokens()
	if len(dom2) != 1 || dom2[0] != "domain:bank.ru" {
		t.Errorf("direct domain tokens: %v", dom2)
	}
	if len(ip2) != 1 || ip2[0] != "geoip:private" {
		t.Errorf("direct ip tokens: %v", ip2)
	}
	// смешанные geoip+geosite категории
	ar2 := AlwaysRules{ProxyCategories: []string{"geosite:telegram", "geoip:telegram", "geoip:cloudflare"}}
	d3, i3 := ar2.ProxyTokens()
	if len(d3) != 1 || d3[0] != "geosite:telegram" || len(i3) != 1 || i3[0] != "geoip:telegram,cloudflare" {
		t.Errorf("mixed tokens: %v %v", d3, i3)
	}
}

func TestAntifilterHappRoutingJSON(t *testing.T) {
	cfg := AntifilterHappRoutingJSON("XKIT", []string{"geosite:ru-blocked"}, []string{"geoip:ru"}, nil, nil, nil, nil)
	// инверсия: всё direct, заблокированное через ноду
	if cfg["GlobalProxy"] != "false" {
		t.Errorf("antifilter GlobalProxy must be false, got %v", cfg["GlobalProxy"])
	}
	if cfg["RouteOrder"] != "block-direct-proxy" {
		t.Errorf("antifilter RouteOrder: %v", cfg["RouteOrder"])
	}
	link := AntifilterHappDeeplink("XKIT", []string{"geosite:ru-blocked"}, nil, nil, nil, nil, nil)
	if !strings.HasPrefix(link, "happ://routing/onadd/") {
		t.Fatal("deeplink prefix")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, "happ://routing/onadd/"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["GlobalProxy"] != "false" {
		t.Errorf("deeplink GlobalProxy: %v", m["GlobalProxy"])
	}
}