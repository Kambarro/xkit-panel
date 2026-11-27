package balancer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	router "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"

	"github.com/kambarro/xkit-panel/internal/routing"
	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/xray"
)

// writeTestBlockedFiles — xkit-blocked.dat + geosite-ru-only.dat (geodata-схема) в asset-dir.
func writeTestBlockedFiles(t *testing.T, dir string) {
	t.Helper()
	ip := &geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "XKIT-BLOCKED", Cidr: []*geodata.CIDR{{Ip: []byte{9, 9, 9, 0}, Prefix: 24}}},
	}}
	site := &geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{Code: "RU-BLOCKED", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "youtube.com"}}},
		{Code: "TELEGRAM", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "t.me"}}},
	}}
	for name, msg := range map[string]proto.Message{
		"xkit-blocked.dat": ip, "xkit-blocked-2.dat": ip, "geosite-ru-only.dat": site,
	} {
		b, _ := proto.Marshal(msg)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

// antifilterStateForTest — минимальное состояние «dat готов» для тестов.
func antifilterStateForTest(datFile string, count int) store.AntifilterState {
	return store.AntifilterState{Source: "live", PrefixCount: count, DatFile: datFile,
		LastFetch: 1700000000, UpdatedAt: 1700000000}
}

// writeAltBlockedFile — альтернативный набор (11.11.11.0/24) для hot-reload теста.
func writeAltBlockedFile(t *testing.T, dir, name string) {
	t.Helper()
	ip := &geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "XKIT-BLOCKED", Cidr: []*geodata.CIDR{{Ip: []byte{11, 11, 11, 0}, Prefix: 24}}},
	}}
	b, _ := proto.Marshal(ip)
	if err := os.WriteFile(filepath.Join(dir, name), b, 0644); err != nil {
		t.Fatal(err)
	}
}

// antifilter_rules_test — порядок правил мастера (решение владельца, sticky-переделка):
// api → always-direct → geoip:ru/geosite RU direct (РФ-исключение) → per-user
// afpd/afpi (blocked → НОДА НАЗНАЧЕНИЯ клиента) → apd/api (always-proxy → нода) →
// af-private direct → catch-all direct. Общего random-балансира XKIT_AF НЕТ.
// Все ВЫШЕ catch-all (урок CRITICAL #1). domainStrategy IPIfNonMatch.

func afTestConfig(t *testing.T, rules string) (string, func()) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(p, []byte(`{"routing":{"domainStrategy":"AsIs","rules":[`+rules+`]}}`), 0644)
	old := masterConfigPath
	masterConfigPath = p
	return p, func() { masterConfigPath = old }
}

const baseRules = `{"type":"field","inboundTag":["api-in"],"outboundTag":"api","ruleTag":"api"},
	{"type":"field","port":"0-65535","outboundTag":"direct"}`

func ruleTags(t *testing.T, path string) []string {
	t.Helper()
	data, _ := os.ReadFile(path)
	var cfg map[string]any
	json.Unmarshal(data, &cfg)
	rt := cfg["routing"].(map[string]any)
	var tags []string
	for _, r := range rt["rules"].([]any) {
		rm := r.(map[string]any)
		tag, _ := rm["ruleTag"].(string)
		tags = append(tags, tag)
	}
	return tags
}

// afUserJSON — тестовый per-user набор как строит syncAllRules (blocked→нода).
func afUserJSON(email, nodeID, datFile string, ar routing.AlwaysRules) []any {
	pd, pi := ar.ProxyTokens()
	var out []any
	out = append(out,
		ruleToJSON("afpd:"+email, email, nodeID, []string{"ext:geosite-ru-only.dat:ru-blocked"}, nil),
		ruleToJSON("afpi:"+email, email, nodeID, nil, []string{"ext:" + datFile + ":xkit-blocked"}),
	)
	if len(pd) > 0 {
		out = append(out, ruleToJSON("apd:"+email, email, nodeID, pd, nil))
	}
	if len(pi) > 0 {
		out = append(out, ruleToJSON("api:"+email, email, nodeID, nil, pi))
	}
	return out
}

func TestEnsureAntifilterRuleOrder(t *testing.T) {
	dir := writeTestGeoFiles(t) // always-категории geosite:telegram резолвятся парсером
	writeTestBlockedFiles(t, dir)
	path, restore := afTestConfig(t, baseRules)
	defer restore()
	c := &Controller{}
	ar := routing.AlwaysRules{
		ProxyCategories: []string{"geosite:telegram", "geoip:private"},
		ProxyDomains:    []string{"custom.io"},
		DirectCategories: []string{"geoip:private"},
		DirectDomains:   []string{"bank.ru"},
	}
	user := afUserJSON("x@test.ru", "node-nl-1", "xkit-blocked.dat", ar)
	c.applyRoutingRules("antifilter", true, "xkit-blocked.dat", ar, []string{"node-nl-1"}, user)
	tags := ruleTags(t, path)
	want := []string{"api", "always-direct-ip", "always-direct-domain",
		"ru-ip", "ru-domain",
		"afpd:x@test.ru", "afpi:x@test.ru", "apd:x@test.ru", "api:x@test.ru",
		"af-private", ""}
	if strings.Join(tags, ",") != strings.Join(want, ",") {
		t.Fatalf("order:\n got %v\nwant %v", tags, want)
	}
	// РЕГРЕССИЯ sticky-переделки: blocked/always-proxy адресуют PER-USER ноду
	// назначения (outboundTag=node-*), общего XKIT_AF/balancerTag НЕТ.
	data := mustRead(t, path)
	var cfg map[string]any
	json.Unmarshal([]byte(data), &cfg)
	rt := cfg["routing"].(map[string]any)
	for _, rl := range rt["rules"].([]any) {
		rm := rl.(map[string]any)
		tag, _ := rm["ruleTag"].(string)
		if _, bad := rm["balancerTag"]; bad {
			t.Errorf("%s: balancerTag — общий балансир удалён (скачки per-connection)", tag)
		}
		if strings.HasPrefix(tag, "afpd:") || strings.HasPrefix(tag, "afpi:") ||
			strings.HasPrefix(tag, "apd:") || strings.HasPrefix(tag, "api:") {
			if rm["outboundTag"] != "node-nl-1" {
				t.Errorf("%s: outboundTag=%v, want нода назначения", tag, rm["outboundTag"])
			}
			u, _ := rm["user"].([]any)
			if len(u) != 1 || u[0] != "x@test.ru" {
				t.Errorf("%s: user=%v — правило обязано быть per-user", tag, rm["user"])
			}
		}
	}
	if strings.Contains(data, afBalancerTag) {
		t.Errorf("легаси %s остался в конфиге", afBalancerTag)
	}
	// снапшот для ReplaceRules парсится, per-user правила — Tag (не BalancingTag)
	snap, err := c.routingSnapshot()
	if err != nil {
		t.Fatalf("routingSnapshot: %v", err)
	}
	if len(snap.BalancingRule) != 0 {
		t.Fatalf("балансировщиков быть не должно: %+v", snap.BalancingRule)
	}
	for _, r := range snap.Rule {
		if r.RuleTag == "afpi:x@test.ru" {
			if r.GetTag() != "node-nl-1" || r.GetBalancingTag() != "" {
				t.Errorf("afpi: Tag=%q BalancingTag=%q, want per-user outbound", r.GetTag(), r.GetBalancingTag())
			}
		}
	}
	// catch-all последний, IPIfNonMatch
	if !strings.Contains(data, `"IPIfNonMatch"`) {
		t.Error("domainStrategy must be IPIfNonMatch")
	}
	// повторное применение — идемпотентно, без дублей (A/B-файл сменился)
	user2 := afUserJSON("x@test.ru", "node-nl-1", "xkit-blocked-2.dat", ar)
	c.applyRoutingRules("antifilter", true, "xkit-blocked-2.dat", ar, []string{"node-de-1", "node-nl-1"}, user2)
	tags2 := ruleTags(t, path)
	if len(tags2) != len(want) {
		t.Fatalf("duplicates after re-apply: %v", tags2)
	}
	// afpi ссылается на НОВЫЙ активный файл (A/B hot-reload)
	if !strings.Contains(mustRead(t, path), "ext:xkit-blocked-2.dat:xkit-blocked") {
		t.Error("afpi must reference active dat file")
	}
}

// TestStripLegacyAFBalancer — легаси-балансир XKIT_AF из прежних версий убирается
// при пересборке правил (миграция без ручных действий).
func TestStripLegacyAFBalancer(t *testing.T) {
	writeTestGeoFiles(t)
	writeTestBlockedFiles(t, os.Getenv("xray.location.asset"))
	path, restore := afTestConfig(t, baseRules)
	defer restore()
	// вручную добавляем легаси-балансир как в конфиге версии 13f7965
	data := mustRead(t, path)
	var cfg map[string]any
	json.Unmarshal([]byte(data), &cfg)
	rt := cfg["routing"].(map[string]any)
	rt["balancers"] = []any{map[string]any{"tag": afBalancerTag, "selector": []string{"node-nl-1"}, "strategy": map[string]any{"type": "random"}}}
	out, _ := json.MarshalIndent(cfg, "", " ")
	os.WriteFile(path, out, 0644)
	c := &Controller{}
	c.applyRoutingRules("antifilter", true, "xkit-blocked.dat", routing.AlwaysRules{}, nil, nil)
	if strings.Contains(mustRead(t, path), afBalancerTag) {
		t.Fatal("легаси XKIT_AF не убран")
	}
}

func mustRead(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEnsureAntifilterPerUserPosition(t *testing.T) {
	// rebuildRules со снапшотом antifilter: per-user вставляется ПЕРЕД catch-all
	// (после af-private), managed-правила не теряются.
	writeTestGeoFiles(t)
	writeTestBlockedFiles(t, os.Getenv("xray.location.asset"))
	_, restore := afTestConfig(t, baseRules)
	defer restore()
	c := &Controller{}
	c.applyRoutingRules("antifilter", true, "xkit-blocked.dat", routing.AlwaysRules{}, nil, nil)
	snap, err := c.routingSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	perUser := []*router.RoutingRule{{
		RuleTag: "afpd:x@test.ru", UserEmail: []string{"x@test.ru"},
		TargetTag: &router.RoutingRule_Tag{Tag: "node-nl-1"},
	}}
	full := rebuildRules(snap.Rule, perUser)
	var tags []string
	for _, r := range full {
		tags = append(tags, r.RuleTag)
	}
	want := []string{"api", "ru-ip", "ru-domain", "af-private", "afpd:x@test.ru", ""}
	if strings.Join(tags, ",") != strings.Join(want, ",") {
		t.Fatalf("per-user position:\n got %v\nwant %v", tags, want)
	}
}

func TestEnsureRUDirectModeCompat(t *testing.T) {
	// ru-direct с нодами — прежнее поведение: ru-ip/ru-domain после api, IPIfNonMatch
	path, restore := afTestConfig(t, baseRules)
	defer restore()
	c := &Controller{}
	c.applyRoutingRules("ru-direct", true, "", routing.AlwaysRules{}, nil, nil)
	tags := ruleTags(t, path)
	want := []string{"api", "ru-ip", "ru-domain", ""}
	if strings.Join(tags, ",") != strings.Join(want, ",") {
		t.Fatalf("ru-direct order: %v want %v", tags, want)
	}
	// solo — RU/af/always правила убраны, AsIs
	c.applyRoutingRules("solo", false, "", routing.AlwaysRules{}, nil, nil)
	tags2 := ruleTags(t, path)
	if strings.Join(tags2, ",") != "api," {
		t.Fatalf("solo must strip managed rules: %v", tags2)
	}
	if !strings.Contains(mustRead(t, path), `"AsIs"`) {
		t.Error("solo domainStrategy must be AsIs")
	}
}

func TestEnsureAlwaysRulesInRUDirect(t *testing.T) {
	// always-direct работает и в ru-direct (поверх дефолта, до RU-правил).
	// always-proxy per-user строит syncAllRules (базовое c покрывает весь не-RU).
	path, restore := afTestConfig(t, baseRules)
	defer restore()
	c := &Controller{}
	ar := routing.AlwaysRules{ProxyCategories: []string{"geosite:netflix"}, DirectDomains: []string{"mybank.ru"}}
	c.applyRoutingRules("ru-direct", true, "", ar, nil, nil)
	tags := ruleTags(t, path)
	want := []string{"api", "always-direct-domain", "ru-ip", "ru-domain", ""}
	if strings.Join(tags, ",") != strings.Join(want, ",") {
		t.Fatalf("always in ru-direct: %v want %v", tags, want)
	}
}

// TestAntifilterSnapshotParsesNewSchema — сгенерированный набор правил обязан
// парситься штатным парсером новой geodata-схемы (инвариант wire-format 26.11.x).
func TestAntifilterSnapshotParsesNewSchema(t *testing.T) {
	dir := writeTestGeoFiles(t)
	// + xkit-blocked.dat и geosite-ru-only.dat в asset-каталог
	writeTestBlockedFiles(t, dir)
	path, restore := afTestConfig(t, baseRules)
	defer restore()
	c := &Controller{}
	ar := routing.AlwaysRules{ProxyCategories: []string{"geosite:telegram", "geoip:telegram"}}
	user := afUserJSON("x@test.ru", "node-nl-1", "xkit-blocked.dat", ar)
	c.applyRoutingRules("antifilter", true, "xkit-blocked.dat", ar, nil, user)
	data := mustRead(t, path)
	var cfg map[string]any
	json.Unmarshal([]byte(data), &cfg)
	rj, _ := json.Marshal(cfg["routing"])
	parsed, err := xray.ParseRoutingConfig(string(rj))
	if err != nil {
		t.Fatalf("antifilter rules not parseable by new-schema parser: %v", err)
	}
	// afpi — geoip-правило нового типа (не legacy), per-user
	for _, r := range parsed.Rule {
		if r.RuleTag == "afpi:x@test.ru" {
			if len(r.Ip) == 0 || r.Ip[0].GetGeoip() == nil {
				t.Fatalf("afpi not geodata.IPRule_Geoip: %+v", r.Ip)
			}
			if r.Ip[0].GetGeoip().File != "xkit-blocked.dat" {
				t.Errorf("afpi file: %q", r.Ip[0].GetGeoip().File)
			}
			if len(r.UserEmail) != 1 {
				t.Errorf("afpi без user — не per-user: %+v", r)
			}
		}
		if r.RuleTag == "afpd:x@test.ru" && (len(r.Domain) == 0 || r.Domain[0].GetGeosite() == nil) {
			t.Fatalf("afpd not geodata.DomainRule_Geosite: %+v", r.Domain)
		}
	}
}