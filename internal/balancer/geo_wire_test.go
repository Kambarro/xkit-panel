package balancer

// Регрессия живого деплоя ac37115 (Ops 2026-11-26): go.mod пиннил xray-core
// v1.260327.0 со СТАРОЙ routing-схемой (RoutingRule.Geoip []*GeoIP), а живое ядро
// 26.11.9 — новая geodata-схема (Ip []*geodata.IPRule / Domain []*geodata.DomainRule).
// ReplaceRules с любым geoip/domain-правилом падал «proto: cannot parse invalid
// wire-format data» → syncAllRules/survey/failover мертвы на живом. Здесь снапшот
// с geoip:RU/geosite:RU гоняется через in-process xray НОВОЙ схемы end-to-end.

import (
	"os"
	"path/filepath"
	"testing"

	router "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"

	"github.com/kambarro/xkit-panel/internal/xray"
)

// writeTestGeoFiles — минимальные geoip.dat/geosite.dat (protobuf-формат новой
// схемы geodata) в temp-каталог + env xray.location.asset на него.
func writeTestGeoFiles(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	geoIP := &geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "RU", Cidr: []*geodata.CIDR{{Ip: []byte{10, 77, 0, 0}, Prefix: 16}}},
		{Code: "PRIVATE", Cidr: []*geodata.CIDR{{Ip: []byte{127, 0, 0, 0}, Prefix: 8}}},
		{Code: "TELEGRAM", Cidr: []*geodata.CIDR{{Ip: []byte{149, 154, 160, 0}, Prefix: 20}}},
	}}
	geoSite := &geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{Code: "RU", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "example-ru.test"}}},
		{Code: "CATEGORY-RU", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "example-ru.test"}}},
		{Code: "TELEGRAM", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "t.me"}}},
	}}
	for name, msg := range map[string]proto.Message{"geoip.dat": geoIP, "geosite.dat": geoSite} {
		b, err := proto.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	t.Setenv("xray.location.asset", dir)
	return dir
}

// TestReplaceRulesGeoSnapshotE2E — CRITICAL живого деплоя: полный снапшот с
// geoip:RU/geosite:RU правилами проходит ReplaceRules против ядра новой схемы,
// per-user остаётся ПЕРЕД catch-all и матчится (TestRoute → node-nl-1).
func TestReplaceRulesGeoSnapshotE2E(t *testing.T) {
	writeTestGeoFiles(t)
	s := testStore(t)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatalf("upsert client: %v", err)
	}
	if err := s.SetAssignment(storeAssignment("client@example.com", "NL", "node-nl-1")); err != nil {
		t.Fatalf("set assignment: %v", err)
	}
	// снапшот как на живом мастере: api + RU-direct (geoip/geosite) + catch-all
	routingJSON := `{
		"domainStrategy":"IPIfNonMatch",
		"rules":[
			{"type":"field","inboundTag":["api-in"],"outboundTag":"api","ruleTag":"api"},
			{"type":"field","ip":["geoip:RU"],"outboundTag":"direct","ruleTag":"ru-ip"},
			{"type":"field","domain":["geosite:RU"],"outboundTag":"direct","ruleTag":"ru-domain"},
			{"type":"field","port":"0-65535","outboundTag":"direct"}
		]}`
	xc := startXrayAPI(t, routingJSON)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(cfgPath, []byte(`{"routing":`+routingJSON+`}`), 0644)
	oldPath := masterConfigPath
	masterConfigPath = cfgPath
	t.Cleanup(func() { masterConfigPath = oldPath })

	c := NewController(s, xc)
	c.SyncRulesNow(t.Context())

	// per-user матчится РАНЬШЕ catch-all — значит ReplaceRules с geo-снапшотом
	// реально применился (на старой библиотеке здесь был invalid wire-format).
	resp, err := xc.TestRoute(t.Context(), "vless-reality", "client@example.com")
	if err != nil {
		t.Fatalf("TestRoute: %v", err)
	}
	if got := resp.GetOutboundTag(); got != "node-nl-1" {
		t.Fatalf("client routed to %q want node-nl-1 (ReplaceRules с geo-снапшотом не применился?)", got)
	}
	// повторный sync (путь как в control loop) не падает и не плодит дубли
	c.SyncRulesNow(t.Context())
	rules, err := xc.ListRules(t.Context())
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	n := 0
	for _, r := range rules {
		if r.RuleTag == "c:client@example.com:NL" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("дубли per-user после повторного sync: %d", n)
	}
}

// TestParseRoutingGeoNewWireFormat — снапшот с geoip/domain обязан собираться в
// НОВУЮ схему: Ip []*geodata.IPRule / Domain []*geodata.DomainRule (не legacy
// GeoIP/Domain из router). Прямой ReplaceRules этими правилами проходит.
func TestParseRoutingGeoNewWireFormat(t *testing.T) {
	writeTestGeoFiles(t)
	parsed, err := xray.ParseRoutingConfig(`{"rules":[
		{"type":"field","ip":["geoip:RU","192.168.0.0/16"],"outboundTag":"direct","ruleTag":"ru-ip"},
		{"type":"field","domain":["geosite:RU","domain:example.ru"],"outboundTag":"direct","ruleTag":"ru-domain"},
		{"type":"field","port":"0-65535","outboundTag":"direct"}
	]}`)
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	if len(parsed.Rule[0].Ip) != 2 || parsed.Rule[0].Ip[0].GetGeoip() == nil {
		t.Fatalf("geoip:RU не стал geodata.IPRule_Geoip: %+v", parsed.Rule[0].Ip)
	}
	if parsed.Rule[0].Ip[1].GetCustom() == nil {
		t.Fatalf("CIDR не стал geodata.IPRule_Custom: %+v", parsed.Rule[0].Ip[1])
	}
	if len(parsed.Rule[1].Domain) != 2 || parsed.Rule[1].Domain[0].GetGeosite() == nil {
		t.Fatalf("geosite:RU не стал geodata.DomainRule_Geosite: %+v", parsed.Rule[1].Domain)
	}
	// catch-all не должен опознаваться как per-user/geo (isCatchAllRule)
	if !isCatchAllRule(parsed.Rule[2]) || isCatchAllRule(parsed.Rule[0]) {
		t.Fatal("isCatchAllRule: geo-правило/catch-all распознаны неверно")
	}
	// прямой ReplaceRules полного набора — ровно падавший на живом вызов
	xc := startXrayAPI(t, `{"rules":[{"type":"field","inboundTag":["api-in"],"outboundTag":"api"}]}`)
	perUser := []*router.RoutingRule{{
		RuleTag: "c:x@test.ru:nl", UserEmail: []string{"x@test.ru"},
		TargetTag: &router.RoutingRule_Tag{Tag: "node-nl-1"},
	}}
	full := rebuildRules(parsed.Rule, perUser)
	if err := xc.ReplaceRules(t.Context(), full, nil); err != nil {
		t.Fatalf("ReplaceRules geo-набор: %v (wire-format регрессия!)", err)
	}
	resp, err := xc.TestRoute(t.Context(), "any-in", "x@test.ru")
	if err != nil || resp.GetOutboundTag() != "node-nl-1" {
		t.Fatalf("TestRoute после ReplaceRules: %v %v", resp, err)
	}
}
