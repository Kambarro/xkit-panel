package balancer

import (
	"os"
	"path/filepath"
	"testing"

	router "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"

	"github.com/kambarro/xkit-panel/internal/xray"
)

// TestInsertPerUserBeforeCatchAll — УРОК аудита CRITICAL #1: Xray матчит ПЕРВОЕ
// совпадение; AppendRules кладёт per-user ПОСЛЕ catch-all → правило мертво, клиент
// выходит direct с РФ-мастера мимо ноды. Пересборка обязана ставить per-user ПЕРЕД
// catch-all, сохраняя api/RU-direct/чужие правила и балансировщики.
func TestInsertPerUserBeforeCatchAll(t *testing.T) {
	snapshotJSON := `{"domainStrategy":"IPIfNonMatch","rules":[
		{"type":"field","inboundTag":["api-in"],"outboundTag":"api","ruleTag":"api"},
		{"type":"field","ip":["192.168.0.0/16"],"outboundTag":"direct","ruleTag":"ru-ip"},
		{"type":"field","user":["stale@test.ru"],"outboundTag":"node-old","ruleTag":"c:stale@test.ru:de"},
		{"type":"field","user":["stale@test.ru"],"vlessRoute":"1","outboundTag":"node-old","ruleTag":"cs:stale@test.ru:DE"},
		{"type":"field","inboundTag":["survey-x"],"outboundTag":"node-nl-1","ruleTag":"survey:survey-x"},
		{"type":"field","port":"0-65535","outboundTag":"direct"}
	]}`
	parsed, err := xray.ParseRoutingConfig(snapshotJSON)
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	perUser := []*router.RoutingRule{
		{RuleTag: "c:client@example.com:nl", UserEmail: []string{"client@example.com"},
			TargetTag: &router.RoutingRule_Tag{Tag: "node-nl-1"}},
	}
	rules := rebuildRules(parsed.Rule, perUser)

	// порядок ruleTag: api → ru-ip → survey → c:client → catch-all (без tag)
	wantTags := []string{"api", "ru-ip", "survey:survey-x", "c:client@example.com:nl", ""}
	if len(rules) != len(wantTags) {
		t.Fatalf("rules=%d want %d: %+v", len(rules), len(wantTags), rules)
	}
	catchAllIdx := -1
	for i, r := range rules {
		if r.RuleTag != wantTags[i] {
			t.Errorf("rule[%d].RuleTag=%q want %q", i, r.RuleTag, wantTags[i])
		}
		if isCatchAllRule(r) {
			catchAllIdx = i
		}
	}
	if catchAllIdx != len(rules)-1 {
		t.Fatalf("catch-all должен остаться последним, idx=%d", catchAllIdx)
	}
	for i, r := range rules {
		if r.RuleTag == "c:client@example.com:nl" {
			if i >= catchAllIdx {
				t.Errorf("per-user %s ПОСЛЕ catch-all (мертво)", r.RuleTag)
			}
		}
	}
	// старые per-user (stale) удалены, survey/api/ru сохранены
	for _, r := range rules {
		if r.RuleTag == "c:stale@test.ru:de" || r.RuleTag == "cs:stale@test.ru:DE" {
			t.Errorf("старое per-user правило не удалено: %s", r.RuleTag)
		}
	}
}

// TestRebuildRulesNoCatchAll — снапшот без catch-all: per-user добавляются в конец
// (порядок остальных сохраняется), паники/потерь нет.
func TestRebuildRulesNoCatchAll(t *testing.T) {
	snapshot := []*router.RoutingRule{
		{RuleTag: "api", InboundTag: []string{"api-in"}, TargetTag: &router.RoutingRule_Tag{Tag: "api"}},
	}
	perUser := []*router.RoutingRule{
		{RuleTag: "c:a@b.c:de", UserEmail: []string{"a@b.c"}, TargetTag: &router.RoutingRule_Tag{Tag: "node-de-1"}},
	}
	rules := rebuildRules(snapshot, perUser)
	if len(rules) != 2 || rules[0].RuleTag != "api" || rules[1].RuleTag != "c:a@b.c:de" {
		t.Fatalf("bad rebuild without catch-all: %+v", rules)
	}
}

// TestIsCatchAllRule — определение catch-all (порт 0-65535 без матчеров).
func TestIsCatchAllRule(t *testing.T) {
	catchAll := &router.RoutingRule{PortList: &net.PortList{Range: []*net.PortRange{{From: 0, To: 65535}}}}
	if !isCatchAllRule(catchAll) {
		t.Error("port 0-65535 без матчеров = catch-all")
	}
	withUser := &router.RoutingRule{UserEmail: []string{"a@b.c"}, PortList: &net.PortList{Range: []*net.PortRange{{From: 0, To: 65535}}}}
	if isCatchAllRule(withUser) {
		t.Error("per-user не catch-all")
	}
	if isCatchAllRule(nil) || isCatchAllRule(&router.RoutingRule{}) {
		t.Error("nil/пустое правило не catch-all")
	}
}

// TestSyncAllRulesOrderE2E — syncAllRules c живым in-process Xray gRPC:
// per-user правило client матчится РАНЬШЕ catch-all (TestRoute → node-nl-1).
func TestSyncAllRulesOrderE2E(t *testing.T) {
	writeTestGeoFiles(t) // ensure-механика инжектит geoip:ru — снапшоту нужны geo-файлы
	s := testStore(t)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatalf("upsert client: %v", err)
	}
	if err := s.SetAssignment(storeAssignment("client@example.com", "NL", "node-nl-1")); err != nil {
		t.Fatalf("set assignment: %v", err)
	}
	routingJSON := `{
		"domainStrategy":"IPIfNonMatch",
		"rules":[
			{"type":"field","inboundTag":["api-in"],"outboundTag":"api","ruleTag":"api"},
			{"type":"field","ip":["10.0.0.0/8"],"outboundTag":"direct","ruleTag":"ru-ip"},
			{"type":"field","domain":["domain:example.ru"],"outboundTag":"direct","ruleTag":"ru-domain"},
			{"type":"field","port":"0-65535","outboundTag":"direct"}
		]}`
	xc := startXrayAPI(t, routingJSON)
	// снапшот syncAllRules читает config.json мастера — подменяем путь на временный
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(cfgPath, []byte(`{"routing":`+routingJSON+`}`), 0644)
	oldPath := masterConfigPath
	masterConfigPath = cfgPath
	t.Cleanup(func() { masterConfigPath = oldPath })
	c := NewController(s, xc)
	c.SyncRulesNow(t.Context())

	resp, err := xc.TestRoute(t.Context(), "vless-reality", "client@example.com")
	if err != nil {
		t.Fatalf("TestRoute: %v", err)
	}
	if got := resp.GetOutboundTag(); got != "node-nl-1" {
		t.Fatalf("client routed to %q, want node-nl-1 (catch-all побеждает per-user?)", got)
	}
	// повторный sync не плодит дубли и не ломает порядок
	c.SyncRulesNow(t.Context())
	rules, err := xc.ListRules(t.Context())
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	count := 0
	for _, r := range rules {
		if r.RuleTag == "c:client@example.com:NL" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("дубли per-user правила: %d", count)
	}
	resp2, err := xc.TestRoute(t.Context(), "vless-reality", "client@example.com")
	if err != nil || resp2.GetOutboundTag() != "node-nl-1" {
		t.Fatalf("после повторного sync: %v %v", resp2, err)
	}
}
