package balancer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCountryChangeE2E — упрощение (решение владельца): страна клиента = ТОЛЬКО
// clients.country, базовое per-user правило user:[email] → нода назначения.
// cs/vlessRoute-слой удалён: ЛЮБОЙ UUID клиента (базовый и легаси страновой —
// ProcessUUID обнулял байты 6-7) маршрутизируется базовым правилом.
// Клиент NL→US→NL: после каждого шага маршрут = нода ВЫБРАННОЙ страны,
// ровно одно per-user правило, cs-правил нет.
func TestCountryChangeE2E(t *testing.T) {
	writeTestGeoFiles(t) // ensure-механика инжектит geoip:ru — снапшоту нужны geo-файлы
	s := testStore(t)
	for _, cc := range []struct {
		country string
		code    uint32
	}{{"NL", 1}, {"US", 3}, {"DE", 4}} {
		if _, err := s.DB().Exec(`INSERT OR REPLACE INTO country_codes(country,code) VALUES(?,?)`, cc.country, cc.code); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertClient(testClient("client@example.com", "NL", 1)); err != nil {
		t.Fatal(err)
	}
	// несколько assignment на email (base '' первой + NL) — репро дедуп-бага QA BUG-1b
	if err := s.SetAssignment(storeAssignment("client@example.com", "", "node-nl-1")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAssignment(storeAssignment("client@example.com", "NL", "node-nl-1")); err != nil {
		t.Fatal(err)
	}

	routingJSON := `{"domainStrategy":"AsIs","rules":[
		{"type":"field","inboundTag":["api-in"],"outboundTag":"api","ruleTag":"api"},
		{"type":"field","port":"0-65535","outboundTag":"direct"}]}`
	xc := startXrayAPI(t, routingJSON)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(cfgPath, []byte(`{"routing":`+routingJSON+`}`), 0644)
	oldPath := masterConfigPath
	masterConfigPath = cfgPath
	t.Cleanup(func() { masterConfigPath = oldPath })
	c := NewController(s, xc)

	check := func(step, want string) {
		t.Helper()
		resp, err := xc.TestRoute(t.Context(), "vless-reality", "client@example.com")
		if err != nil {
			t.Fatalf("%s TestRoute: %v", step, err)
		}
		if got := resp.GetOutboundTag(); got != want {
			t.Errorf("%s: базовый uuid → %q, want %q", step, got, want)
		}
	}

	// старт: страна NL — базовое правило на NL-ноде
	c.SyncRulesNow(t.Context())
	check("start NL", "node-nl-1")

	// country_change → US (как PublicClientCountry): clients.country=US + PushAssignment
	if _, err := s.DB().Exec(`UPDATE clients SET country='US', country_code=3 WHERE email='client@example.com'`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PushAssignment(t.Context(), "client@example.com", "US"); err != nil {
		t.Fatalf("PushAssignment US: %v", err)
	}
	check("after →US", "node-us-1")

	// обратно → NL: базовое правило НЕ должно залипнуть на US (QA BUG-1b)
	if _, err := s.DB().Exec(`UPDATE clients SET country='NL', country_code=1 WHERE email='client@example.com'`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PushAssignment(t.Context(), "client@example.com", "NL"); err != nil {
		t.Fatalf("PushAssignment NL: %v", err)
	}
	check("after →NL", "node-nl-1")

	rules, err := xc.ListRules(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// cs-правил НЕТ (слой удалён), базовое per-user ровно одно
	baseCount := 0
	for _, r := range rules {
		if strings.HasPrefix(r.RuleTag, "cs:") || strings.HasPrefix(r.RuleTag, "cspd:") || strings.HasPrefix(r.RuleTag, "cspi:") {
			t.Fatalf("легаси cs-правило в ядре: %s", r.RuleTag)
		}
		if strings.HasPrefix(r.RuleTag, "c:client@example.com:") {
			baseCount++
		}
	}
	if baseCount != 1 {
		t.Fatalf("базовых per-user правил %d, want 1 (дедуп)", baseCount)
	}
}
