package balancer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	routercmd "github.com/xtls/xray-core/app/router/command"
	xnet "github.com/xtls/xray-core/common/net"

	"github.com/kambarro/xkit-panel/internal/routing"
)

// TestAntifilterModeE2E — режим antifilter на живом in-process Xray (новая
// geodata-схема): blocked IP/домен → нода, РФ → direct, незаблокированное → direct
// (catch-all), always-direct приоритетнее always-proxy. Все правила ВЫШЕ catch-all.
func TestAntifilterModeE2E(t *testing.T) {
	dir := writeTestGeoFiles(t)
	writeTestBlockedFiles(t, dir)
	s := testStore(t)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAssignment(storeAssignment("client@example.com", "NL", "node-nl-1")); err != nil {
		t.Fatal(err)
	}
	// режим antifilter + состояние (dat готов)
	if err := s.SetRoutingMode("antifilter"); err != nil {
		t.Fatal(err)
	}
	s.SetAntifilterState(antifilterStateForTest("xkit-blocked.dat", 1))
	// always: t.me через ноду, но example-blocked.test всегда напрямую (приоритет direct)
	s.SetAlwaysRules(routing.AlwaysRules{
		ProxyDomains:  []string{"t.me"},
		DirectDomains: []string{"youtube.com"}, // youtube в RU-BLOCKED, но always-direct выше
	})

	routingJSON := `{"domainStrategy":"AsIs","rules":[
		{"type":"field","inboundTag":["api-in"],"outboundTag":"api","ruleTag":"api"},
		{"type":"field","port":"0-65535","outboundTag":"direct"}
	]}`
	// ядро стартует с базовым набором; af-правила придут через ReplaceRules
	xc := startXrayAPI(t, routingJSON)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(cfgPath, []byte(`{"routing":`+routingJSON+`}`), 0644)
	oldPath := masterConfigPath
	masterConfigPath = cfgPath
	t.Cleanup(func() { masterConfigPath = oldPath })

	c := NewController(s, xc)
	c.SyncRulesNow(t.Context())

	// blocked IP (9.9.9.0/24 в xkit-blocked.dat) → нода через балансир XKIT_AF
	resp, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
		InboundTag: "vless-reality", User: "client@example.com", TargetPort: 443,
		TargetIPs: [][]byte{[]byte{9,9,9,9}},
	}})
	if err != nil {
		t.Fatalf("TestRoute blocked ip: %v", err)
	}
	if got := resp.GetOutboundTag(); got != "XKIT_AF" && got != "node-nl-1" && got != "node-de-1" && got != "node-us-1" {
		t.Fatalf("blocked IP routed to %q, want node/balancer (af-ip не сработал выше catch-all?)", got)
	}
	// незаблокированный IP → direct (инверсия: catch-all direct)
	resp2, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
		InboundTag: "vless-reality", User: "client@example.com", TargetPort: 443,
		TargetIPs: [][]byte{[]byte{93,184,216,34}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp2.GetOutboundTag(); got != "direct" {
		t.Fatalf("unblocked IP routed to %q, want direct (antifilter inversion)", got)
	}
	// RU IP (10.77.0.0/16 в geoip:ru) → direct даже если per-user назначен на ноду
	resp3, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
		InboundTag: "vless-reality", User: "client@example.com", TargetPort: 443,
		TargetIPs: [][]byte{[]byte{10,77,1,1}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp3.GetOutboundTag(); got != "direct" {
		t.Fatalf("RU IP routed to %q, want direct (РФ-исключение)", got)
	}
	// blocked ДОМЕН (youtube.com в geosite RU-BLOCKED), но always-direct выше → direct
	resp4, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
		InboundTag: "vless-reality", User: "client@example.com", TargetPort: 443,
		TargetDomain: "youtube.com",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp4.GetOutboundTag(); got != "direct" {
		t.Fatalf("always-direct domain routed to %q, want direct (приоритет always-direct)", got)
	}
	// always-proxy домен t.me → нода
	resp5, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
		InboundTag: "vless-reality", User: "client@example.com", TargetPort: 443,
		TargetDomain: "t.me",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp5.GetOutboundTag(); got == "direct" || got == "api" {
		t.Fatalf("always-proxy domain routed to %q, want node", got)
	}
	// повторный sync — без дублей и порядок жив
	c.SyncRulesNow(t.Context())
	rules, err := xc.ListRules(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, r := range rules {
		seen[r.RuleTag]++
	}
	for tag, n := range seen {
		if n > 1 {
			t.Errorf("duplicate rule %s x%d", tag, n)
		}
	}
	if seen["afpi:client@example.com"] != 1 || seen["afpd:client@example.com"] != 1 {
		t.Errorf("per-user af rules missing after re-sync: %v", seen)
	}
	// РЕГРЕССИЯ sticky-переделки: per-user правила в antifilter ОБЯЗАНЫ быть
	// (blocked → нода назначения), базовых c: НЕТ (инверсия: unblocked → direct),
	// общего балансира XKIT_AF нет.
	if seen["c:client@example.com:NL"] != 0 {
		t.Errorf("базовое per-user в antifilter ломает инверсию: %v", seen)
	}
	for tag := range seen {
		if strings.Contains(tag, "XKIT_AF") {
			t.Errorf("общий балансир остался: %s", tag)
		}
	}
	// config.json персистентен: af-правила выше catch-all
	data, _ := os.ReadFile(cfgPath)
	var cfg map[string]any
	json.Unmarshal(data, &cfg)
	rt := cfg["routing"].(map[string]any)
	rl := rt["rules"].([]any)
	last := rl[len(rl)-1].(map[string]any)
	if last["outboundTag"] != "direct" || last["port"] != "0-65535" {
		t.Errorf("catch-all must stay last: %v", last)
	}
	if rt["domainStrategy"] != "IPIfNonMatch" {
		t.Errorf("domainStrategy: %v", rt["domainStrategy"])
	}
}

// TestAntifilterHotReloadE2E — обновление dat (A/B-файл) + sync: новое содержимое
// матчится БЕЗ рестарта ядра (weak-cache IPSetFactory обходится сменой имени файла).
func TestAntifilterHotReloadE2E(t *testing.T) {
	dir := writeTestGeoFiles(t)
	writeTestBlockedFiles(t, dir)
	s := testStore(t)
	s.SetRoutingMode("antifilter")
	s.SetAntifilterState(antifilterStateForTest("xkit-blocked.dat", 1))
	// per-user af-правила требуют назначения клиента (sticky-переделка)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAssignment(storeAssignment("client@example.com", "NL", "node-nl-1")); err != nil {
		t.Fatal(err)
	}
	routingJSON := `{"domainStrategy":"AsIs","rules":[
		{"type":"field","inboundTag":["api-in"],"outboundTag":"api","ruleTag":"api"},
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

	routeIP := func(ip string) string {
		resp, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
			InboundTag: "vless-in", User: "client@example.com", TargetPort: 443, TargetIPs: [][]byte{xnet.ParseAddress(ip).IP()},
		}})
		if err != nil {
			t.Fatalf("TestRoute %s: %v", ip, err)
		}
		return resp.GetOutboundTag()
	}
	if got := routeIP("9.9.9.9"); got == "direct" {
		t.Fatalf("9.9.9.9 must be blocked initially, got %q", got)
	}
	if got := routeIP("11.11.11.11"); got != "direct" {
		t.Fatalf("11.11.11.11 must be direct initially, got %q", got)
	}
	// «обновление»: файл B содержит ДРУГОЙ набор (11.11.11.0/24 вместо 9.9.9.0/24)
	writeAltBlockedFile(t, dir, "xkit-blocked-2.dat")
	s.SetAntifilterState(antifilterStateForTest("xkit-blocked-2.dat", 1))
	c.SyncRulesNow(t.Context())
	if got := routeIP("11.11.11.11"); got == "direct" {
		t.Fatalf("11.11.11.11 must be blocked after hot reload, got %q", got)
	}
	if got := routeIP("9.9.9.9"); got != "direct" {
		t.Fatalf("9.9.9.9 must be direct after hot reload (old set), got %q", got)
	}
}