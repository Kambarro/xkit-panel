package balancer

import (
	"testing"
)

// TestAssignIdempotent — BUG-4 (QA 2026-11-26): повторный Assign на ту же ноду
// (в т.ч. country="") давал 500 duplicate ruleTag: ветка else звала AddUserRule
// без remove, а параллельный syncAllRules уже добавил правило с тем же тегом.
// Assign обязан быть идемпотентным: повтор → ok, ровно одно правило в ядре.
func TestAssignIdempotent(t *testing.T) {
	writeTestGeoFiles(t)
	s := testStore(t)
	if err := s.UpsertClient(testClient("client@example.com", "", 0)); err != nil {
		t.Fatal(err)
	}
	routingJSON := `{"domainStrategy":"AsIs","rules":[
		{"type":"field","inboundTag":["api-in"],"outboundTag":"api","ruleTag":"api"},
		{"type":"field","port":"0-65535","outboundTag":"direct"}]}`
	xc := startXrayAPI(t, routingJSON)
	b := New(s, xc)
	loads := map[string]NodeLoad{}

	// первый assign base ('') — как POST /api/assign {"country":""}
	a1, err := b.Assign(t.Context(), "client@example.com", "", loads)
	if err != nil {
		t.Fatalf("assign#1: %v", err)
	}
	// имитируем гонку из отчёта: syncAllRules уже добавил правило с тем же тегом
	// (первый Assign добавил, повторный без remove падал duplicate ruleTag)
	a2, err := b.Assign(t.Context(), "client@example.com", "", loads)
	if err != nil {
		t.Fatalf("assign#2 (тот же узел, идемпотентность): %v", err)
	}
	if a2.NodeID != a1.NodeID {
		t.Fatalf("нода изменилась без причины: %s → %s", a1.NodeID, a2.NodeID)
	}
	// третий подряд — тоже ok
	if _, err := b.Assign(t.Context(), "client@example.com", "", loads); err != nil {
		t.Fatalf("assign#3: %v", err)
	}
	// в ядре ровно одно правило c:client:
	rules, err := xc.ListRules(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, r := range rules {
		if r.RuleTag == "c:client@example.com:" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("правил c:client: в ядре %d, want 1", count)
	}
	// смена ноды тем же тегом (NL→другая нода той же страны) тоже без duplicate
	if _, err := b.Assign(t.Context(), "client@example.com", "DE", loads); err != nil {
		t.Fatalf("assign DE: %v", err)
	}
	if _, err := b.Assign(t.Context(), "client@example.com", "DE", loads); err != nil {
		t.Fatalf("assign DE повтор: %v", err)
	}
}