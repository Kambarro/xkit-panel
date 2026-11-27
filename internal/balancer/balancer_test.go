package balancer

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/kambarro/xkit-panel/internal/store"
)

// testStore создаёт временную SQLite БД с тестовыми нодами.
func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	// DE: 2 ноды (priority 1, 2), NL: 1 нода, US: 1 нода
	nodes := []store.Node{
		{ID: "node-de-1", Name: "Frankfurt-1", Country: "DE", CountryCode: 1, Priority: 1, Price: 1.0, Host: "de1.test", Tunnel: "reality", Health: "alive", Enabled: true},
		{ID: "node-de-2", Name: "Frankfurt-2", Country: "DE", CountryCode: 1, Priority: 2, Price: 1.0, Host: "de2.test", Tunnel: "reality", Health: "alive", Enabled: true},
		{ID: "node-nl-1", Name: "Amsterdam-1", Country: "NL", CountryCode: 2, Priority: 1, Price: 1.2, Host: "nl1.test", Tunnel: "xhttp", Health: "alive", Enabled: true},
		{ID: "node-us-1", Name: "NewYork-1", Country: "US", CountryCode: 3, Priority: 1, Price: 1.5, Host: "us1.test", Tunnel: "ws", Health: "alive", Enabled: true},
	}
	for _, n := range nodes {
		if err := s.UpsertNode(n); err != nil {
			t.Fatalf("upsert node: %v", err)
		}
	}
	return s
}

// TestPickNode_Priority проверяет выбор лучшей по приоритету незагруженной ноды.
func TestPickNode_Priority(t *testing.T) {
	s := testStore(t)
	b := New(s, nil) // xray nil — PickNode не использует gRPC
	loads := map[string]NodeLoad{}
	n, err := b.PickNode("DE", loads)
	if err != nil || n == nil {
		t.Fatalf("PickNode DE: %v %v", n, err)
	}
	if n.ID != "node-de-1" {
		t.Errorf("ожидал node-de-1 (priority 1), получил %s", n.ID)
	}
}

// TestPickNode_Loaded проверяет: лучшая загружена → следующая по приоритету.
func TestPickNode_Loaded(t *testing.T) {
	s := testStore(t)
	b := New(s, nil)
	loads := map[string]NodeLoad{"node-de-1": {Load: 0.95}} // de-1 загружена
	n, _ := b.PickNode("DE", loads)
	if n == nil || n.ID != "node-de-2" {
		t.Errorf("de-1 загружена → ожидал node-de-2, получил %v", n)
	}
}

// TestPickNode_AllLoaded проверяет: все загружены → наименее загруженная.
func TestPickNode_AllLoaded(t *testing.T) {
	s := testStore(t)
	b := New(s, nil)
	loads := map[string]NodeLoad{"node-de-1": {Load: 0.95}, "node-de-2": {Load: 0.85}}
	n, _ := b.PickNode("DE", loads)
	if n == nil || n.ID != "node-de-2" {
		t.Errorf("все загружены → ожидал node-de-2 (0.85), получил %v", n)
	}
}

// TestPickNode_Down проверяет: down нода пропускается.
func TestPickNode_Down(t *testing.T) {
	s := testStore(t)
	s.SetNodeHealth("node-de-1", "down", 3)
	b := New(s, nil)
	n, _ := b.PickNode("DE", map[string]NodeLoad{})
	if n == nil || n.ID != "node-de-2" {
		t.Errorf("de-1 down → ожидал node-de-2, получил %v", n)
	}
}

// TestPickNode_AllDown проверяет: все ноды страны down → nil (для fallback).
func TestPickNode_AllDown(t *testing.T) {
	s := testStore(t)
	s.SetNodeHealth("node-us-1", "down", 3)
	b := New(s, nil)
	n, _ := b.PickNode("US", map[string]NodeLoad{})
	if n != nil {
		t.Errorf("US все down → ожидал nil, получил %v", n)
	}
}

// TestFallbackCountry проверяет: все ноды страны мертвы → другая страна.
func TestFallbackCountry(t *testing.T) {
	s := testStore(t)
	s.SetNodeHealth("node-us-1", "down", 3)
	b := New(s, nil)
	n, country, err := b.fallbackCountry("US", map[string]NodeLoad{})
	if err != nil || n == nil {
		t.Fatalf("fallback: %v %v", n, err)
	}
	if country == "US" {
		t.Errorf("fallback не должен быть US")
	}
	t.Logf("US down → fallback %s (%s)", country, n.ID)
}

// TestRecordProbe_FailsToDown проверяет гистерезис: 3 неудачи подряд → down.
func TestRecordProbe_FailsToDown(t *testing.T) {
	s := testStore(t)
	b := New(s, nil)
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		down, err := b.RecordProbe(ctx, "node-de-1", false)
		if err != nil {
			t.Fatalf("probe %d: %v", i, err)
		}
		if i < 3 && down {
			t.Errorf("probe %d: не должен быть down раньше 3", i)
		}
		if i == 3 && !down {
			t.Errorf("probe 3: должен стать down")
		}
	}
	// восстановление
	down, _ := b.RecordProbe(ctx, "node-de-1", true)
	if down {
		t.Errorf("удачная проба не должна давать down")
	}
	var health string
	s.DB().QueryRow(`SELECT health FROM nodes WHERE id='node-de-1'`).Scan(&health)
	if health != "alive" {
		t.Errorf("после удачной пробы health=%s, ожидал alive", health)
	}
}

// TestStore_Assignment проверяет sticky-карту CRUD.
func TestStore_Assignment(t *testing.T) {
	s := testStore(t)
	s.UpsertClient(store.Client{Email: "ivan@test.ru", UUID: "u1", SubID: "s1", Country: "DE", CountryCode: 1, Enabled: true})
	a := store.Assignment{Email: "ivan@test.ru", Country: "DE", NodeID: "node-de-1", RuleTag: "c:ivan@test.ru:de", Status: "sticky"}
	if err := s.SetAssignment(a); err != nil {
		t.Fatalf("set assignment: %v", err)
	}
	got, _ := s.GetAssignment("ivan@test.ru", "DE")
	if got == nil || got.NodeID != "node-de-1" {
		t.Fatalf("get assignment: %v", got)
	}
	// смена ноды
	a.NodeID = "node-de-2"
	s.SetAssignment(a)
	got, _ = s.GetAssignment("ivan@test.ru", "DE")
	if got.NodeID != "node-de-2" {
		t.Errorf("после смены нода=%s, ожидал node-de-2", got.NodeID)
	}
	byNode, _ := s.AssignmentsByNode("node-de-2")
	if len(byNode) != 1 {
		t.Errorf("AssignmentsByNode: %d, ожидал 1", len(byNode))
	}
}

// TestStore_Expired проверяет enforce expiry.
func TestStore_Expired(t *testing.T) {
	s := testStore(t)
	s.UpsertClient(store.Client{Email: "old@test.ru", UUID: "u", SubID: "s", Expiry: 1000, Enabled: true})
	s.UpsertClient(store.Client{Email: "new@test.ru", UUID: "u", SubID: "s", Expiry: 9999999999, Enabled: true})
	s.UpsertClient(store.Client{Email: "free@test.ru", UUID: "u", SubID: "s", Expiry: 0, Enabled: true})
	exp, _ := s.ExpiredClients(2000)
	if len(exp) != 1 || exp[0].Email != "old@test.ru" {
		t.Errorf("ExpiredClients: %v, ожидал только old@test.ru", exp)
	}
}