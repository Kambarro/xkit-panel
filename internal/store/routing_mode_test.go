package store

import (
	"encoding/json"
	"testing"

	"github.com/kambarro/xkit-panel/internal/routing"
)

// Режим маршрутизации мастера: solo | ru-direct | antifilter (решение владельца).
// Пустая настройка = авто: solo без нод / ru-direct с нодами (текущее поведение).

func TestRoutingModeDefault(t *testing.T) {
	s := openTestStore(t)
	if m := s.RoutingMode(); m != "" {
		t.Fatalf("default routing mode must be '' (auto), got %q", m)
	}
	if eff := s.EffectiveRoutingMode(false); eff != "solo" {
		t.Errorf("auto without nodes → solo, got %q", eff)
	}
	if eff := s.EffectiveRoutingMode(true); eff != "ru-direct" {
		t.Errorf("auto with nodes → ru-direct, got %q", eff)
	}
}

func TestRoutingModeSet(t *testing.T) {
	s := openTestStore(t)
	for _, m := range []string{"solo", "ru-direct", "antifilter"} {
		if err := s.SetRoutingMode(m); err != nil {
			t.Fatalf("set %s: %v", m, err)
		}
		if got := s.RoutingMode(); got != m {
			t.Errorf("get %q want %q", got, m)
		}
		// явный режим не зависит от нод
		if eff := s.EffectiveRoutingMode(false); m != "antifilter" && eff != m {
			t.Errorf("effective %q want %q", eff, m)
		}
	}
	if err := s.SetRoutingMode("bogus"); err == nil {
		t.Error("bogus mode accepted")
	}
	// сброс к авто
	if err := s.SetRoutingMode(""); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if s.RoutingMode() != "" {
		t.Error("reset to auto failed")
	}
}

func TestAlwaysRulesStore(t *testing.T) {
	s := openTestStore(t)
	// пусто по умолчанию
	ar := s.AlwaysRules()
	if len(ar.ProxyCategories)+len(ar.ProxyDomains)+len(ar.DirectCategories)+len(ar.DirectDomains) != 0 {
		t.Fatalf("default always rules not empty: %+v", ar)
	}
	in := routing.AlwaysRules{
		ProxyCategories: []string{"geosite:telegram"},
		ProxyDomains:    []string{"example.com"},
		DirectDomains:   []string{"bank.ru"},
	}
	if err := s.SetAlwaysRules(in); err != nil {
		t.Fatalf("set: %v", err)
	}
	got := s.AlwaysRules()
	if len(got.ProxyCategories) != 1 || got.ProxyCategories[0] != "geosite:telegram" ||
		len(got.ProxyDomains) != 1 || got.ProxyDomains[0] != "example.com" ||
		len(got.DirectDomains) != 1 || got.DirectDomains[0] != "bank.ru" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	// битый JSON в settings → пустые правила, не паника
	s.SetSetting("always_rules", "{broken")
	if ar := s.AlwaysRules(); len(ar.ProxyDomains) != 0 {
		t.Errorf("broken json must yield empty rules: %+v", ar)
	}
}

func TestAntifilterSettings(t *testing.T) {
	s := openTestStore(t)
	if s.AntifilterMargin() {
		t.Error("margin (/24 allyouneed) must default OFF — точный режим")
	}
	if err := s.SetAntifilterMargin(true); err != nil {
		t.Fatal(err)
	}
	if !s.AntifilterMargin() {
		t.Error("margin not persisted")
	}
	// state roundtrip
	st := AntifilterState{Source: "live", PrefixCount: 12345, LastFetch: 1700000000, UpdatedAt: 1700000001}
	if err := s.SetAntifilterState(st); err != nil {
		t.Fatal(err)
	}
	got := s.AntifilterState()
	if got.Source != "live" || got.PrefixCount != 12345 || got.LastFetch != 1700000000 {
		t.Fatalf("state roundtrip: %+v", got)
	}
	// пустое состояние
	s.SetSetting("antifilter_state", "")
	if got := s.AntifilterState(); got.Source != "" || got.PrefixCount != 0 {
		t.Errorf("empty state: %+v", got)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

var _ = json.Marshal