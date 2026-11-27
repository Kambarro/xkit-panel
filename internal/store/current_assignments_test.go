package store

import (
	"path/filepath"
	"testing"
)

// currentTestStore — БД с нодами NL/US/DE и клиентом client (country=NL)
// + QA-мусор в assignments: базовое ''/any → node-us-539 (устаревшие варианты).
func currentTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { s.Close() })
	for _, n := range []Node{
		{ID: "node-nl-1", Name: "Whisper", Country: "NL", Health: "alive", Enabled: true},
		{ID: "node-us-539", Name: "OldUS", Country: "US", Health: "alive", Enabled: true},
		{ID: "node-de-1", Name: "Berlin", Country: "DE", Health: "alive", Enabled: true},
	} {
		if err := s.UpsertNode(n); err != nil { t.Fatal(err) }
	}
	if err := s.UpsertClient(Client{Email: "client", UUID: "u", SubID: "s", Country: "NL", Enabled: true}); err != nil { t.Fatal(err) }
	// строки как на стенде QA: '' первой, any, NL — базовое и any указывают на US
	for _, a := range []Assignment{
		{Email: "client", Country: "", NodeID: "node-us-539", RuleTag: "c:client:", Status: "sticky"},
		{Email: "client", Country: "NL", NodeID: "node-nl-1", RuleTag: "c:client:NL", Status: "sticky"},
		{Email: "client", Country: "any", NodeID: "node-us-539", RuleTag: "c:client:any", Status: "sticky"},
		{Email: "client", Country: "US", NodeID: "node-us-539", RuleTag: "c:client:US", Status: "sticky"},
	} {
		if err := s.SetAssignment(a); err != nil { t.Fatal(err) }
	}
	// явные updated_at: NL-строка — последняя (текущий выбор страны),
	// остальные старше (устаревшие варианты; в пределах одной секунды равны)
	s.DB().Exec(`UPDATE assignments SET updated_at=1000 WHERE email='client'`)
	s.DB().Exec(`UPDATE assignments SET updated_at=2000 WHERE email='client' AND country='NL'`)
	return s
}

// TestCurrentAssignmentsHidesStale — QA-наследие: 4 строки assignments у client
// (базовое/US/any/NL), country=NL → в карте ровно ОДНА актуальная: NL → Whisper.
// Мусор ''/any/US не показывается и БД не чистится.
func TestCurrentAssignmentsHidesStale(t *testing.T) {
	s := currentTestStore(t)
	cur, err := s.CurrentAssignments()
	if err != nil { t.Fatal(err) }
	if len(cur) != 1 {
		t.Fatalf("строк %d, want 1: %+v", len(cur), cur)
	}
	a := cur[0]
	if a.Email != "client" || a.NodeID != "node-nl-1" || a.NodeName != "Whisper" || a.NodeCountry != "NL" || a.Variant {
		t.Fatalf("актуальное: %+v", a)
	}
	// строки в БД остались (код фильтрует, не чистит)
	all, _ := s.AllAssignments()
	if len(all) != 4 { t.Fatalf("БД почищена: %d строк, want 4", len(all)) }
}

// TestCurrentAssignmentsSecondDeviceVariant — свежий явный country-вариант на
// ДРУГОЙ живой ноде (второе устройство, назначен ПОСЛЕ выбора страны) —
// показывается дополнительно с Variant=true; устаревший (старше базы) — нет;
// down-нода варианта — нет.
func TestCurrentAssignmentsSecondDeviceVariant(t *testing.T) {
	s := currentTestStore(t)
	// US-строка старше базы (мусор) → скрыта; сделаем её свежей (второе устройство)
	s.DB().Exec(`UPDATE assignments SET updated_at=3000 WHERE email='client' AND country='US'`)
	cur, _ := s.CurrentAssignments()
	byCountry := map[string]CurrentAssignment{}
	for _, a := range cur { byCountry[a.Country] = a }
	if len(cur) != 2 { t.Fatalf("ожидали базовое NL + свежий вариант US, got %+v", cur) }
	if !byCountry["US"].Variant || byCountry["US"].NodeID != "node-us-539" {
		t.Fatalf("US-вариант: %+v", byCountry["US"])
	}
	if byCountry["NL"].Variant { t.Fatal("базовое помечено вариантом") }
	// нода варианта down → вариант скрыт, базовое осталось
	s.SetNodeHealth("node-us-539", "down", 3)
	cur, _ = s.CurrentAssignments()
	if len(cur) != 1 || cur[0].NodeID != "node-nl-1" { t.Fatalf("down-вариант не скрыт: %+v", cur) }
}

// TestCurrentAssignmentsAnyCountry — клиент country=any: базовое = строка any
// (или '' взаимозаменяемо), устаревшие NL/US-строки (старше базы) скрыты.
func TestCurrentAssignmentsAnyCountry(t *testing.T) {
	s := currentTestStore(t)
	s.DB().Exec(`UPDATE clients SET country='any' WHERE email='client'`)
	s.DB().Exec(`UPDATE assignments SET updated_at=3000 WHERE email='client' AND country='any'`)
	cur, _ := s.CurrentAssignments()
	if len(cur) != 1 { t.Fatalf("any: %+v", cur) }
	base := cur[0]
	if base.Variant || base.NodeID != "node-us-539" { t.Fatalf("базовое any: %+v", base) }
}

// TestCurrentAssignmentsNoClientCountryRow — строки страны клиента нет:
// fallback list[0] (тот же выбор, что syncAllRules), не пустая карта.
func TestCurrentAssignmentsNoClientCountryRow(t *testing.T) {
	s := currentTestStore(t)
	s.DB().Exec(`DELETE FROM assignments WHERE email='client' AND country='NL'`)
	cur, _ := s.CurrentAssignments()
	found := false
	for _, a := range cur {
		if !a.Variant { found = true; if a.Country != "" { t.Fatalf("fallback не list[0]: %+v", a) } }
	}
	if !found { t.Fatal("базовое не найдено") }
}
