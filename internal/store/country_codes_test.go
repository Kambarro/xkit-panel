package store

import (
	"path/filepath"
	"testing"
)

// TestCountryCodeSyncMigration — BUG-1a/BUG-7 (QA 2026-11-26): рассинхрон
// nodes.country_code с канонической country_codes (US-нода с кодом 1=NL)
// лечится миграцией 034 при открытии БД; клиенты тоже приводятся к канону.
func TestCountryCodeSyncMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// канон: NL=1, US=3, DE=4 (как на живом стенде QA)
	for _, cc := range []struct {
		country string
		code    uint32
	}{{"NL", 1}, {"US", 3}, {"DE", 4}} {
		if _, err := s.DB().Exec(`INSERT INTO country_codes(country,code) VALUES(?,?)`, cc.country, cc.code); err != nil {
			t.Fatal(err)
		}
	}
	// «сломанные» данные: обе ноды с кодом 1 (репро BUG-7)
	nodes := []Node{
		{ID: "node-nl-1", Name: "NL", Country: "NL", CountryCode: 1, Host: "nl.test", Health: "alive", Enabled: true},
		{ID: "node-us-539", Name: "US", Country: "US", CountryCode: 1, Host: "us.test", Health: "alive", Enabled: true},
	}
	for _, n := range nodes {
		if err := s.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	// клиент сменил страну на US, но код залип NL=1 (репро BUG-1a)
	if err := s.UpsertClient(Client{Email: "client@example.com", UUID: "u", SubID: "s1", Country: "US", CountryCode: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// клиент any: код обязан быть 0
	if err := s.UpsertClient(Client{Email: "any@test.ru", UUID: "u2", SubID: "s2", Country: "any", CountryCode: 7, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// повторное открытие = миграция 034 чинит рассинхрон
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var code uint32
	if err := s2.DB().QueryRow(`SELECT country_code FROM nodes WHERE id='node-us-539'`).Scan(&code); err != nil || code != 3 {
		t.Fatalf("US-нода code=%d err=%v, want 3 (канон country_codes)", code, err)
	}
	if err := s2.DB().QueryRow(`SELECT country_code FROM clients WHERE email='client@example.com'`).Scan(&code); err != nil || code != 3 {
		t.Fatalf("клиент US code=%d err=%v, want 3", code, err)
	}
	if err := s2.DB().QueryRow(`SELECT country_code FROM clients WHERE email='any@test.ru'`).Scan(&code); err != nil || code != 0 {
		t.Fatalf("клиент any code=%d err=%v, want 0", code, err)
	}
	// канонические коды не тронуты
	if err := s2.DB().QueryRow(`SELECT country_code FROM nodes WHERE id='node-nl-1'`).Scan(&code); err != nil || code != 1 {
		t.Fatalf("NL-нода code=%d err=%v, want 1", code, err)
	}
}

// TestCountryCode — единая точка выдачи/чтения кода страны (канон country_codes).
func TestCountryCode(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// новая страна: код выдаётся и запоминается
	c1, err := s.CountryCode("NL")
	if err != nil || c1 == 0 {
		t.Fatalf("CountryCode(NL)=%d err=%v", c1, err)
	}
	// повтор — тот же код (инвариант «код выдаётся один раз»)
	c2, _ := s.CountryCode("NL")
	if c2 != c1 {
		t.Fatalf("код NL изменился: %d → %d", c1, c2)
	}
	// другая страна — другой код
	c3, _ := s.CountryCode("US")
	if c3 == 0 || c3 == c1 {
		t.Fatalf("US code=%d, want отличный от NL=%d", c3, c1)
	}
	// LookupCountryCode: неизвестная страна → 0 без ошибки и БЕЗ выдачи кода
	if got, _ := s.LookupCountryCode("ZZ"); got != 0 {
		t.Fatalf("LookupCountryCode(ZZ)=%d want 0", got)
	}
	var n int
	s.DB().QueryRow(`SELECT COUNT(*) FROM country_codes WHERE country='ZZ'`).Scan(&n)
	if n != 0 {
		t.Fatal("Lookup не должен создавать код для неизвестной страны")
	}
}