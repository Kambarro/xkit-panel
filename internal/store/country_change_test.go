package store

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestChangeClientCountry — единая точка смены страны (упрощение: страна =
// clients.country). Валидация (канон + включённая нода), нормализация any,
// rate-limit (1 смена/10сек), аудит, админский путь без лимита.
func TestChangeClientCountry(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.DB().Exec(`INSERT INTO country_codes(country,code) VALUES('NL',1),('US',3)`)
	for _, n := range []Node{
		{ID: "node-nl-1", Name: "NL", Country: "NL", CountryCode: 1, Host: "nl.test", Health: "alive", Enabled: true},
		{ID: "node-us-1", Name: "US", Country: "US", CountryCode: 3, Host: "us.test", Health: "alive", Enabled: true},
	} {
		if err := s.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertClient(Client{Email: "c@test.ru", UUID: "u", SubID: "s1", Country: "NL", CountryCode: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	// валидная смена NL→US: код из канона, БД обновлена, аудит есть
	code, err := s.ChangeClientCountry("c@test.ru", "US", 10, "subscription")
	if err != nil || code != 3 {
		t.Fatalf("change US: code=%d err=%v", code, err)
	}
	var country string
	var dbCode uint32
	s.DB().QueryRow(`SELECT country,country_code FROM clients WHERE email='c@test.ru'`).Scan(&country, &dbCode)
	if country != "US" || dbCode != 3 {
		t.Fatalf("БД: %s/%d, want US/3", country, dbCode)
	}
	var events int
	s.DB().QueryRow(`SELECT COUNT(*) FROM events WHERE kind='country_change'`).Scan(&events)
	if events != 1 {
		t.Fatalf("аудит country_change: %d событий, want 1", events)
	}

	// rate-limit: повторная смена сразу → ErrCountryRateLimit, БД не изменилась
	if _, err := s.ChangeClientCountry("c@test.ru", "NL", 10, "bot"); !errors.Is(err, ErrCountryRateLimit) {
		t.Fatalf("повторная смена: err=%v, want ErrCountryRateLimit", err)
	}
	s.DB().QueryRow(`SELECT country FROM clients WHERE email='c@test.ru'`).Scan(&country)
	if country != "US" {
		t.Fatalf("rate-limit не должен менять БД: %s", country)
	}

	// админский путь (minInterval=0) обходит лимит
	if _, err := s.ChangeClientCountry("c@test.ru", "NL", 0, "admin"); err != nil {
		t.Fatalf("admin change: %v", err)
	}

	// неизвестная страна / страна без нод → ErrCountryUnavailable
	if _, err := s.ChangeClientCountry("c@test.ru", "XX", 0, "admin"); !errors.Is(err, ErrCountryUnavailable) {
		t.Fatalf("XX: err=%v, want ErrCountryUnavailable", err)
	}
	s.DB().Exec(`UPDATE nodes SET enabled=0 WHERE id='node-us-1'`)
	if _, err := s.ChangeClientCountry("c@test.ru", "US", 0, "admin"); !errors.Is(err, ErrCountryUnavailable) {
		t.Fatalf("US без включённых нод: err=%v, want ErrCountryUnavailable", err)
	}

	// any/пусто нормализуются в any, code=0, валидация не нужна
	for _, in := range []string{"any", "", "ANY"} {
		code, err := s.ChangeClientCountry("c@test.ru", in, 0, "bot")
		if err != nil || code != 0 {
			t.Fatalf("any(%q): code=%d err=%v", in, code, err)
		}
		s.DB().QueryRow(`SELECT country FROM clients WHERE email='c@test.ru'`).Scan(&country)
		if country != "any" {
			t.Fatalf("any(%q) → %q", in, country)
		}
	}
}