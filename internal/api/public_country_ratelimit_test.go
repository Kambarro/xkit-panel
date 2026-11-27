package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kambarro/xkit-panel/internal/store"
)

// TestPublicCountryRateLimit — POST смены страны на secret-URL подписки:
// rate-limit 1 смена/10сек → 429, БД не меняется; админский путь не лимитирован.
func TestPublicCountryRateLimit(t *testing.T) {
	s := testStoreAPI(t)
	srv := NewServer(s, nil, "test", "test.local")
	s.DB().Exec(`INSERT INTO country_codes(country,code) VALUES('NL',1),('US',3)`)
	for _, n := range []store.Node{
		{ID: "node-nl-1", Name: "NL", Country: "NL", CountryCode: 1, Host: "nl.test", Health: "alive", Enabled: true},
		{ID: "node-us-1", Name: "US", Country: "US", CountryCode: 3, Host: "us.test", Health: "alive", Enabled: true},
	} {
		if err := s.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertClient(store.Client{Email: "client@example.com", UUID: "u", SubID: "subk", Country: "NL", CountryCode: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	post := func(country string) int {
		w := httptest.NewRecorder()
		srv.PublicClientCountry(w, httptest.NewRequest(http.MethodPost, "/x/subk/country", strings.NewReader(`{"country":"`+country+`"}`)), "subk")
		return w.Code
	}
	if code := post("US"); code != 200 {
		t.Fatalf("первая смена: %d want 200", code)
	}
	if code := post("NL"); code != http.StatusTooManyRequests {
		t.Fatalf("повторная смена сразу: %d want 429", code)
	}
	var country string
	s.DB().QueryRow(`SELECT country FROM clients WHERE email='client@example.com'`).Scan(&country)
	if country != "US" {
		t.Fatalf("429 не должен менять БД: %s", country)
	}
	// истёкший интервал → смена проходит
	s.DB().Exec(`UPDATE clients SET country_changed_at=country_changed_at-11 WHERE email='client@example.com'`)
	if code := post("NL"); code != 200 {
		t.Fatalf("смена после 10с: %d want 200", code)
	}
	// несуществующий subId → 404 (secret-URL валидация)
	w := httptest.NewRecorder()
	srv.PublicClientCountry(w, httptest.NewRequest(http.MethodPost, "/x/nope/country", strings.NewReader(`{"country":"US"}`)), "nope")
	if w.Code != 404 {
		t.Fatalf("чужой subId: %d want 404", w.Code)
	}
}