package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kambarro/xkit-panel/internal/store"
)

// TestPublicCountryChangeCode — BUG-1a (QA 2026-11-26): POST country US возвращал
// code=1 (код NL из nodes.country_code) вместо канонического US=3 из country_codes.
// Код обязан браться из канона; GET available — тоже канон.
func TestPublicCountryChangeCode(t *testing.T) {
	s := testStoreAPI(t)
	srv := NewServer(s, nil, "test", "test.local")
	// канон: NL=1, US=3; nodes рассинхронизированы (US-нода code=1) — репро BUG-7
	for _, cc := range []struct {
		country string
		code    uint32
	}{{"NL", 1}, {"US", 3}} {
		s.DB().Exec(`INSERT INTO country_codes(country,code) VALUES(?,?)`, cc.country, cc.code)
	}
	for _, n := range []store.Node{
		{ID: "node-nl-1", Name: "NL", Country: "NL", CountryCode: 1, Host: "nl.test", Health: "alive", Enabled: true},
		{ID: "node-us-539", Name: "US", Country: "US", CountryCode: 1, Host: "us.test", Health: "alive", Enabled: true},
	} {
		if err := s.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertClient(store.Client{Email: "client@example.com", UUID: "u", SubID: "subk", Country: "NL", CountryCode: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/x/subk/country", strings.NewReader(`{"country":"US"}`))
	w := httptest.NewRecorder()
	srv.PublicClientCountry(w, req, "subk")
	if w.Code != 200 {
		t.Fatalf("POST country US: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		OK      bool   `json:"ok"`
		Country string `json:"country"`
		Code    uint32 `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.OK || resp.Country != "US" || resp.Code != 3 {
		t.Fatalf("resp=%+v, want ok US code=3 (канон), не code=1 из nodes", resp)
	}
	// БД: код клиента тоже канонический
	var code uint32
	s.DB().QueryRow(`SELECT country_code FROM clients WHERE email='client@example.com'`).Scan(&code)
	if code != 3 {
		t.Fatalf("clients.country_code=%d want 3", code)
	}
	// GET available: US с кодом 3, не 1
	w = httptest.NewRecorder()
	srv.PublicClientCountry(w, httptest.NewRequest(http.MethodGet, "/x/subk/country", nil), "subk")
	var get struct {
		Country   string `json:"country"`
		Available []struct {
			Country string `json:"country"`
			Code    uint32 `json:"code"`
		} `json:"available"`
	}
	json.Unmarshal(w.Body.Bytes(), &get)
	for _, a := range get.Available {
		if a.Country == "US" && a.Code != 3 {
			t.Fatalf("available US code=%d want 3", a.Code)
		}
		if a.Country == "NL" && a.Code != 1 {
			t.Fatalf("available NL code=%d want 1", a.Code)
		}
	}
	// неизвестная страна → 400 (не 200)
	w = httptest.NewRecorder()
	srv.PublicClientCountry(w, httptest.NewRequest(http.MethodPost, "/x/subk/country", strings.NewReader(`{"country":"ZZ"}`)), "subk")
	if w.Code != 400 {
		t.Fatalf("POST country ZZ: %d want 400", w.Code)
	}
}