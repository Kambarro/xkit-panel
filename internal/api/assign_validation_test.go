package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kambarro/xkit-panel/internal/balancer"
	"github.com/kambarro/xkit-panel/internal/store"
)

// TestAssignValidation — BUG-6 (QA 2026-11-26): /api/assign {} → 500 FK,
// несуществующий email → 500 FK + сиротское правило в xray, country=ZZ → 200.
// Должно быть: пустой email → 400, неизвестный клиент → 404, неизвестная
// страна → 400, и НИКАКИХ правил/assignments до валидации.
func TestAssignValidation(t *testing.T) {
	s := testStoreAPI(t)
	xc := startTestXray(t)
	srv := NewServer(s, xc, "test", "test.local")
	srv.SetController(balancer.NewController(s, xc))
	s.DB().Exec(`INSERT INTO country_codes(country,code) VALUES('NL',1)`)
	if err := s.UpsertNode(store.Node{ID: "node-nl-1", Name: "NL", Country: "NL", CountryCode: 1, Host: "nl.test", Health: "alive", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertClient(store.Client{Email: "client@example.com", UUID: "u", SubID: "sk", Country: "NL", CountryCode: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// outbound node-nl-1 в тестовом xray есть (startXrayAPI не имеет — добавим через freedom нельзя,
	// правило создастся, но TestRoute не нужен: проверяем HTTP-коды и отсутствие сирот)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/assign", strings.NewReader(body))
		w := httptest.NewRecorder()
		srv.assignClient(w, req)
		return w
	}
	if w := post(`{}`); w.Code != 400 {
		t.Errorf("assign {}: %d want 400 (было 500 FK)", w.Code)
	}
	if w := post(`{"email":"nobody@test.ru","country":"NL"}`); w.Code != 404 {
		t.Errorf("assign nobody: %d want 404 (было 500 FK)", w.Code)
	}
	if w := post(`{"email":"client@example.com","country":"ZZ"}`); w.Code != 400 {
		t.Errorf("assign ZZ: %d want 400 (было 200)", w.Code)
	}
	// сиротских правил/assignments не создано
	var n int
	s.DB().QueryRow(`SELECT COUNT(*) FROM assignments WHERE email='nobody@test.ru'`).Scan(&n)
	if n != 0 {
		t.Errorf("сиротские assignments nobody: %d", n)
	}
	s.DB().QueryRow(`SELECT COUNT(*) FROM assignments WHERE country='ZZ'`).Scan(&n)
	if n != 0 {
		t.Errorf("assignment ZZ создан: %d", n)
	}
	rules, err := xc.ListRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if strings.Contains(r.RuleTag, "nobody") || strings.HasSuffix(r.RuleTag, ":ZZ") {
			t.Errorf("сиротское правило в xray: %s", r.RuleTag)
		}
	}
	// валидный assign всё ещё работает (идемпотентно, BUG-4)
	if w := post(`{"email":"client@example.com","country":""}`); w.Code != 200 {
		t.Fatalf("assign base: %d %s", w.Code, w.Body.String())
	}
	if w := post(`{"email":"client@example.com","country":""}`); w.Code != 200 {
		t.Fatalf("assign base повтор (BUG-4): %d %s", w.Code, w.Body.String())
	}
}

// TestFailoverUnknownNode — BUG-10 (LOW, QA): failover несуществующей ноды →
// 200 done + мусорное событие node_down error. Должен 404 без события.
func TestFailoverUnknownNode(t *testing.T) {
	s := testStoreAPI(t)
	xc := startTestXray(t)
	srv := NewServer(s, xc, "test", "test.local")
	srv.SetController(balancer.NewController(s, xc))
	req := httptest.NewRequest(http.MethodPost, "/api/failover", strings.NewReader(`{"node_id":"no-such-node"}`))
	w := httptest.NewRecorder()
	srv.failoverNode(w, req)
	if w.Code != 404 {
		t.Fatalf("failover no-such-node: %d want 404", w.Code)
	}
	var n int
	s.DB().QueryRow(`SELECT COUNT(*) FROM events WHERE kind='node_down' AND message LIKE '%no-such-node%'`).Scan(&n)
	if n != 0 {
		t.Fatalf("мусорное событие node_down о несуществующей ноде: %d", n)
	}
}

// TestSetClientCountryUnknownEmail — BUG-6: /api/clients/country для
// несуществующего email → 200 ok + warn FK. Должен 404.
func TestSetClientCountryUnknownEmail(t *testing.T) {
	s := testStoreAPI(t)
	srv := NewServer(s, nil, "test", "test.local")
	req := httptest.NewRequest(http.MethodPost, "/api/clients/country", strings.NewReader(`{"email":"nobody@test.ru","country":"NL"}`))
	w := httptest.NewRecorder()
	srv.setClientCountry(w, req)
	if w.Code != 404 {
		t.Fatalf("clients/country nobody: %d want 404 (было 200+мусор)", w.Code)
	}
}