package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kambarro/xkit-panel/internal/antifilter"
	"github.com/kambarro/xkit-panel/internal/store"
)

// TestRoutingModeAPI — переключатель режимов: валидация, antifilter без нод
// запрещён, пустой кеш → 409 (не молча), always-правила валидируются, конфликты
// видны в GET, но сохранение не блокируют (direct приоритетнее).
func TestRoutingModeAPI(t *testing.T) {
	s := testStoreAPI(t)
	srv := NewServer(s, nil, "test", "test.local")
	af := antifilter.NewManager(s, filepath.Join(t.TempDir(), "cache"), filepath.Join(t.TempDir(), "asset"))
	srv.SetAntifilterManager(af)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/routing/mode", strings.NewReader(body))
		w := httptest.NewRecorder()
		srv.routingMode(w, req)
		return w
	}
	get := func() map[string]any {
		w := httptest.NewRecorder()
		srv.routingMode(w, httptest.NewRequest(http.MethodGet, "/api/routing/mode", nil))
		var m map[string]any
		json.Unmarshal(w.Body.Bytes(), &m)
		return m
	}
	// дефолт: авто, effective solo (нод нет)
	g := get()
	if g["mode"] != "" || g["effective"] != "solo" {
		t.Fatalf("default: %v", g)
	}
	// битый режим → 400
	if w := post(`{"mode":"bogus"}`); w.Code != 400 {
		t.Errorf("bogus mode: %d", w.Code)
	}
	// antifilter без нод → 400
	if w := post(`{"mode":"antifilter"}`); w.Code != 400 {
		t.Errorf("antifilter without nodes: %d want 400", w.Code)
	}
	// нода есть, но кеш пуст → 409 (режим не включается молча)
	s.UpsertNode(store.Node{ID: "n1", Name: "NL", Country: "NL", Host: "nl.test", Health: "alive", Enabled: true})
	if w := post(`{"mode":"antifilter"}`); w.Code != 409 {
		t.Errorf("antifilter empty cache: %d want 409", w.Code)
	}
	// solo/ru-direct переключаются свободно
	if w := post(`{"mode":"ru-direct"}`); w.Code != 200 {
		t.Errorf("ru-direct: %d %s", w.Code, w.Body.String())
	}
	if s.RoutingMode() != "ru-direct" {
		t.Errorf("mode not persisted: %q", s.RoutingMode())
	}
	// always: мусор → 400
	if w := post(`{"always":{"proxy_domains":["bad domain"]}}`); w.Code != 400 {
		t.Errorf("bad always: %d", w.Code)
	}
	// always: валидное + конфликт (telegram в обоих) → 200, conflicts в GET
	if w := post(`{"always":{"proxy_categories":["geosite:telegram"],"direct_categories":["geosite:telegram"],"proxy_domains":["Example.com"]}}`); w.Code != 200 {
		t.Fatalf("valid always: %d %s", w.Code, w.Body.String())
	}
	g = get()
	conf, _ := g["conflicts"].(map[string]any)
	cats, _ := conf["categories"].([]any)
	if len(cats) != 1 || cats[0] != "geosite:telegram" {
		t.Errorf("conflicts not surfaced: %v", conf)
	}
	always, _ := g["always"].(map[string]any)
	pd, _ := always["proxy_domains"].([]any)
	if len(pd) != 1 || pd[0] != "example.com" {
		t.Errorf("always not normalized: %v", always)
	}
	catsList, _ := g["categories"].([]any)
	if len(catsList) == 0 {
		t.Error("categories catalog empty")
	}
	// margin флаг
	if w := post(`{"margin":true}`); w.Code != 200 || !s.AntifilterMargin() {
		t.Errorf("margin: %d", w.Code)
	}
}