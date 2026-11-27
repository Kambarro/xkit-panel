package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

// TestClientsNodesTrafficFields — API клиентов/нод отдаёт lifetime-трафик;
// где накопитель пуст — текущий доступный счётчик + traffic_lifetime=false.
func TestClientsNodesTrafficFields(t *testing.T) {
	s := testStoreAPI(t)
	srv := NewServer(s, nil, "test", "test.local")
	if err := s.UpsertNode(store.Node{ID: "node-nl-1", Name: "Whisper", Country: "NL", Health: "alive", Enabled: true}); err != nil { t.Fatal(err) }
	if err := s.UpsertClient(store.Client{Email: "a@t", UUID: "u", SubID: "s", Enabled: true}); err != nil { t.Fatal(err) }
	s.SetUsedBytes("a@t", 500) // текущий счётчик без накопителя

	get := func(path string, fn func(*httptest.ResponseRecorder)) []map[string]any {
		w := httptest.NewRecorder()
		var out []map[string]any
		fn(w)
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil { t.Fatalf("%s: %v", path, err) }
		return out
	}
	cls := get("/api/clients", func(w *httptest.ResponseRecorder) {
		srv.clients(w, httptest.NewRequest("GET", "/api/clients", nil))
	})
	if len(cls) != 1 { t.Fatalf("clients: %v", cls) }
	c := cls[0]
	if c["traffic_total_bytes"].(float64) != 500 || c["traffic_lifetime"].(bool) {
		t.Fatalf("fallback на used_bytes: %v", c)
	}
	// накопитель появился → lifetime
	s.AccumulateClientTraffic("a@t", 1000, 2000)
	s.AddTrafficDelta("node", "node-nl-1", 7, 8)
	cls = get("/api/clients", func(w *httptest.ResponseRecorder) {
		srv.clients(w, httptest.NewRequest("GET", "/api/clients", nil))
	})
	c = cls[0]
	if c["traffic_total_bytes"].(float64) != 3000 || !c["traffic_lifetime"].(bool) ||
		c["traffic_up_bytes"].(float64) != 1000 || c["traffic_down_bytes"].(float64) != 2000 {
		t.Fatalf("lifetime клиента: %v", c)
	}
	nds := get("/api/nodes", func(w *httptest.ResponseRecorder) {
		srv.nodes(w, httptest.NewRequest("GET", "/api/nodes", nil))
	})
	n := nds[0]
	if n["traffic_total_bytes"].(float64) != 15 || !n["traffic_lifetime"].(bool) {
		t.Fatalf("lifetime ноды: %v", n)
	}
}

// TestClientsNodesTrafficPeriods — /api/clients и /api/nodes отдают скользящие
// периоды 24ч/7д/30д (up+down и раздельно) из hour-бакетов рядом с lifetime;
// бакетов нет → нули, не отсутствие полей.
func TestClientsNodesTrafficPeriods(t *testing.T) {
	s := testStoreAPI(t)
	srv := NewServer(s, nil, "test", "test.local")
	if err := s.UpsertNode(store.Node{ID: "n1", Name: "W", Country: "NL", Health: "alive", Enabled: true}); err != nil { t.Fatal(err) }
	if err := s.UpsertClient(store.Client{Email: "a@t", UUID: "u", SubID: "s", Enabled: true}); err != nil { t.Fatal(err) }
	s.AccumulateClientTraffic("a@t", 1000, 2000) // текущий час → во всех окнах
	s.AddTrafficDelta("node", "n1", 7, 8)
	// старый бакет клиента: 8 дней назад → только month
	h := time.Now().Unix() / 3600 * 3600
	if _, err := s.DB().Exec(`INSERT INTO traffic_hourly(kind,id,hour,up,down) VALUES('client','a@t',?,100,200)`, h-8*24*3600); err != nil { t.Fatal(err) }

	get := func(fn func(*httptest.ResponseRecorder)) map[string]any {
		w := httptest.NewRecorder()
		fn(w)
		var out []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil { t.Fatal(err) }
		if len(out) != 1 { t.Fatalf("want 1 row: %v", out) }
		return out[0]
	}
	c := get(func(w *httptest.ResponseRecorder) { srv.clients(w, httptest.NewRequest("GET", "/api/clients", nil)) })
	if c["traffic_today_bytes"].(float64) != 3000 || c["traffic_today_up_bytes"].(float64) != 1000 || c["traffic_today_down_bytes"].(float64) != 2000 {
		t.Fatalf("client today: %v", c)
	}
	if c["traffic_week_bytes"].(float64) != 3000 { t.Fatalf("client week: %v", c) }
	if c["traffic_month_bytes"].(float64) != 3300 || c["traffic_month_up_bytes"].(float64) != 1100 || c["traffic_month_down_bytes"].(float64) != 2200 {
		t.Fatalf("client month: %v", c)
	}
	if c["traffic_total_bytes"].(float64) != 3000 { t.Fatalf("lifetime не должен включать ручной старый бакет: %v", c) }
	n := get(func(w *httptest.ResponseRecorder) { srv.nodes(w, httptest.NewRequest("GET", "/api/nodes", nil)) })
	if n["traffic_today_bytes"].(float64) != 15 || n["traffic_week_bytes"].(float64) != 15 || n["traffic_month_bytes"].(float64) != 15 {
		t.Fatalf("node periods: %v", n)
	}
	if n["traffic_today_up_bytes"].(float64) != 7 || n["traffic_today_down_bytes"].(float64) != 8 {
		t.Fatalf("node today up/down: %v", n)
	}
}
