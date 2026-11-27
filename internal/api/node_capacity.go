package api

import (
	"encoding/json"
	"net/http"
)

// POST /api/nodes/capacity {id, capacity} — ёмкость ноды (клиентов = 100% загрузки).
// capacity=0 → используется дефолт из настроек балансировщика.
func (s *Server) setNodeCapacity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		Capacity int    `json:"capacity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "id обязателен", 400)
		return
	}
	if err := s.store.SetNodeCapacity(req.ID, req.Capacity); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.store.AddEvent("node", "ok", "ёмкость ноды "+req.ID+" изменена", "{}")
	writeJSON(w, map[string]any{"ok": true, "id": req.ID, "capacity": req.Capacity})
}