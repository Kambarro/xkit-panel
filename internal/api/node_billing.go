package api

import (
	"encoding/json"
	"net/http"
	"time"
)

func nowUnixAPI() int64 { return time.Now().Unix() }

// Трафик-бюджет ноды под биллинг хостера (P1 #5, Remnawave nodes.md).
// Лимит GB + день сброса + multiplier ×0.5/×2 + алерт 90%.

// nodeBilling — GET /api/nodes/billing?id=... : бюджет ноды.
func (s *Server) nodeBilling(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" { http.Error(w, "id required", 400); return }
	b := s.store.GetNodeBilling(id)
	writeJSON(w, map[string]any{
		"limit_gb": b.LimitGB, "used_bytes": b.UsedBytes, "reset_day": b.ResetDay,
		"period_start": b.PeriodStart, "multiplier": b.Multiplier,
		"pct": b.Pct(), "alert_sent": b.AlertSent,
	})
}

// setNodeBilling — POST /api/nodes/billing {id, limit_gb, reset_day, multiplier}.
func (s *Server) setNodeBilling(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID         string  `json:"id"`
		LimitGB    int     `json:"limit_gb"`
		ResetDay   int     `json:"reset_day"`
		Multiplier float64 `json:"multiplier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "id required", 400); return
	}
	if err := s.store.SetNodeBilling(body.ID, body.LimitGB, body.ResetDay, body.Multiplier); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("node_billing", "ok", "бюджет ноды "+body.ID+" обновлён", "{}")
	writeJSON(w, map[string]any{"ok": true, "id": body.ID})
}

// resetNodeBilling — POST /api/nodes/billing/reset {id}: ручной сброс периода.
func (s *Server) resetNodeBilling(w http.ResponseWriter, r *http.Request) {
	var body struct{ ID string `json:"id"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "id required", 400); return
	}
	if err := s.store.ResetNodeBillingPeriod(body.ID, nowUnixAPI()); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("node_billing", "ok", "трафик ноды "+body.ID+" сброшен вручную", "{}")
	writeJSON(w, map[string]any{"ok": true})
}