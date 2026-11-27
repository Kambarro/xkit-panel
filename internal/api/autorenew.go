package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

// Автопродление клиента (P0 #2, panels-research 3x-ui/Marzban).
// Режимы: none/daily/weekly/monthly/days + сброс трафика. Cron в enforce контроллера.

// setAutoRenew — POST /api/clients/autorenew {email, mode, days, reset_traffic}.
func (s *Server) setAutoRenew(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email        string `json:"email"`
		Mode         string `json:"mode"`
		Days         int    `json:"days"`
		ResetTraffic bool   `json:"reset_traffic"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	valid := map[string]bool{"none": true, "daily": true, "weekly": true, "monthly": true, "days": true}
	if !valid[body.Mode] {
		http.Error(w, "mode: none/daily/weekly/monthly/days", 400); return
	}
	if err := s.store.SetAutoRenew(body.Email, body.Mode, body.Days, body.ResetTraffic); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("autorenew_config", "ok", "автопродление "+body.Email+": "+body.Mode, "{}")
	writeJSON(w, map[string]any{"ok": true, "email": body.Email, "mode": body.Mode})
}

// getAutoRenew — GET /api/clients/autorenew?email=... : параметры + следующее продление.
func (s *Server) getAutoRenew(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" { http.Error(w, "email required", 400); return }
	a := s.store.GetAutoRenew(email)
	var expiry int64
	s.store.DB().QueryRow(`SELECT expiry FROM clients WHERE email=?`, email).Scan(&expiry)
	base := a.LastRenewAt
	if base == 0 { base = expiry }
	if base == 0 { base = time.Now().Unix() }
	next := store.NextRenewTime(a.Mode, a.Days, base)
	writeJSON(w, map[string]any{"mode": a.Mode, "days": a.Days, "reset_traffic": a.ResetTraffic, "last_renew_at": a.LastRenewAt, "next_renew": next, "expiry": expiry})
}