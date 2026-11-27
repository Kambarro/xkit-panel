package api

import (
	"encoding/json"
	"net/http"

	"github.com/kambarro/xkit-panel/internal/routing"
	"github.com/kambarro/xkit-panel/internal/store"
)

// PublicClientRouting — публичный API роутинга клиента по subId (без auth).
// GET /<prefix>/<subId>/routing → {mode, rules, allowed, default}
// POST {mode, rules} — клиент меняет свои правила (если allowed владельцем).
// Вызывается из main.go /sub handler. Серверные правила владельца не трогает.
func (s *Server) PublicClientRouting(w http.ResponseWriter, r *http.Request, subID string) {
	var email string
	err := s.store.DB().QueryRow(`SELECT email FROM clients WHERE sub_id=? AND enabled=1`, subID).Scan(&email)
	if err != nil {
		http.Error(w, "not found", 404); return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		mode, rules, allowed := s.store.ClientRouting(email)
		json.NewEncoder(w).Encode(map[string]any{
			"mode": mode, "rules": rules, "allowed": allowed,
			"default": s.store.DefaultRouting(),
		})
		return
	}
	if r.Method == http.MethodPost {
		var body struct {
			Mode  string              `json:"mode"`
			Rules routing.CustomRules `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400); return
		}
		_, _, allowed := s.store.ClientRouting(email)
		if body.Mode == "custom" && !allowed {
			http.Error(w, "кастомный роутинг запрещён владельцем", 403); return
		}
		if body.Mode != "custom" { body.Mode = "default" }
		sr := store.CustomRules{DirectSites: body.Rules.DirectSites, ProxySites: body.Rules.ProxySites, BlockSites: body.Rules.BlockSites, DirectIP: body.Rules.DirectIP, ProxyIP: body.Rules.ProxyIP, BlockIP: body.Rules.BlockIP}
		if err := s.store.SetClientRouting(email, body.Mode, sr); err != nil {
			http.Error(w, err.Error(), 500); return
		}
		s.store.AddEvent("routing", "ok", "клиент "+email+" изменил свои правила ("+body.Mode+")", "{}")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "mode": body.Mode})
		return
	}
	http.Error(w, "method not allowed", 405)
}