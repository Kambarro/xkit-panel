package api

import (
	"encoding/json"
	"net/http"

	"github.com/kambarro/xkit-panel/internal/store"
)

// Настройки балансировщика (админ, вкладка Балансировщик).
// GET /api/balancer/settings, POST /api/balancer/settings.

func (s *Server) balancerSettings(w http.ResponseWriter, r *http.Request) {
	bs := s.store.BalancerSettings()
	if r.Method == http.MethodPost {
		var in store.BalancerSettings
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), 400); return
		}
		// валидация
		if in.LoadThreshold <= 0 || in.LoadThreshold > 1 { in.LoadThreshold = 0.80 }
		if in.FailsToDown < 1 { in.FailsToDown = 3 }
		if in.ProbeSec < 5 { in.ProbeSec = 15 }
		if in.ReevalSec < 5 { in.ReevalSec = 30 }
		if in.EnforceSec < 10 { in.EnforceSec = 60 }
		s.store.SetBalancerSettings(in)
		if s.ctrl != nil {
			s.ctrl.ReloadBalancerSettings()
		}
		s.store.AddEvent("balancer", "ok", "настройки балансировщика обновлены", "{}")
		writeJSON(w, map[string]any{"ok": true, "settings": in})
		return
	}
	writeJSON(w, bs)
}