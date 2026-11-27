package api

import (
	"encoding/json"
	"net/http"

	"github.com/kambarro/xkit-panel/internal/store"
)

// Дефолт-маршрутизация владельца (админ, Настройки → Маршрутизация по умолчанию).
// GET /api/routing/default, POST /api/routing/default, POST /api/routing/default/reset.
// Базовый набор для ВСЕХ клиентов (geoip/geosite/domain), хранится в БД.

func (s *Server) defaultRouting(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var dr store.DefaultRouting
		if err := json.NewDecoder(r.Body).Decode(&dr); err != nil {
			http.Error(w, err.Error(), 400); return
		}
		if err := s.store.SetDefaultRouting(dr); err != nil {
			http.Error(w, err.Error(), 500); return
		}
		s.store.AddEvent("routing", "ok", "дефолт-маршрутизация обновлена админом", "{}")
		writeJSON(w, map[string]any{"ok": true, "routing": dr})
		return
	}
	writeJSON(w, s.store.DefaultRouting())
}

func (s *Server) resetDefaultRouting(w http.ResponseWriter, r *http.Request) {
	dr := store.BuiltinDefaultRouting()
	if err := s.store.SetDefaultRouting(dr); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("routing", "ok", "дефолт-маршрутизация сброшена к встроенной", "{}")
	writeJSON(w, map[string]any{"ok": true, "routing": dr})
}