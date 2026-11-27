package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/kambarro/xkit-panel/internal/antifilter"
	"github.com/kambarro/xkit-panel/internal/routing"
	"github.com/kambarro/xkit-panel/internal/store"
)

// Режим маршрутизации мастера (Настройки, expert): solo | ru-direct | antifilter.
// GET /api/routing/mode → {mode, effective, has_nodes, margin, always, conflicts, categories, antifilter}
// POST /api/routing/mode {mode?, margin?, always?} — переключение/правила владельца.
// POST /api/routing/antifilter/refresh — принудительное обновление blocked-списков.

// SetAntifilterManager — менеджер blocked-списков (ставится из main.go).
func (s *Server) SetAntifilterManager(m *antifilter.Manager) { s.afMgr = m }

func (s *Server) routingMode(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var body struct {
			Mode   *string               `json:"mode"`
			Margin *bool                 `json:"margin"`
			Always *routing.AlwaysRules  `json:"always"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if body.Mode != nil {
			mode := *body.Mode
			if mode != "" && mode != "solo" && mode != "ru-direct" && mode != "antifilter" {
				http.Error(w, "неизвестный режим (solo|ru-direct|antifilter|пусто=авто)", 400)
				return
			}
			if mode == "antifilter" {
				// antifilter недоступен в соло (нет нод) — решение владельца
				var n int
				s.store.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE enabled=1`).Scan(&n)
				if n == 0 {
					http.Error(w, "antifilter недоступен без нод (соло-режим)", 400)
					return
				}
				// пустой кеш → режим не включается молча (§5.2): требуем данные
				if s.afMgr == nil || !s.afMgr.Ready() {
					http.Error(w, "blocked-список ещё не загружен — нажмите «Обновить» и повторите (пустой кеш: режим не включается молча)", 409)
					return
				}
			}
			if err := s.store.SetRoutingMode(mode); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			s.store.AddEvent("routing", "ok", "режим маршрутизации: "+modeLabel(mode), "{}")
		}
		if body.Margin != nil {
			marginChanged := s.store.AntifilterMargin() != *body.Margin
			s.store.SetAntifilterMargin(*body.Margin)
			s.store.AddEvent("routing", "ok", "antifilter /24-margin: "+boolOnOff(*body.Margin), "{}")
			// QA AF-BUG-2: смена флага сразу пересобирает набор (в обе стороны),
			// не ждём 30-мин тика — Refresh форсирует регенерацию при смене состава.
			if marginChanged && s.afMgr != nil {
				ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
				if _, err := s.afMgr.RefreshNow(ctx); err != nil {
					log.Printf("antifilter: refresh после смены margin: %v", err)
				}
				cancel()
			}
		}
		if body.Always != nil {
			norm, err := routing.ValidateAlwaysRules(*body.Always)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if err := s.store.SetAlwaysRules(norm); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			s.store.AddEvent("routing", "ok", "always-правила обновлены", "{}")
		}
		// горячая пересборка правил мастера + подписки станут mode-aware при запросе
		if s.ctrl != nil {
			s.ctrl.SyncRulesNow(r.Context())
		}
	}
	var n int
	s.store.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE enabled=1`).Scan(&n)
	mode := s.store.RoutingMode()
	af := s.store.AntifilterState()
	resp := map[string]any{
		"mode":       mode,
		"effective":  s.store.EffectiveRoutingMode(n > 0),
		"has_nodes":  n > 0,
		"margin":     s.store.AntifilterMargin(),
		"always":     s.store.AlwaysRules(),
		"conflicts":  routing.AlwaysConflicts(s.store.AlwaysRules()),
		"categories": routing.AlwaysCategories(),
		"antifilter": af,
		"ready":      s.afMgr != nil && s.afMgr.Ready(),
	}
	if r.Method == http.MethodPost {
		resp["ok"] = true
	}
	writeJSON(w, resp)
}

func modeLabel(m string) string {
	switch m {
	case "solo":
		return "соло (всё напрямую)"
	case "ru-direct":
		return "РФ напрямую, остальное через ноды"
	case "antifilter":
		return "antifilter (заблокированное через ноды)"
	}
	return "авто"
}

func boolOnOff(b bool) string {
	if b {
		return "вкл"
	}
	return "выкл"
}

// antifilterRefresh — принудительный цикл обновления (кнопка UI).
func (s *Server) antifilterRefresh(w http.ResponseWriter, r *http.Request) {
	if s.afMgr == nil {
		http.Error(w, "antifilter manager не инициализирован", 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	st, err := s.afMgr.RefreshNow(ctx)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error(), "state": st})
		return
	}
	if s.ctrl != nil {
		s.ctrl.SyncRulesNow(ctx)
	}
	writeJSON(w, map[string]any{"ok": true, "state": st})
}

var _ = store.AntifilterState{}