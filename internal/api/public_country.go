package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/kambarro/xkit-panel/internal/store"
)

// Публичный выбор страны выхода на странице подписки (без auth, по subId —
// secret-URL подписки, тот же доступ что чтение). GET → текущая страна +
// доступные; POST {country} → clients.country (единственный флаг) +
// PushAssignment (горячо, базовое per-user правило). "any" = лучшая нода
// среди всех. Безопасность: secret-URL + rate-limit 1 смена/10сек + валидация
// (страна среди живых нод) + аудит — в store.ChangeClientCountry (единая точка).

// GET/POST /<prefix>/<subId>/country
func (s *Server) PublicClientCountry(w http.ResponseWriter, r *http.Request, subID string) {
	var email, country string
	var code uint32
	err := s.store.DB().QueryRow(`SELECT email,country,country_code FROM clients WHERE sub_id=? AND enabled=1`, subID).Scan(&email, &country, &code)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		// доступные страны из живых включённых нод; код — КАНОН country_codes
		// (УРОК QA BUG-1/7: nodes.country_code рассинхронизирован — US=1=NL).
		type cEntry struct {
			Country string `json:"country"`
			Code    uint32 `json:"code"`
		}
		var avail []cEntry
		rows, err := s.store.DB().Query(`SELECT DISTINCT n.country, COALESCE(cc.code, n.country_code) FROM nodes n LEFT JOIN country_codes cc ON cc.country=n.country WHERE n.enabled=1 AND COALESCE(cc.code, n.country_code)>0 ORDER BY n.country`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var c cEntry
				rows.Scan(&c.Country, &c.Code)
				avail = append(avail, c)
			}
		}
		cur := country
		if cur == "" {
			cur = "any"
		}
		// текущий код клиента тоже из канона (в БД мог залипнуть старый)
		if cur != "any" {
			if cc, _ := s.store.LookupCountryCode(cur); cc > 0 {
				code = cc
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"country": cur, "code": code, "available": avail})
		return
	}
	if r.Method == http.MethodPost {
		var body struct {
			Country string `json:"country"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		// единая точка: нормализация/валидация/rate-limit(10с)/запись/аудит
		newCountry := strings.TrimSpace(body.Country)
		if newCountry == "" || strings.EqualFold(newCountry, "any") {
			newCountry = "any"
		}
		newCode, err := s.store.ChangeClientCountry(email, newCountry, 10, "subscription")
		if errors.Is(err, store.ErrCountryRateLimit) {
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		}
		if errors.Is(err, store.ErrCountryUnavailable) {
			http.Error(w, err.Error(), 400)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		// горячо: базовое per-user правило на лучшую ноду выбранной страны (any → всех)
		if s.ctrl != nil {
			if _, err := s.ctrl.PushAssignment(r.Context(), email, newCountry); err != nil {
				s.store.AddEvent("country_change", "warn", fmt.Sprintf("%s → %s: назначение не удалось: %v", email, newCountry, err), "{}")
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "country": newCountry, "code": newCode})
		return
	}
	http.Error(w, "method not allowed", 405)
}