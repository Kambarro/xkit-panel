package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/kambarro/xkit-panel/internal/store"
)

// Настройки ноды: priority/price/country/name. УРОК (QA): не было API+UI смены
// приоритета/цены/страны ноды (openNodeBilling — про трафик-бюджет, не про это).
// POST /api/nodes/settings {id, priority?, price?, country?, name?}
// Смена страны → country_code из нод + пересчёт назначений клиентов этой страны.
func (s *Server) nodeSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string   `json:"id"`
		Priority *int     `json:"priority"`
		Price    *float64 `json:"price"`
		Country  string   `json:"country"`
		Name     string   `json:"name"`
		Expiry   *int64   `json:"expiry"` // unix ts, 0 = бессрочно
		Note     *string  `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "id обязателен", 400)
		return
	}
	n := s.getNode(req.ID)
	if n == nil {
		http.Error(w, "нода не найдена", 404)
		return
	}
	if req.Priority != nil {
		n.Priority = *req.Priority
	}
	if req.Price != nil {
		n.Price = *req.Price
	}
	if req.Name != "" {
		n.Name = req.Name
	}
	if req.Expiry != nil {
		n.Expiry = *req.Expiry
	}
	if req.Note != nil {
		n.Note = *req.Note
	}
	countryChanged := false
	if req.Country != "" && !strings.EqualFold(req.Country, n.Country) {
		newCountry := strings.ToUpper(req.Country)
		// УРОК (QA): стабильный код страны из country_codes (не выводить из нод —
		// иначе смена страны туда-обратно меняет код и ломает старые UUID клиентов).
		code, err := s.store.CountryCode(newCountry)
		if err != nil || code == 0 {
			http.Error(w, "не удалось выдать код страны", 500)
			return
		}
		n.Country = newCountry
		n.CountryCode = code
		countryChanged = true
	}
	if err := s.store.UpsertNode(*n); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.store.AddEvent("node_settings", "ok", fmt.Sprintf("нода %s: priority=%d price=%.2f country=%s", n.ID, n.Priority, n.Price, n.Country), "{}")
	// смена страны → пересчитать назначения (клиенты старой страны могли потерять ноду)
	if countryChanged && s.ctrl != nil {
		s.ctrl.SyncRulesNow(r.Context())
	}
	writeJSON(w, map[string]any{"ok": true, "node": n})
}

// nodeToggle — POST /api/nodes/toggle {id, enabled}: вкл/выкл ноду без удаления.
// УРОК (QA): не было способа временно отключить ноду (только delete).
// Выкл → клиенты failover на другие ноды; вкл → возврат sticky.
func (s *Server) nodeToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "id обязателен", 400)
		return
	}
	n := s.getNode(body.ID)
	if n == nil {
		http.Error(w, "нода не найдена", 404)
		return
	}
	en := 0
	if body.Enabled {
		en = 1
	}
	s.store.DB().Exec(`UPDATE nodes SET enabled=? WHERE id=?`, en, body.ID)
	state := "выключена"
	if body.Enabled {
		state = "включена"
	}
	s.store.AddEvent("node_toggle", "ok", fmt.Sprintf("нода %s %s", body.ID, state), "{}")
	if s.ctrl != nil {
		s.ctrl.SyncRulesNow(r.Context())
	}
	writeJSON(w, map[string]any{"ok": true, "id": body.ID, "enabled": body.Enabled})
}

func (s *Server) getNode(id string) *store.Node {
	rows, err := s.store.DB().Query(`SELECT id,name,country,country_code,priority,price,host,port,tunnel,tunnel_cfg,health,health_fails,expiry,enabled,capacity,latency_ms,uptime_pct,quality_score,note FROM nodes WHERE id=?`, id)
	if err != nil {
		return nil
	}
	defer rows.Close()
	if !rows.Next() {
		return nil
	}
	var n store.Node
	var en int
	if err := rows.Scan(&n.ID, &n.Name, &n.Country, &n.CountryCode, &n.Priority, &n.Price, &n.Host, &n.Port, &n.Tunnel, &n.TunnelCfg, &n.Health, &n.HealthFails, &n.Expiry, &en, &n.Capacity, &n.LatencyMs, &n.UptimePct, &n.QualityScore, &n.Note); err != nil {
		return nil
	}
	n.Enabled = en == 1
	return &n
}