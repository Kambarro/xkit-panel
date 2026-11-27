package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

// Группы доступа/тарифы (P1 #8, Remnawave internal squads / Kitsune группы).
// группа = набор inbounds (протоколов) + дефолтные лимиты. Bulk-назначение клиентов.
// Подписка клиента фильтруется по inbounds группы (если задана) — тариф «семья/премиум».

// listSquads — GET /api/squads.
func (s *Server) listSquads(w http.ResponseWriter, r *http.Request) {
	squads, err := s.store.AllSquads()
	if err != nil { http.Error(w, err.Error(), 500); return }
	if squads == nil { squads = []store.Squad{} }
	// добавим count клиентов каждой группы
	type sqView struct {
		store.Squad
		Clients int `json:"clients"`
	}
	var out []sqView
	for _, sq := range squads {
		cls, _ := s.store.SquadClients(sq.ID)
		out = append(out, sqView{sq, len(cls)})
	}
	if out == nil { out = []sqView{} }
	writeJSON(w, out)
}

// saveSquad — POST /api/squads {id?, name, inbounds, country, hwid_limit, quota_gb, expiry_days, autorenew_mode}.
func (s *Server) saveSquad(w http.ResponseWriter, r *http.Request) {
	var sq store.Squad
	if err := json.NewDecoder(r.Body).Decode(&sq); err != nil || sq.Name == "" {
		http.Error(w, "name required", 400); return
	}
	if sq.ID == "" { sq.ID = "squad-" + randHex(4) }
	if sq.Autorenew == "" { sq.Autorenew = "none" }
	if err := s.store.UpsertSquad(sq); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("squad", "ok", "группа "+sq.Name+" сохранена", "{}")
	writeJSON(w, map[string]any{"ok": true, "squad": sq})
}

// deleteSquad — POST /api/squads/delete {id}.
func (s *Server) deleteSquad(w http.ResponseWriter, r *http.Request) {
	var body struct{ ID string `json:"id"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "id required", 400); return
	}
	if err := s.store.DeleteSquad(body.ID); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("squad", "ok", "группа удалена (клиенты отвязаны)", "{}")
	writeJSON(w, map[string]any{"ok": true})
}

// assignSquad — POST /api/squads/assign {email, squad_id}: назначить клиента в группу
// + применить дефолты группы (hwid/quota/expiry/autorenew/country).
func (s *Server) assignSquad(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email   string `json:"email"`
		SquadID string `json:"squad_id"` // "" = убрать из группы
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	cl, _ := s.store.GetClient(body.Email)
	if cl == nil { http.Error(w, "client not found", 404); return }
	if err := s.store.AssignSquad(body.Email, body.SquadID); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	// применим дефолты группы
	if body.SquadID != "" {
		sq, _ := s.store.GetSquad(body.SquadID)
		if sq != nil {
			s.store.SetClientHWIDLimit(body.Email, sq.HWIDLimit)
			var quota int64
			if sq.QuotaGB > 0 { quota = int64(sq.QuotaGB) * 1024 * 1024 * 1024 }
			var expiry int64
			if sq.ExpiryDays > 0 { expiry = time.Now().AddDate(0, 0, sq.ExpiryDays).Unix() }
			s.store.DB().Exec(`UPDATE clients SET quota_bytes=?, expiry=? WHERE email=?`, quota, expiry, body.Email)
			s.store.SetAutoRenew(body.Email, sq.Autorenew, 30, false)
			if sq.Country != "" {
				// канон country_codes (QA BUG-1/7)
				code, _ := s.store.LookupCountryCode(sq.Country)
				s.store.DB().Exec(`UPDATE clients SET country=?, country_code=? WHERE email=?`, sq.Country, code, body.Email)
			}
		}
	}
	s.store.AddEvent("squad", "ok", fmt.Sprintf("клиент %s → группа %s", body.Email, body.SquadID), "{}")
	// реальный запрет: пересинхронизировать доступ к inbound по новому effective set
	s.syncClientInboundAccess(r, body.Email, cl.UUID)
	writeJSON(w, map[string]any{"ok": true, "email": body.Email, "squad_id": body.SquadID})
}

// bulkAssignSquad — POST /api/squads/bulk {squad_id, emails[]}: массовое назначение.
func (s *Server) bulkAssignSquad(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SquadID string   `json:"squad_id"`
		Emails  []string `json:"emails"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400); return
	}
	n := 0
	for _, email := range body.Emails {
		if err := s.store.AssignSquad(email, body.SquadID); err == nil {
			n++
			if cl, _ := s.store.GetClient(email); cl != nil {
				s.syncClientInboundAccess(r, email, cl.UUID) // реальный запрет
			}
		}
	}
	s.store.AddEvent("squad", "ok", fmt.Sprintf("bulk: %d клиентов → группа %s", n, body.SquadID), "{}")
	writeJSON(w, map[string]any{"ok": true, "assigned": n})
}