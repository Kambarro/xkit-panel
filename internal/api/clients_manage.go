package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// deleteClient — POST /api/clients/delete: удалить клиента (горячо из всех inbound + rules + БД).
// УРОК XKIT (round-trip): при удалении — убрать из ВСЕХ inbound, убрать routing rule, почистить assignments.
func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	var body struct{ Email string `json:"email"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	// убрать из всех включённых vless-inbound (горячо)
	if s.xray != nil {
		// УРОК (дедлок MaxOpenConns=1): сначала читаем все inbound в срез,
		// потом syncHysteria2Access (вложенные запросы к БД).
		ibs, _ := s.store.AllInbounds()
		for _, ib := range ibs {
			if !userProto(ib.Protocol) { continue }
			// hy2: пересоздание clients[] без удалённого (аудит #2)
			if ib.Protocol == "hysteria2" || ib.Protocol == "hysteria" {
				if ib.Enabled {
					s.syncHysteria2Access(r.Context(), &ib)
				}
				continue
			}
			if err := s.xray.RemoveUser(r.Context(), ib.Tag, body.Email); err != nil {
				// не фатально: юзера могло не быть в этом inbound
			}
		}
	}
	// убрать routing rules клиента + assignments (через syncAllRules — атомарно)
	s.store.DB().Exec(`DELETE FROM assignments WHERE email=?`, body.Email)
	// УРОК (QA BUG#24): удалить AWG-пир клиента (иначе осиротевший пир остаётся в сервере).
	if p, _ := s.store.GetAWGPeer(body.Email); p != nil {
		if s.awgMu != nil && s.awgMu.srv != nil {
			s.awgMu.srv.RemovePeer(p.PublicKey)
		}
		s.store.DeleteAWGPeer(body.Email)
	}
	cl, _ := s.store.GetClient(body.Email)
	if _, err := s.store.DB().Exec(`DELETE FROM clients WHERE email=?`, body.Email); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.DeleteTrafficTotal("client", body.Email) // lifetime-трафик удалённого клиента
	if s.ctrl != nil { s.ctrl.SyncRulesNow(r.Context()) }
	if cl != nil {
		s.AddEventWithRollback("client_deleted", "ok", "клиент "+body.Email+" удалён", RollbackSnapshot{
			Entity: "client", ID: body.Email, Action: "delete",
			Before: map[string]any{"email": cl.Email, "uuid": cl.UUID, "name": cl.Name, "sub_id": cl.SubID, "country": cl.Country, "country_code": cl.CountryCode, "enabled": cl.Enabled, "quota_bytes": cl.QuotaBytes, "expiry": cl.Expiry},
		})
	} else {
		s.store.AddEvent("client_deleted", "ok", "клиент "+body.Email+" удалён", "{}")
	}
	writeJSON(w, map[string]any{"ok": true, "deleted": body.Email})
}

// toggleClient — POST /api/clients/toggle: вкл/выкл клиента (горячо).
// enabled=false → RemoveUser из всех inbound (доступ закрыт) + enabled=0 в БД.
// enabled=true → AddUser во все включённые inbound + enabled=1.
func (s *Server) toggleClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email   string `json:"email"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	var uuid string
	var en int
	err := s.store.DB().QueryRow(`SELECT uuid,enabled FROM clients WHERE email=?`, body.Email).Scan(&uuid, &en)
	if err != nil { http.Error(w, "client not found", 404); return }

	if s.xray != nil {
		ibs, _ := s.store.AllInbounds()
		for _, ib := range ibs {
			if !userProto(ib.Protocol) { continue }
			// hy2: пересоздание clients[] (аудит #2)
			if ib.Protocol == "hysteria2" || ib.Protocol == "hysteria" {
				if ib.Enabled {
					s.syncHysteria2Access(r.Context(), &ib)
				}
				continue
			}
			if body.Enabled {
				if !ib.Enabled { continue }
				flow := ""
				if (ib.Network == "tcp" || ib.Network == "") && (ib.Security == "reality" || ib.Security == "tls") {
					flow = "xtls-rprx-vision"
				}
				s.xray.AddUserProto(r.Context(), ib.Tag, body.Email, uuid, flow, ib.Protocol)
			} else {
				s.xray.RemoveUser(r.Context(), ib.Tag, body.Email)
			}
		}
	}
	en = 0
	if body.Enabled { en = 1 }
	if _, err := s.store.DB().Exec(`UPDATE clients SET enabled=?, updated_at=strftime('%s','now') WHERE email=?`, en, body.Email); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	state := "отключён"
	if body.Enabled { state = "включён" }
	s.store.AddEvent("client_toggle", "ok", fmt.Sprintf("клиент %s %s", body.Email, state), "{}")
	writeJSON(w, map[string]any{"ok": true, "email": body.Email, "enabled": body.Enabled})
}

// renewClient — POST /api/clients/renew: продлить срок/квоту клиента.
func (s *Server) renewClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email      string `json:"email"`
		ExpiryDays int    `json:"expiry_days"` // добавить дней (0 = бессрочно)
		QuotaGB    int    `json:"quota_gb"`    // новая квота ГБ (0 = безлимит)
		ResetUsed  bool   `json:"reset_used"`  // сбросить использованный трафик
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	var expiry int64
	if body.ExpiryDays > 0 { expiry = time.Now().AddDate(0, 0, body.ExpiryDays).Unix() }
	var quota int64
	if body.QuotaGB > 0 { quota = int64(body.QuotaGB) * 1024 * 1024 * 1024 }
	if body.ResetUsed {
		s.store.DB().Exec(`UPDATE clients SET expiry=?, quota_bytes=?, used_bytes=0, enabled=1, updated_at=strftime('%s','now') WHERE email=?`, expiry, quota, body.Email)
	} else {
		s.store.DB().Exec(`UPDATE clients SET expiry=?, quota_bytes=?, enabled=1, updated_at=strftime('%s','now') WHERE email=?`, expiry, quota, body.Email)
	}
	// если был отключён по квоте/сроку — вернём в inbound
	if s.xray != nil {
		var uuid string
		s.store.DB().QueryRow(`SELECT uuid FROM clients WHERE email=?`, body.Email).Scan(&uuid)
		s.syncInboundUsers(r, body.Email, uuid)
	}
	s.store.AddEvent("client_renew", "ok", "клиент "+body.Email+" продлён", "{}")
	writeJSON(w, map[string]any{"ok": true, "email": body.Email, "expiry": expiry, "quota_bytes": quota})
}