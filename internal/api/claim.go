package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kambarro/xkit-panel/internal/bot"
)

// Invite-link самопривязки клиента к TG-боту (P0 #4, panels-research 3x-ui Invite Link).
// Админ генерит токен → ссылка t.me/<bot>?start=<token> → клиент сам привязывается.

// claimLink — POST /api/clients/claim-link {email}: сгенерировать invite-ссылку.
func (s *Server) claimLink(w http.ResponseWriter, r *http.Request) {
	var body struct{ Email string `json:"email"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	cl, _ := s.store.GetClient(body.Email)
	if cl == nil { http.Error(w, "client not found", 404); return }
	// имя бота для ссылки (из settings или env)
	botUsername := s.store.GetSetting("tg_bot_username", "")
	token := bot.GenerateClaimToken()
	if _, err := s.store.DB().Exec(`UPDATE clients SET tg_claim_token=?, updated_at=strftime('%s','now') WHERE email=?`, token, body.Email); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	link := ""
	if botUsername != "" {
		link = fmt.Sprintf("https://t.me/%s?start=%s", botUsername, token)
	}
	s.store.AddEvent("tg_claim", "ok", "invite-link создан для "+body.Email, "{}")
	writeJSON(w, map[string]any{"ok": true, "email": body.Email, "token": token, "link": link, "bot_username": botUsername})
}

// unlinkTG — POST /api/clients/unlink-tg {email}: отвязать Telegram клиента.
func (s *Server) unlinkTG(w http.ResponseWriter, r *http.Request) {
	var body struct{ Email string `json:"email"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	if _, err := s.store.DB().Exec(`UPDATE clients SET tg_chat_id=0, tg_claim_token='', updated_at=strftime('%s','now') WHERE email=?`, body.Email); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("tg_claim", "ok", "Telegram отвязан от "+body.Email, "{}")
	writeJSON(w, map[string]any{"ok": true})
}