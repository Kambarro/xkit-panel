package api

import (
	"encoding/json"
	"net/http"
)

// Webhook-настройки (P1 #14). GET/POST /api/webhook, POST /api/webhook/test.
// Хранится в settings: webhook_url, webhook_secret, webhook_events (CSV kind'ов, пусто=все).

func (s *Server) webhookStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"url":    s.store.GetSetting("webhook_url", ""),
		"secret": s.store.GetSetting("webhook_secret", ""),
		"events": s.store.GetSetting("webhook_events", ""),
		"enabled": s.store.GetSetting("webhook_url", "") != "",
	})
}

func (s *Server) webhookConfigure(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL    string `json:"url"`
		Secret string `json:"secret"`
		Events string `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400); return
	}
	s.store.SetSetting("webhook_url", body.URL)
	s.store.SetSetting("webhook_secret", body.Secret)
	s.store.SetSetting("webhook_events", body.Events)
	s.store.AddEvent("webhook_config", "ok", "webhook настроем", "{}")
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) webhookTest(w http.ResponseWriter, r *http.Request) {
	if s.webhook == nil {
		http.Error(w, "webhook не инициализирован", 500); return
	}
	if err := s.webhook.Test(); err != nil {
		http.Error(w, err.Error(), 400); return
	}
	writeJSON(w, map[string]any{"ok": true, "sent": true})
}