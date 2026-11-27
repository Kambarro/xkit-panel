package api

import (
	"encoding/json"
	"net/http"

	"github.com/kambarro/xkit-panel/internal/store"
)

// HWID-лимит устройств + управление устройствами (P0 #1, стандарт Happ x-hwid).
// УРОК (panels-research): основа тарифов «на N устройств»; список с отвязкой.

// setHWIDLimit — POST /api/clients/hwid-limit {email, limit}.
func (s *Server) setHWIDLimit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Limit int    `json:"limit"` // 0 = без лимита
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	if body.Limit < 0 { body.Limit = 0 }
	if err := s.store.SetClientHWIDLimit(body.Email, body.Limit); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("client_hwid", "ok", "лимит устройств "+body.Email, "{}")
	writeJSON(w, map[string]any{"ok": true, "email": body.Email, "hwid_limit": body.Limit})
}

// clientDevices — GET /api/clients/devices?email=... : список устройств.
func (s *Server) clientDevices(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" { http.Error(w, "email required", 400); return }
	devs, err := s.store.Devices(email)
	if err != nil { http.Error(w, err.Error(), 500); return }
	if devs == nil { devs = []store.Device{} }
	writeJSON(w, map[string]any{"devices": devs, "limit": s.store.ClientHWIDLimit(email), "count": len(devs)})
}

// removeDevice — POST /api/clients/devices/remove {email, hwid}: отвязать устройство.
func (s *Server) removeDevice(w http.ResponseWriter, r *http.Request) {
	var body struct{ Email, HWID string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.HWID == "" {
		http.Error(w, "email and hwid required", 400); return
	}
	if err := s.store.RemoveDevice(body.Email, body.HWID); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("client_hwid", "ok", "устройство отвязано "+body.Email, "{}")
	writeJSON(w, map[string]any{"ok": true})
}

// setIPLimit — POST /api/clients/ip-limit {email, limit} (P1 #11).
func (s *Server) setIPLimit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Limit int    `json:"limit"` // 0 = без лимита
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	if body.Limit < 0 { body.Limit = 0 }
	if err := s.store.SetClientIPLimit(body.Email, body.Limit); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("client_ip", "ok", "лимит IP "+body.Email, "{}")
	writeJSON(w, map[string]any{"ok": true, "email": body.Email, "ip_limit": body.Limit})
}