package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// userProto — протоколы с per-user account (gRPC AddUser/RemoveUser).
// vless/trojan/vmess — uuid/пароль на клиента; hysteria2 — per-user auth=uuid;
// shadowsocks — общий пароль в settings (не per-user).
func userProto(p string) bool {
	return p == "vless" || p == "trojan" || p == "vmess" || p == "hysteria2"
}

// Per-client набор протоколов (вариант B: группы + override). Требование владельца:
// «как в 3xui выбрать доступные протоколы каждому; новый — все; группы семья/роутеры;
// реальный запрет — убирать из inbound». Приоритет: свой набор > группа > все включённые.

// GET /api/clients/protocols?email — эффективный набор + источник + все доступные протоколы.
func (s *Server) getClientProtocols(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email обязателен", 400)
		return
	}
	eff, source := s.store.EffectiveProtocols(email)
	override := s.store.ClientProtocols(email)
	// все включённые протоколы (для UI выбора)
	type proto struct {
		Tag      string `json:"tag"`
		Protocol string `json:"protocol"`
		Network  string `json:"network"`
		Security string `json:"security"`
		Port     int    `json:"port"`
		AutoAdd  bool   `json:"auto_add"`
	}
	var all []proto
	ibs, _ := s.store.AllInbounds()
	for _, ib := range ibs {
		if !ib.Enabled || ib.Tag == "api-in" || ib.Tag == "api" {
			continue
		}
		all = append(all, proto{ib.Tag, ib.Protocol, ib.Network, ib.Security, ib.Port, s.store.InboundAutoAdd(ib.Tag)})
	}
	var squadID string
	s.store.DB().QueryRow(`SELECT squad_id FROM clients WHERE email=?`, email).Scan(&squadID)
	writeJSON(w, map[string]any{
		"email": email, "effective": eff, "source": source,
		"override": override, "squad_id": squadID, "available": all,
	})
}

// POST /api/clients/protocols {email, protocols:[]|null} — задать свой набор (null/[]=наследовать).
// Реальный запрет: синхронизирует inbound'ы — добавляет в разрешённые, убирает из запрещённых.
func (s *Server) setClientProtocols(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email     string   `json:"email"`
		Protocols []string `json:"protocols"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email обязателен", 400)
		return
	}
	cl, _ := s.store.GetClient(body.Email)
	if cl == nil {
		http.Error(w, "клиент не найден", 404)
		return
	}
	s.store.SetClientProtocols(body.Email, body.Protocols)
	s.syncClientInboundAccess(r, body.Email, cl.UUID)
	src := "наследует"
	if body.Protocols != nil {
		src = fmt.Sprintf("свой набор (%d)", len(body.Protocols))
	}
	s.store.AddEvent("client_protocols", "ok", fmt.Sprintf("%s: протоколы — %s", body.Email, src), "{}")
	eff, source := s.store.EffectiveProtocols(body.Email)
	writeJSON(w, map[string]any{"ok": true, "email": body.Email, "effective": eff, "source": source})
}

// syncClientInboundAccess — реальный запрет: клиент в inbound только разрешённых протоколов.
// Добавляет в разрешённые vless-inbound, убирает из запрещённых (горячо gRPC).
func (s *Server) syncClientInboundAccess(r *http.Request, email, uuid string) {
	if s.xray == nil {
		return
	}
	ibs, _ := s.store.AllInbounds()
	for _, ib := range ibs {
		if !ib.Enabled || !userProto(ib.Protocol) || ib.Tag == "api-in" || ib.Tag == "api" {
			continue
		}
		// hy2: доступ пересозданием с clients[] (аудит #2, персист в БД)
		if ib.Protocol == "hysteria2" || ib.Protocol == "hysteria" {
			if _, _, err := s.syncHysteria2Access(r.Context(), &ib); err != nil {
				s.store.AddEvent("client_sync", "warn", fmt.Sprintf("hy2 sync %s: %v", ib.Tag, err), "{}")
			}
			continue
		}
		if s.store.ProtocolAllowed(email, ib.Tag) {
			flow := ""
			if (ib.Network == "tcp" || ib.Network == "") && (ib.Security == "reality" || ib.Security == "tls") {
				flow = "xtls-rprx-vision"
			}
			if err := s.xray.AddUserProto(r.Context(), ib.Tag, email, uuid, flow, ib.Protocol); err != nil && !strings.Contains(err.Error(), "already") {
				s.store.AddEvent("client_sync", "warn", fmt.Sprintf("AddUser %s в %s: %v", email, ib.Tag, err), "{}")
			}
		} else {
			// реальный запрет: убрать из inbound (ссылка убрана + uuid не авторизуется)
			if err := s.xray.RemoveUser(r.Context(), ib.Tag, email); err != nil {
				s.store.AddEvent("client_sync", "warn", fmt.Sprintf("RemoveUser %s из %s: %v", email, ib.Tag, err), "{}")
			}
		}
	}
}