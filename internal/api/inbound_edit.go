package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Редактирование установленного протокола (advanced, как в 3x-ui).
// GET /api/inbounds/get?tag → полные параметры для формы.
// POST /api/inbounds/update {tag, port, network, security, dest, sni, path, serviceName, regenKeys}
// Горячо: RemoveInbound + AddInbound с новыми параметрами, клиенты сохраняются.

func (s *Server) getInbound(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("tag")
	ib, _ := s.store.GetInbound(tag)
	if ib == nil { http.Error(w, "inbound not found", 404); return }
	var settings, stream map[string]any
	json.Unmarshal([]byte(ib.Settings), &settings)
	json.Unmarshal([]byte(ib.Stream), &stream)
	dest, sni, path, serviceName := "", "", "", ""
	if rs, ok := stream["realitySettings"].(map[string]any); ok {
		dest, _ = rs["dest"].(string)
		if sns, ok := rs["serverNames"].([]any); ok && len(sns) > 0 { sni, _ = sns[0].(string) }
	}
	if ws, ok := stream["wsSettings"].(map[string]any); ok { path, _ = ws["path"].(string) }
	if gs, ok := stream["grpcSettings"].(map[string]any); ok { serviceName, _ = gs["serviceName"].(string) }
	if xs, ok := stream["xhttpSettings"].(map[string]any); ok { path, _ = xs["path"].(string) }
	writeJSON(w, map[string]any{
		"tag": ib.Tag, "protocol": ib.Protocol, "port": ib.Port,
		"network": ib.Network, "security": ib.Security, "enabled": ib.Enabled,
		"hidden": ib.Hidden, "public_port": ib.ClientPort(),
		"dest": dest, "sni": sni, "path": path, "service_name": serviceName,
		"clients": len(ib.Clients()),
		"reality_pub": settings["realityPub"], "reality_sid": settings["realitySid"],
		"fingerprint": settings["fingerprint"],
	})
}

func (s *Server) updateInbound(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tag         string `json:"tag"`
		Port        int    `json:"port"`
		Network     string `json:"network"`
		Security    string `json:"security"`
		Dest        string `json:"dest"`
		SNI         string `json:"sni"`
		Path        string `json:"path"`
		ServiceName string `json:"service_name"`
		RegenKeys   bool   `json:"regen_keys"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Tag == "" {
		http.Error(w, "tag required", 400); return
	}
	if body.Tag == "api-in" || body.Tag == "api" {
		http.Error(w, "нельзя редактировать служебный api-inbound", 400); return
	}
	ib, _ := s.store.GetInbound(body.Tag)
	if ib == nil { http.Error(w, "inbound not found", 404); return }
	// snapshot для отката (разрушающее: смена security/network/regen keys)
	snapBefore := map[string]any{"tag": ib.Tag, "protocol": ib.Protocol, "port": ib.Port, "network": ib.Network, "security": ib.Security, "settings": ib.Settings, "stream": ib.Stream, "enabled": ib.Enabled, "hidden": ib.Hidden}
	// маскировка по умолчанию: hidden-протокол — порт менять нельзя (он cosmetic за 443)
	if !guardHiddenEdit(w, ib, body.Port) { return }

	var settings, stream map[string]any
	json.Unmarshal([]byte(ib.Settings), &settings)
	json.Unmarshal([]byte(ib.Stream), &stream)
	if settings == nil { settings = map[string]any{} }
	if stream == nil { stream = map[string]any{} }

	// порт: проверка занятости другим inbound
	if body.Port != 0 && body.Port != ib.Port {
		if body.Port < 1 || body.Port > 65535 { http.Error(w, "port 1..65535", 400); return }
		var cnt int
		s.store.DB().QueryRow(`SELECT COUNT(*) FROM inbounds WHERE port=? AND tag!=?`, body.Port, body.Tag).Scan(&cnt)
		if cnt > 0 { http.Error(w, fmt.Sprintf("порт %d уже занят", body.Port), 400); return }
		ib.Port = body.Port
	}
	// transport
	if body.Network != "" { ib.Network = body.Network }
	stream["network"] = ib.Network
	// transport-specific settings (сохраняем path если задан, иначе генерим)
	switch ib.Network {
	case "ws":
		path := body.Path
		if path == "" { if ws, ok := stream["wsSettings"].(map[string]any); ok { path, _ = ws["path"].(string) } }
		if path == "" { path = "/" + randHex(6) }
		stream["wsSettings"] = map[string]any{"path": path}
		delete(stream, "grpcSettings"); delete(stream, "xhttpSettings")
	case "grpc":
		sn := body.ServiceName
		if sn == "" { if gs, ok := stream["grpcSettings"].(map[string]any); ok { sn, _ = gs["serviceName"].(string) } }
		if sn == "" { sn = randHex(6) }
		stream["grpcSettings"] = map[string]any{"serviceName": sn}
		delete(stream, "wsSettings"); delete(stream, "xhttpSettings")
	case "xhttp", "splithttp":
		path := body.Path
		if path == "" { if xs, ok := stream["xhttpSettings"].(map[string]any); ok { path, _ = xs["path"].(string) } }
		if path == "" { path = "/" + randHex(6) }
		stream["xhttpSettings"] = map[string]any{"path": path, "mode": "auto"}
		delete(stream, "wsSettings"); delete(stream, "grpcSettings")
	default:
		delete(stream, "wsSettings"); delete(stream, "grpcSettings"); delete(stream, "xhttpSettings")
	}
	// security
	if body.Security != "" { ib.Security = body.Security }
	switch ib.Security {
	case "reality":
		rs, _ := stream["realitySettings"].(map[string]any)
		if rs == nil { rs = map[string]any{} }
		dest := body.Dest
		if dest == "" { dest, _ = rs["dest"].(string) }
		if dest == "" { dest = "127.0.0.1:8443" }
		sni := body.SNI
		if sni == "" { if sns, ok := rs["serverNames"].([]any); ok && len(sns) > 0 { sni, _ = sns[0].(string) } }
		if sni == "" { sni = s.domain }
		rs["dest"] = dest
		rs["serverNames"] = []string{sni}
		rs["show"] = false
		if body.RegenKeys || rs["privateKey"] == nil {
			priv, pub, err := genRealityKeys()
			if err != nil { http.Error(w, "reality keys: "+err.Error(), 500); return }
			sid := randHex(4)
			rs["privateKey"] = priv
			rs["shortIds"] = []string{sid}
			settings["realityPub"] = pub
			settings["realitySid"] = sid
		}
		settings["realitySni"] = sni
		stream["security"] = "reality"
		stream["realitySettings"] = rs
		delete(stream, "tlsSettings")
	case "tls":
		stream["security"] = "tls"
		if stream["tlsSettings"] == nil {
			stream["tlsSettings"] = map[string]any{"certificates": []any{map[string]any{
				"certificateFile": "/etc/letsencrypt/live/" + s.domain + "/fullchain.pem",
				"keyFile":         "/etc/letsencrypt/live/" + s.domain + "/privkey.pem",
			}}}
		}
		delete(stream, "realitySettings")
		delete(settings, "realityPub"); delete(settings, "realitySid"); delete(settings, "realitySni")
	default:
		stream["security"] = "none"
		delete(stream, "realitySettings"); delete(stream, "tlsSettings")
		delete(settings, "realityPub"); delete(settings, "realitySid"); delete(settings, "realitySni")
	}

	// fingerprint (uTLS, клиентский): сохраняется в settings, влияет на fp в ссылках подписки
	if body.Fingerprint != "" {
		settings["fingerprint"] = body.Fingerprint
	}

	settingsJSON, _ := json.Marshal(settings)
	streamJSON, _ := json.Marshal(stream)
	ib.Settings = string(settingsJSON)
	ib.Stream = string(streamJSON)
	// hy2: version=2/hysteriaSettings/network=hysteria обязательны (аудит #2)
	normalizeHysteria2(ib, s.domain)

	// горячо: Remove + Add. УРОК (QA): gRPC AddUser НЕ персистится в settings.clients БД —
	// после edit клиенты теряются. Пересобираем clients из effective set всех клиентов.
	if userProto(ib.Protocol) {
		var cls []any
		clients, _ := s.store.EnabledClients()
		for _, cl := range clients {
			if !s.store.ProtocolAllowed(cl.Email, body.Tag) { continue }
			c := map[string]any{"email": cl.Email}
			switch ib.Protocol {
			case "vless":
				c["id"] = cl.UUID
				if (ib.Network == "tcp" || ib.Network == "") && (ib.Security == "reality" || ib.Security == "tls") {
					c["flow"] = "xtls-rprx-vision"
				}
			case "trojan":
				c["password"] = cl.UUID
			case "vmess":
				c["id"] = cl.UUID
			case "hysteria2", "hysteria":
				// УРОК (аудит #2): hy2 clients = {auth,email} (account.Auth), не id
				c["auth"] = cl.UUID
			}
			cls = append(cls, c)
		}
		if cls == nil { cls = []any{} }
		settings["clients"] = cls
		settingsJSON, _ = json.Marshal(settings)
		ib.Settings = string(settingsJSON)
	}
	if s.xray != nil {
		s.xray.RemoveInbound(r.Context(), body.Tag) // игнорируем ошибку (мог отсутствовать)
		if err := s.xray.AddInbound(r.Context(), buildInboundJSON(*ib)); err != nil {
			http.Error(w, "gRPC AddInbound: "+err.Error(), 500); return
		}
	}
	if err := s.store.UpsertInbound(*ib); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	// откат только для разрушающих: regen keys, смена security/network
	destructive := body.RegenKeys || (body.Security != "" && body.Security != str(snapBefore["security"])) || (body.Network != "" && body.Network != str(snapBefore["network"]))
	if destructive {
		s.AddEventWithRollback("inbound_updated", "ok", fmt.Sprintf("протокол %s обновлён (%s:%d, %s/%s)", body.Tag, ib.Protocol, ib.Port, ib.Network, ib.Security), RollbackSnapshot{
			Entity: "inbound", ID: body.Tag, Action: "update", Before: snapBefore,
		})
	} else {
		s.store.AddEvent("inbound_updated", "ok", fmt.Sprintf("протокол %s обновлён (%s:%d, %s/%s)", body.Tag, ib.Protocol, ib.Port, ib.Network, ib.Security), "{}")
	}
	s.syncFirewall() // автоматика UFW: порт мог измениться
	writeJSON(w, map[string]any{"ok": true, "inbound": ib})
}

var _ = strings.TrimSpace