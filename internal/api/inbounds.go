package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"github.com/kambarro/xkit-panel/internal/store"
)

// execCommand — запуск команды с выводом (для xray x25519).
func execCommand(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// randHex — случайная hex-строка (shortId, ws path, grpc serviceName).
func randHex(n int) string {
	return hex.EncodeToString(randBytes(n))
}

// inboundsAPI — управление протоколами мастера (этап A: REALITY + база для любых).
// УРОК (владелец): не ограничены 3X-UI — protocol/network/security любые из Xray 26.x.
// SQLite = источник правды; config мастера + gRPC AddInbound/RemoveInbound горячо.

// listInbounds — GET /api/inbounds: список протоколов мастера.
func (s *Server) listInbounds(w http.ResponseWriter, r *http.Request) {
	ibs, err := s.store.AllInbounds()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	type iv struct {
		Tag string `json:"tag"`; Protocol string `json:"protocol"`; Port int `json:"port"`
		Network string `json:"network"`; Security string `json:"security"`; Enabled bool `json:"enabled"`
		Clients int `json:"clients"`
		Hidden bool `json:"hidden"`; PublicPort int `json:"public_port"`
		Mask string `json:"mask"`; MaskRu string `json:"mask_ru"`; MaskEn string `json:"mask_en"`
	}
	var out []iv
	for _, ib := range ibs {
		if ib.Tag == dispatcherTag { continue } // служебный — не показываем
		lvl, ru, en := maskBadge(ib)
		out = append(out, iv{ib.Tag, ib.Protocol, ib.Port, ib.Network, ib.Security, ib.Enabled, len(ib.Clients()), ib.Hidden, ib.ClientPort(), lvl, ru, en})
	}
	if out == nil { out = []iv{} }
	writeJSON(w, out)
}

// createInbound — POST /api/inbounds: создать протокол (горячо через gRPC).
// Тело: {protocol, port, network, security, reality:{dest,sni,...} или tls:{...}}.
// Ключи REALITY генерируются автоматически если не заданы.
func (s *Server) createInbound(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		Network  string `json:"network"`
		Security string `json:"security"`
		Dest     string `json:"dest"`     // REALITY dest (цель маскировки)
		SNI      string `json:"sni"`      // REALITY serverNames
		Tag      string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400); return
	}
	// валидация (урок: на границе доверия)
	if body.Protocol == "" { body.Protocol = "vless" }
	if body.Port == 0 { http.Error(w, "port required", 400); return }
	if body.Port < 1 || body.Port > 65535 { http.Error(w, "port 1..65535", 400); return }
	if body.Network == "" { body.Network = "tcp" }
	if body.Security == "" { body.Security = "reality" }
	validProto := map[string]bool{"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "hysteria2": true, "dokodemo-door": true}
	if !validProto[body.Protocol] { http.Error(w, "unsupported protocol: "+body.Protocol, 400); return }
	// порт не занят?
	var cnt int
	s.store.DB().QueryRow(`SELECT COUNT(*) FROM inbounds WHERE port=?`, body.Port).Scan(&cnt)
	if cnt > 0 { http.Error(w, fmt.Sprintf("порт %d уже занят", body.Port), 400); return }
	if body.Tag == "" { body.Tag = fmt.Sprintf("%s-%s-%d", body.Protocol, body.Security, body.Port) }
	if existing, _ := s.store.GetInbound(body.Tag); existing != nil {
		http.Error(w, "tag уже существует: "+body.Tag, 400); return
	}
	// hysteria2 — отдельный код-путь (xray proxy/hysteria v2, QUIC+salamander, per-user auth)
	if body.Protocol == "hysteria2" {
		s.createHysteria2Inbound(w, r, body.Port, body.Tag, body.SNI)
		return
	}

	// соберём settings/stream по протоколу
	settings := map[string]any{"clients": []any{}, "decryption": "none"}
	stream := map[string]any{"network": body.Network}
	// УРОК (QA): shadowsocks — НЕ vless-шаблон. SS2022: password = base64(16 байт) для aes-128-gcm.
	if body.Protocol == "shadowsocks" {
		ssPass := base64.StdEncoding.EncodeToString(randBytes(16))
		settings = map[string]any{
			"method": "2022-blake3-aes-128-gcm",
			"password": ssPass,
			"network": "tcp,udp",
		}
	}
	switch body.Security {
	case "reality":
		dest := body.Dest
		if dest == "" { dest = "127.0.0.1:8443" } // self-steal под свой camo (дефолт)
		sni := body.SNI
		if sni == "" { sni = s.domain }
		// ключи REALITY: генерируем x25519 (через xray CLI на мастере)
		priv, pub, err := genRealityKeys()
		if err != nil { http.Error(w, "reality keys: "+err.Error(), 500); return }
		sid := randHex(4)
		stream["security"] = "reality"
		stream["realitySettings"] = map[string]any{
			"show": false, "dest": dest, "xver": 0,
			"serverNames": []string{sni}, "privateKey": priv, "shortIds": []string{sid},
		}
		// сохраним pub для подписок (settings)
		settings["realityPub"] = pub
		settings["realitySid"] = sid
		settings["realitySni"] = sni
	case "tls":
		stream["security"] = "tls"
		stream["tlsSettings"] = map[string]any{
			"certificates": []any{map[string]any{
				"certificateFile": "/etc/letsencrypt/live/" + s.domain + "/fullchain.pem",
				"keyFile":         "/etc/letsencrypt/live/" + s.domain + "/privkey.pem",
			}},
		}
	default:
		stream["security"] = "none"
	}
	// transport-specific
	switch body.Network {
	case "ws":
		stream["wsSettings"] = map[string]any{"path": "/" + randHex(6)}
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": randHex(6)}
	case "xhttp", "splithttp":
		stream["xhttpSettings"] = map[string]any{"path": "/" + randHex(6), "mode": "auto"}
	}

	settingsJSON, _ := json.Marshal(settings)
	streamJSON, _ := json.Marshal(stream)
	ib := store.Inbound{
		Tag: body.Tag, Protocol: body.Protocol, Port: body.Port, Listen: "0.0.0.0",
		Network: body.Network, Security: body.Security,
		Settings: string(settingsJSON), Stream: string(streamJSON), Enabled: true,
	}
	// горячо через gRPC (если Xray доступен)
	if s.xray != nil {
		inboundJSON := buildInboundJSON(ib)
		if err := s.xray.AddInbound(r.Context(), inboundJSON); err != nil {
			http.Error(w, "gRPC AddInbound: "+err.Error(), 500); return
		}
	}
	if err := s.store.UpsertInbound(ib); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("inbound_created", "ok", fmt.Sprintf("протокол %s создан (%s:%d, %s/%s)", body.Tag, body.Protocol, body.Port, body.Network, body.Security), "{}")
	// auto_add: новый протокол добавляется в группы с auto_add=1 (урок QA: не только toggle).
	if s.store.InboundAutoAdd(body.Tag) {
		s.store.AddProtocolToAutoAddSquads(body.Tag)
	}
	// маскировка по умолчанию: прячущиеся TCP-протоколы сразу за 443 (без редактирования)
	if hideable(ib.Protocol, ib.Network) {
		if err := s.hideInbound(r, &ib); err != nil {
			s.store.AddEvent("masking", "warn", fmt.Sprintf("скрыть %s за 443: %v", ib.Tag, err), "{}")
		} else {
			s.store.AddEvent("masking", "ok", fmt.Sprintf("%s спрятан за 443 (внутренний :%d)", ib.Tag, ib.Port), "{}")
		}
	}
	s.syncFirewall() // автоматика UFW: открыли порт нового протокола (hidden — не открывается)
	writeJSON(w, map[string]any{"ok": true, "inbound": ib})
}

// deleteInbound — POST /api/inbounds/delete: удалить протокол (горячо).
func (s *Server) deleteInbound(w http.ResponseWriter, r *http.Request) {
	var body struct{ Tag string `json:"tag"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Tag == "" {
		http.Error(w, "tag required", 400); return
	}
	ib, _ := s.store.GetInbound(body.Tag)
	if ib == nil { http.Error(w, "inbound not found", 404); return }
	// защита: не удалить api-inbound (gRPC) и последний клиентский
	if body.Tag == "api-in" || body.Tag == "api" {
		http.Error(w, "нельзя удалить служебный api-inbound", 400); return
	}
	if s.xray != nil {
		if err := s.xray.RemoveInbound(r.Context(), body.Tag); err != nil {
			// не фатально: mungkin уже удалён из Xray — продолжаем чистить базу
			s.store.AddEvent("inbound_delete", "warn", "gRPC RemoveInbound: "+err.Error(), "{}")
		}
	}
	s.store.DeleteInbound(body.Tag)
	// УРОК (QA): убрать tag из наборов групп и override клиентов (висячие ссылки).
	s.store.RemoveProtocolEverywhere(body.Tag)
	s.AddEventWithRollback("inbound_deleted", "ok", "протокол "+body.Tag+" удалён", RollbackSnapshot{
		Entity: "inbound", ID: body.Tag, Action: "delete",
		Before: map[string]any{"tag": ib.Tag, "protocol": ib.Protocol, "port": ib.Port, "network": ib.Network, "security": ib.Security, "settings": ib.Settings, "stream": ib.Stream, "enabled": ib.Enabled, "hidden": ib.Hidden},
	})
	s.syncFirewall() // автоматика UFW: закрыли порт удалённого протокола
	writeJSON(w, map[string]any{"ok": true, "deleted": body.Tag})
}

// buildInboundJSON — JSON для gRPC AddInbound.
// УРОК: hysteria2 в БД/подписках, но xray registry знает только "hysteria" (version 2 внутри).
func buildInboundJSON(ib store.Inbound) string {
	proto := ib.Protocol
	if proto == "hysteria2" {
		proto = "hysteria"
	}
	return buildInboundJSONProto(ib, proto)
}

// buildInboundJSONProto — с явным именем протокола для xray registry.
// УРОК: hysteria2 в БД/подписках, но xray registry знает только "hysteria" (version 2 внутри).
func buildInboundJSONProto(ib store.Inbound, proto string) string {
	// УРОК (аудит #2): version=2/hysteriaSettings/alpn=h3 обязательны на ЛЮБОМ
	// пути AddInbound (create/toggle/restore/sync) — нормализуем здесь, в корне.
	normalizeHysteria2(&ib, "")
	var settings, stream map[string]any
	json.Unmarshal([]byte(ib.Settings), &settings)
	json.Unmarshal([]byte(ib.Stream), &stream)
	// realityPub/Sid/Sni — служебные для подписок, не часть Xray settings
	delete(settings, "realityPub"); delete(settings, "realitySid"); delete(settings, "realitySni")
	// subSni/subTls — служебные для подписок hidden-протоколов (аудит #6)
	delete(settings, "subSni"); delete(settings, "subTls")
	full := map[string]any{
		"tag": ib.Tag, "listen": ib.Listen, "port": ib.Port,
		"protocol": proto, "settings": settings, "streamSettings": stream,
	}
	data, _ := json.Marshal(full)
	return string(data)
}

// genRealityKeys — x25519 ключи через xray CLI (на мастере).
func genRealityKeys() (priv, pub string, err error) {
	out, e := execCommand("/usr/local/bin/xray", "x25519")
	if e != nil { return "", "", e }
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "PrivateKey:") {
			priv = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey:"))
		}
		if strings.HasPrefix(line, "Password") || strings.HasPrefix(line, "PublicKey:") {
			if i := strings.Index(line, ":"); i >= 0 {
				pub = strings.TrimSpace(line[i+1:])
			}
		}
	}
	if priv == "" || pub == "" { return "", "", fmt.Errorf("x25519 output parse failed") }
	return priv, pub, nil
}