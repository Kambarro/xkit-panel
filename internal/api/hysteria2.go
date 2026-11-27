package api

// Hysteria2 — починка мёртвого inbound (аудит #2).
// Корень: при пересоздании/миграциях терялись settings.version=2 и
// stream.hysteriaSettings{version:2} — xray registry protocol "hysteria"
// без них строит inbound без валидатора/users → auth всегда 404.
// Проверено по xray-core 26.x (модуль v1.260327.0 + main): proxy/hysteria
// Server.AddUser ЕСТЬ (validator.Add), worker передаёт валидатор в transport
// через ContextWithValidator — горячий AddUserOperation поддерживается.
// Но пересоздание inbound с clients[] надёжнее (персист в settings, переживает
// рестарт xray без gRPC-досинхронизации) — syncHysteria2Access делает
// RemoveInbound+AddInbound при изменении доступа.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kambarro/xkit-panel/internal/store"
)

// normalizeHysteria2 — восстанавливает обязательные поля hy2-inbound:
// settings.version=2, stream.hysteriaSettings{version:2}, stream.network=hysteria,
// tlsSettings.serverName (fallback: из cert-пути, затем домен мастера).
// Идемпотентно: существующие значения не трогает. true = были изменения.
func normalizeHysteria2(ib *store.Inbound, domain string) bool {
	if ib.Protocol != "hysteria2" && ib.Protocol != "hysteria" {
		return false
	}
	var settings, stream map[string]any
	json.Unmarshal([]byte(ib.Settings), &settings)
	json.Unmarshal([]byte(ib.Stream), &stream)
	if settings == nil {
		settings = map[string]any{}
	}
	if stream == nil {
		stream = map[string]any{}
	}
	changed := false
	if v, _ := settings["version"].(float64); v != 2 {
		settings["version"] = 2
		changed = true
	}
	if clients, ok := settings["clients"].([]any); !ok || clients == nil {
		settings["clients"] = []any{}
		changed = true
	}
	if stream["network"] != "hysteria" {
		stream["network"] = "hysteria"
		changed = true
	}
	if hy, ok := stream["hysteriaSettings"].(map[string]any); !ok || hy["version"] != float64(2) {
		stream["hysteriaSettings"] = map[string]any{"version": 2}
		changed = true
	}
	ts, _ := stream["tlsSettings"].(map[string]any)
	if ts == nil {
		ts = map[string]any{}
	}
	// ALPN h3 обязателен: hysteria transport = QUIC+HTTP/3, без alpn=["h3"]
	// TLS-handshake падает "no application protocol" (проверено E2E).
	if alpn, ok := ts["alpn"].([]any); !ok || len(alpn) == 0 || alpn[0] != "h3" {
		ts["alpn"] = []any{"h3"}
		changed = true
	}
	if sn, _ := ts["serverName"].(string); sn == "" {
		// serverName потерян при пересоздании — восстановим из cert-пути
		// (/etc/letsencrypt/live/<domain>/fullchain.pem), иначе домен мастера.
		sni := domain
		if certs, ok := ts["certificates"].([]any); ok && len(certs) > 0 {
			if c0, ok := certs[0].(map[string]any); ok {
				if cf, _ := c0["certificateFile"].(string); cf != "" {
					parts := strings.Split(cf, "/")
					for i, p := range parts {
						if p == "live" && i+1 < len(parts) && parts[i+1] != "" {
							sni = parts[i+1]
							break
						}
					}
				}
			}
		}
		if sni != "" {
			ts["serverName"] = sni
			changed = true
		}
	}
	stream["tlsSettings"] = ts
	if changed {
		sj, _ := json.Marshal(settings)
		stj, _ := json.Marshal(stream)
		ib.Settings = string(sj)
		ib.Stream = string(stj)
	}
	return changed
}

// hy2User — клиент для clients[] hy2-inbound (auth=uuid, per-user).
type hy2User struct {
	Email string
	UUID  string
}

// hysteria2Clients — clients[] для settings hy2 (auth/email/level).
func hysteria2Clients(users []hy2User) []any {
	cls := make([]any, 0, len(users))
	for _, u := range users {
		cls = append(cls, map[string]any{"auth": u.UUID, "email": u.Email, "level": 0})
	}
	return cls
}

// syncHysteria2Access — синхронизация доступа hy2 ПЕРЕСОЗДАНИЕМ inbound с
// clients[] (RemoveInbound+AddInbound), а не AddUserOperation: clients
// персистятся в settings БД и переживают рестарт xray. Краткий разрыв UDP
// приемлем (hy2-клиенты переподключаются). Возвращает added/removed.
func (s *Server) syncHysteria2Access(ctx context.Context, ib *store.Inbound) (added, removed int, err error) {
	if s.xray == nil {
		return 0, 0, nil
	}
	normalizeHysteria2(ib, s.domain)
	var settings map[string]any
	json.Unmarshal([]byte(ib.Settings), &settings)
	if settings == nil {
		settings = map[string]any{}
	}
	// текущий состав (для дельты)
	oldEmails := map[string]bool{}
	if cls, ok := settings["clients"].([]any); ok {
		for _, c := range cls {
			if cm, ok := c.(map[string]any); ok {
				if e, _ := cm["email"].(string); e != "" {
					oldEmails[e] = true
				}
			}
		}
	}
	// effective set из БД (источник правды)
	clients, _ := s.store.EnabledClients()
	var users []hy2User
	newEmails := map[string]bool{}
	for _, cl := range clients {
		if s.store.ProtocolAllowed(cl.Email, ib.Tag) {
			users = append(users, hy2User{Email: cl.Email, UUID: cl.UUID})
			newEmails[cl.Email] = true
		}
	}
	for e := range newEmails {
		if !oldEmails[e] {
			added++
		}
	}
	for e := range oldEmails {
		if !newEmails[e] {
			removed++
		}
	}
	settings["clients"] = hysteria2Clients(users)
	sj, _ := json.Marshal(settings)
	ib.Settings = string(sj)
	// пересоздание: Remove (идемпотентно) + Add с полным clients[]
	_ = s.xray.RemoveInbound(ctx, ib.Tag)
	if err := s.xray.AddInbound(ctx, buildInboundJSONProto(*ib, "hysteria")); err != nil {
		return 0, 0, fmt.Errorf("hy2 recreate %s: %w", ib.Tag, err)
	}
	// B-1 (Ops 147be19): UpsertInbound(*ib) затирал enabled/in_sub УСТАРЕВШЕЙ
	// структурой — toggle читает ib ДО SetInboundEnabled(true) → enabled откатывался
	// в 0, hy2 пропадал из подписок, syncFirewall закрывал udp-порт (B-2).
	// Персистим ТОЛЬКО свои поля (settings/stream) поверх СВЕЖЕЙ строки из БД.
	if fresh, _ := s.store.GetInbound(ib.Tag); fresh != nil {
		fresh.Settings = ib.Settings
		fresh.Stream = ib.Stream
		if err := s.store.UpsertInbound(*fresh); err != nil {
			return added, removed, err
		}
	} else if err := s.store.UpsertInbound(*ib); err != nil {
		// строки ещё нет в БД (первичное создание) — пишем целиком
		return added, removed, err
	}
	return added, removed, nil
}
