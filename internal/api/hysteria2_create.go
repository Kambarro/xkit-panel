package api

// Hysteria2 — клиентский протокол ВНУТРИ Xray (proxy/hysteria, version 2), как AWG по UX:
// галочка в «Добавить протоколы» → inbound + ссылка hysteria2:// в подписке + QR.
// УРОК: xray registry protocol = "hysteria" (НЕ "hysteria2"), settings {version:2, clients:[{auth,email}]},
// stream network = "hysteria" (UDP/QUIC), TLS cert, obfs salamander в finalmask.udp[].
// Per-user auth = uuid клиента.
// УРОК (аудит #2): version=2 обязателен в settings И stream.hysteriaSettings —
// без них inbound строится без валидатора → auth 404. normalizeHysteria2 чинит
// потерянные поля; доступ синхронизируется пересозданием inbound с clients[]
// (syncHysteria2Access), clients персистятся в БД и переживают рестарт xray.
// xray-core 26.x proxy/hysteria AddUser ЕСТЬ (проверено по модулю и main),
// но пересоздание надёжнее горячего AddUser без персиста.

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kambarro/xkit-panel/internal/store"
)

// createHysteria2Inbound — отдельный код-путь для hysteria2 (не vless-шаблон).
// Вызывается из createInbound при protocol=hysteria2.
func (s *Server) createHysteria2Inbound(w http.ResponseWriter, r *http.Request, port int, tag, sni string) {
	if sni == "" {
		sni = s.domain
	}
	obfsPass := randHex(8)
	settings := map[string]any{"version": 2, "clients": []any{}}
	stream := map[string]any{
		"network":  "hysteria",
		"security": "tls",
		"tlsSettings": map[string]any{
			"serverName": sni,
			"certificates": []any{map[string]any{
				"certificateFile": "/etc/letsencrypt/live/" + s.domain + "/fullchain.pem",
				"keyFile":         "/etc/letsencrypt/live/" + s.domain + "/privkey.pem",
			}},
		},
		"hysteriaSettings": map[string]any{"version": 2},
		"finalmask": map[string]any{
			"udp": []any{map[string]any{
				"type":     "salamander",
				"settings": map[string]any{"password": obfsPass},
			}},
		},
	}
	settingsJSON, _ := json.Marshal(settings)
	streamJSON, _ := json.Marshal(stream)
	ib := store.Inbound{
		Tag: tag, Protocol: "hysteria2", Port: port, Listen: "0.0.0.0",
		Network: "hysteria", Security: "tls",
		Settings: string(settingsJSON), Stream: string(streamJSON), Enabled: true,
	}
	// добавить разрешённых клиентов в clients[] ДО создания (auth=uuid, персист)
	clients, _ := s.store.EnabledClients()
	var users []hy2User
	for _, c := range clients {
		if s.store.ProtocolAllowed(c.Email, tag) {
			users = append(users, hy2User{Email: c.Email, UUID: c.UUID})
		}
	}
	settings["clients"] = hysteria2Clients(users)
	settingsJSON, _ = json.Marshal(settings)
	ib.Settings = string(settingsJSON)
	if s.xray != nil {
		// xray registry: protocol "hysteria" (version 2 внутри settings)
		if err := s.xray.AddInbound(r.Context(), buildInboundJSONProto(ib, "hysteria")); err != nil {
			http.Error(w, "gRPC AddInbound hysteria2: "+err.Error(), 500)
			return
		}
	}
	if err := s.store.UpsertInbound(ib); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.store.AddEvent("inbound_created", "ok", fmt.Sprintf("протокол %s создан (hysteria2:%d, QUIC+salamander, клиентов: %d)", tag, port, len(users)), "{}")
	if s.store.InboundAutoAdd(tag) {
		s.store.AddProtocolToAutoAddSquads(tag)
	}
	s.syncFirewall()
	writeJSON(w, map[string]any{"ok": true, "tag": tag, "port": port})
}
