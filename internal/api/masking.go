package api

// Маскировка по умолчанию: все прячущиеся TCP-протоколы за ОДНИМ 443.
// Цепочка: клиент → :443 REALITY (vless-reality) → [не-REALITY трафик] →
// TLS-dispatcher 127.0.0.1:9443 (LE-сертификат домена) → fallbacks по path/alpn →
// ws/xhttp/grpc/vmess inbound'ы на 127.0.0.1 (внутренние порты = косметика).
// Снаружи открыт ОДИН TCP-порт. Клиентские ссылки — все домен:443 security=tls.
// Что спрятать нельзя (trojan/ss2022 — нет path/SNI-зацепки; UDP — другой транспорт)
// честно помечается и НЕ прячется. Порт hidden-протокола менять нельзя.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/kambarro/xkit-panel/internal/store"
)

const (
	dispatcherTag  = "tls-dispatcher"
	dispatcherPort = 9443 // 127.0.0.1, внутренний TLS-терминатор за REALITY
	publicTLS443   = 443
)

// hideable — протоколы, которые НАДЁЖНО прячутся за 443 через VLESS TLS-fallback.
// ws (GET Upgrade) — проверено реальным подключением. xhttp (POST body) и grpc (h2)
// через fallback молча не работают — их НЕ прячем (честный красный бейдж, свой порт).
// trojan/shadowsocks — нет path/SNI-зацепки; hysteria2 — UDP. Тоже не прячем.
func hideable(protocol, network string) bool {
	if protocol != "vless" && protocol != "vmess" {
		return false
	}
	return network == "ws"
}

// maskBadge — честный уровень маскировки для UI.
// green: за 443, неотличим от сайта; orange: UDP (обфускация, но свой порт);
// red: свой TCP-порт, виден провайдеру.
func maskBadge(ib store.Inbound) (level, labelRu, labelEn string) {
	if ib.Hidden {
		return "green", "за 443 · неотличим от сайта", "behind 443 · looks like a website"
	}
	if ib.Protocol == "vless" && ib.Security == "reality" && ib.Port == 443 {
		return "green", "443 · REALITY-маскировка", "443 · REALITY masking"
	}
	if ib.Protocol == "hysteria2" || ib.Protocol == "hysteria" {
		return "orange", fmt.Sprintf("UDP :%d · обфускация, за TCP-443 не спрятать", ib.Port), fmt.Sprintf("UDP :%d · obfuscated, cannot share TCP 443", ib.Port)
	}
	if ib.Network == "xhttp" || ib.Network == "grpc" || ib.Protocol == "trojan" || ib.Protocol == "shadowsocks" {
		return "red", fmt.Sprintf("свой порт :%d · спрятать за 443 нельзя", ib.Port), fmt.Sprintf("own port :%d · cannot hide behind 443", ib.Port)
	}
	return "red", fmt.Sprintf("свой порт :%d · виден провайдеру", ib.Port), fmt.Sprintf("own port :%d · visible to ISP", ib.Port)
}

// ensureDispatcher — создаёт/обновляет внутренний TLS-dispatcher inbound.
// REALITY dest=:9443 → dispatcher терминирует TLS (LE домена) → fallbacks по path/alpn.
func (s *Server) ensureDispatcher(r *http.Request) error {
	ibs, _ := s.store.AllInbounds()
	var fallbacks []map[string]any
	for _, ib := range ibs {
		if !ib.Enabled || !ib.Hidden {
			continue
		}
		var stream map[string]any
		json.Unmarshal([]byte(ib.Stream), &stream)
		fb := map[string]any{"dest": ib.Port, "xver": 0}
		if ws, ok := stream["wsSettings"].(map[string]any); ok {
			if p, _ := ws["path"].(string); p != "" {
				fb["path"] = p
			}
		}
		if xhttp, ok := stream["xhttpSettings"].(map[string]any); ok {
			if p, _ := xhttp["path"].(string); p != "" {
				fb["path"] = p
			}
		}
		if grpc, ok := stream["grpcSettings"].(map[string]any); ok {
			if sn, _ := grpc["serviceName"].(string); sn != "" {
				// gRPC fallback по path /serviceName (БЕЗ alpn h2 — иначе перехватывает
				// весь h2-трафик включая подписки/панель, ломая их: 000).
				fb["path"] = "/" + sn
			}
		}
		fallbacks = append(fallbacks, fb)
	}
	// default fallback → plaintext nginx :8081 (camo+panel+sub). НЕ :8443 (ssl) —
	// dispatcher уже снял TLS, шлёт plaintext; nginx ssl-порт его не примет (000).
	fallbacks = append(fallbacks, map[string]any{"dest": 8081, "xver": 0})

	settings := map[string]any{"clients": []any{}, "decryption": "none", "fallbacks": fallbacks}
	stream := map[string]any{
		"network":  "tcp",
		"security": "tls",
		"tlsSettings": map[string]any{
			"certificates": []any{map[string]any{
				"certificateFile": "/etc/letsencrypt/live/" + s.domain + "/fullchain.pem",
				"keyFile":         "/etc/letsencrypt/live/" + s.domain + "/privkey.pem",
			}},
			"alpn": []string{"http/1.1"},
		},
	}
	sj, _ := json.Marshal(settings)
	stj, _ := json.Marshal(stream)
	disp := store.Inbound{
		Tag: dispatcherTag, Protocol: "vless", Port: dispatcherPort, Listen: "127.0.0.1",
		Network: "tcp", Security: "tls", Settings: string(sj), Stream: string(stj), Enabled: true,
	}
	if s.xray != nil {
		ctx := r.Context()
		_ = s.xray.RemoveInbound(ctx, dispatcherTag)
		if err := s.xray.AddInbound(ctx, buildInboundJSON(disp)); err != nil {
			return fmt.Errorf("dispatcher: %w", err)
		}
	}
	if err := s.store.UpsertInbound(disp); err != nil {
		return err
	}
	// REALITY :443 dest → dispatcher. Конфиг-файловый reality: правим ФАЙЛ (персист),
	// горячо пересоздаём inbound с клиентами (иначе после рестарта xray dest=старый).
	if rib, _ := s.store.GetInbound("vless-reality"); rib != nil {
		var st map[string]any
		json.Unmarshal([]byte(rib.Stream), &st)
		if rs, ok := st["realitySettings"].(map[string]any); ok {
			newDest := fmt.Sprintf("127.0.0.1:%d", dispatcherPort)
			if cur, _ := rs["dest"].(string); cur != newDest {
				rs["dest"] = newDest
				st["realitySettings"] = rs
				stj, _ := json.Marshal(st)
				rib.Stream = string(stj)
				s.store.UpsertInbound(*rib)
				// персист в config.json (источник при рестарте xray)
				s.patchRealityDestInConfig(newDest)
				// горячо: пересоздать reality inbound + клиенты (краткий разрыв, один раз при миграции)
				if s.xray != nil {
					ctx := r.Context()
					_ = s.xray.RemoveInbound(ctx, "vless-reality")
					if err := s.xray.AddInbound(ctx, buildInboundJSON(*rib)); err == nil {
						clients, _ := s.store.EnabledClients()
						for _, c := range clients {
							if s.store.ProtocolAllowed(c.Email, "vless-reality") {
								s.xray.AddUserProto(ctx, "vless-reality", c.Email, c.UUID, "xtls-rprx-vision", "vless")
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// patchRealityDestInConfig — правит dest vless-reality в config.json мастера (персист).
func (s *Server) patchRealityDestInConfig(dest string) {
	data, err := os.ReadFile("/usr/local/etc/xray/config.json")
	if err != nil {
		return
	}
	var cfg map[string]any
	if json.Unmarshal(data, &cfg) != nil {
		return
	}
	inbounds, _ := cfg["inbounds"].([]any)
	changed := false
	for _, raw := range inbounds {
		ib, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if tag, _ := ib["tag"].(string); tag != "vless-reality" {
			continue
		}
		st, _ := ib["streamSettings"].(map[string]any)
		rs, _ := st["realitySettings"].(map[string]any)
		if rs != nil {
			rs["dest"] = dest
			changed = true
		}
	}
	if !changed {
		return
	}
	s.rebuildConfigClients(cfg)
	out, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile("/usr/local/etc/xray/config.json", out, 0644)
}

// hideInbound — прячет inbound за 443: listen 127.0.0.1, public_port=443,
// security=tls (клиентский TLS терминирует dispatcher), серверный stream без tls
// (dispatcher уже расшифровал — внутренний inbound принимает plaintext ws/grpc/xhttp).
func (s *Server) hideInbound(r *http.Request, ib *store.Inbound) error {
	var stream map[string]any
	json.Unmarshal([]byte(ib.Stream), &stream)
	// сохраним sni для подписки в tlsSettings.serverName, но сам inbound — plaintext за dispatcher
	sni := s.domain
	if ts, ok := stream["tlsSettings"].(map[string]any); ok {
		if sn, _ := ts["serverName"].(string); sn != "" {
			sni = sn
		}
	}
	// внутренний inbound: security none (TLS уже снят dispatcher'ом)
	newStream := map[string]any{"network": ib.Network}
	for _, k := range []string{"wsSettings", "grpcSettings", "xhttpSettings"} {
		if v, ok := stream[k]; ok {
			newStream[k] = v
		}
	}
	// для подписки: клиент видит tls+sni (сохраняем в settings служебно)
	var settings map[string]any
	json.Unmarshal([]byte(ib.Settings), &settings)
	if settings == nil {
		settings = map[string]any{}
	}
	settings["subSni"] = sni
	settings["subTls"] = true
	sj, _ := json.Marshal(settings)
	stj, _ := json.Marshal(newStream)
	ib.Listen = "127.0.0.1"
	ib.Hidden = true
	ib.PublicPort = publicTLS443
	ib.Settings = string(sj)
	ib.Stream = string(stj)
	if s.xray != nil {
		_ = s.xray.RemoveInbound(r.Context(), ib.Tag)
		if err := s.xray.AddInbound(r.Context(), buildInboundJSON(*ib)); err != nil {
			return err
		}
		// клиенты заново (inbound пересоздан)
		s.addClientsToInbound(r, *ib)
	}
	if err := s.store.UpsertInbound(*ib); err != nil {
		return err
	}
	return s.ensureDispatcher(r)
}

// applyDefaultMasking — идемпотентно прячет все hideable inbound за 443.
// Вызывается при старте (RestoreInbounds) и после создания протокола.
func (s *Server) applyDefaultMasking(r *http.Request) {
	ibs, _ := s.store.AllInbounds()
	changed := false
	for _, ib := range ibs {
		if !ib.Enabled || ib.Hidden || ib.Tag == dispatcherTag || ib.Tag == "vless-reality" {
			continue
		}
		if hideable(ib.Protocol, ib.Network) {
			if err := s.hideInbound(r, &ib); err != nil {
				s.store.AddEvent("masking", "warn", fmt.Sprintf("скрыть %s за 443: %v", ib.Tag, err), "{}")
				continue
			}
			s.store.AddEvent("masking", "ok", fmt.Sprintf("%s спрятан за 443 (внутренний :%d)", ib.Tag, ib.Port), "{}")
			changed = true
		}
	}
	if changed {
		s.syncFirewall()
	}
	// dispatcher всегда актуален (fallback-порты/дефолт могли измениться даже без новых hidden)
	bgReq2, _ := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	if err := s.ensureDispatcher(bgReq2); err != nil {
		s.store.AddEvent("masking", "warn", "dispatcher: "+err.Error(), "{}")
	}
}

// sanitizeHiddenStream — hidden-inbound за dispatcher принимает PLAINTEXT
// (TLS уже снят dispatcher'ом, как в hideInbound). УРОК (аудит #6): старые
// записи несли tlsSettings с пустым serverName → cert-путь live//fullchain →
// AddInbound падал, ws-ссылка подписки была мёртвой. Убираем security/tlsSettings,
// сохраняем transport-settings; sni для подписки — в settings.subSni.
// true = были изменения.
func sanitizeHiddenStream(ib *store.Inbound) bool {
	var stream map[string]any
	json.Unmarshal([]byte(ib.Stream), &stream)
	if stream == nil {
		return false
	}
	_, hasTLS := stream["tlsSettings"]
	sec, _ := stream["security"].(string)
	if !hasTLS && (sec == "" || sec == "none") {
		return false // уже plaintext
	}
	// сохраним sni для подписки (если ещё не сохранён)
	var settings map[string]any
	json.Unmarshal([]byte(ib.Settings), &settings)
	if settings == nil {
		settings = map[string]any{}
	}
	if sni, _ := settings["subSni"].(string); sni == "" {
		sni := ""
		if ts, ok := stream["tlsSettings"].(map[string]any); ok {
			sni, _ = ts["serverName"].(string)
		}
		if sni != "" {
			settings["subSni"] = sni
			settings["subTls"] = true
			sj, _ := json.Marshal(settings)
			ib.Settings = string(sj)
		}
	}
	newStream := map[string]any{"network": ib.Network}
	for _, k := range []string{"wsSettings", "grpcSettings", "xhttpSettings"} {
		if v, ok := stream[k]; ok {
			newStream[k] = v
		}
	}
	stj, _ := json.Marshal(newStream)
	ib.Stream = string(stj)
	return true
}

// guardHiddenEdit — запрет менять порт/скрытие hidden-протокола (условие владельца:
// маскировка по умолчанию БЕЗ возможности изменить).
func guardHiddenEdit(w http.ResponseWriter, ib *store.Inbound, newPort int) bool {
	if ib.Hidden && newPort != ib.Port {
		http.Error(w, "протокол спрятан за 443 — внутренний порт менять нельзя (маскировка по умолчанию)", 403)
		return false
	}
	return true
}