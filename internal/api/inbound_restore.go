package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// RestoreInbounds — восстановление inbound'ов и доступа клиентов при старте панели.
// УРОК 1: preset-inbound'ы в БД enabled, но после рестарта xray их нет в живом конфиге
// (handler not found) → подписка отдаёт ссылки на несуществующие протоколы.
// УРОК 2: inbound из конфиг-файла (vless-reality) тоже надо синхронизировать — иначе
// новый клиент есть в подписке, но НЕ в clients[] inbound → подключение молча падает.
// УРОК 3: gRPC xray поднимается не мгновенно — ждём готовности, иначе connection refused.
// SQLite = источник правды.
func (s *Server) RestoreInbounds() {
	if s.xray == nil {
		return
	}
	// ожидание готовности gRPC xray (до ~40с): лёгкий запрос OnlineUsers как probe
	ready := false
	for i := 0; i < 20; i++ {
		probeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := s.xray.OnlineUsers(probeCtx)
		cancel()
		if err == nil {
			ready = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !ready {
		s.store.AddEvent("inbound_restore", "warn", "gRPC xray недоступен — восстановление inbound отложено", "{}")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// УРОК (аудит #8): IPv6-ловушка мастера — dns:null + freedom domainStrategy=None
	// → системный DNS отдаёт AAAA первым, IPv6 мёртв → таймауты. Доставляем фикс
	// v9.1.6 (dns UseIPv4 + freedom UseIPv4) в config.json существующего мастера;
	// применится при следующем рестарте xray (dns не имеет горячего gRPC-API).
	if changed, err := ensureMasterIPv4DNS(masterConfigPath); err == nil && changed {
		s.store.AddEvent("inbound_restore", "ok", "мастер: dns/freedom UseIPv4 записан в config.json (аудит #8, применится при рестарте xray)", "{}")
	}
	// теги из конфиг-файла мастера: inbound уже создан — только синхронизируем клиентов
	existing := map[string]bool{}
	if cfgData, err := os.ReadFile("/usr/local/etc/xray/config.json"); err == nil {
		var cfg struct {
			Inbounds []struct {
				Tag string `json:"tag"`
			} `json:"inbounds"`
		}
		if json.Unmarshal(cfgData, &cfg) == nil {
			for _, ib := range cfg.Inbounds {
				existing[ib.Tag] = true
			}
		}
	}
	clients, _ := s.store.EnabledClients()
	ibs, _ := s.store.AllInbounds()
	for _, ib := range ibs {
		if !ib.Enabled || ib.Tag == "api-in" || ib.Tag == "api" || !userProto(ib.Protocol) {
			continue
		}
		// УРОК (аудит #2): hy2 — version=2/hysteriaSettings могли потеряться при
		// пересоздании/миграции (auth 404, inbound без users). Чиним ДО создания.
		if ib.Protocol == "hysteria2" || ib.Protocol == "hysteria" {
			if normalizeHysteria2(&ib, s.domain) {
				s.store.UpsertInbound(ib)
				s.store.AddEvent("inbound_restore", "ok", fmt.Sprintf("%s: восстановлены version=2/hysteriaSettings", ib.Tag), "{}")
			}
		}
		// УРОК (аудит #6): hidden ws-inbound за dispatcher — plaintext-stream
		// (TLS уже снят dispatcher'ом). Старые записи могли нести tlsSettings
		// с пустым serverName → cert-путь live//fullchain → AddInbound падал.
		if ib.Hidden {
			if sanitizeHiddenStream(&ib) {
				s.store.UpsertInbound(ib)
				s.store.AddEvent("inbound_restore", "ok", fmt.Sprintf("%s: hidden-stream → plaintext за dispatcher", ib.Tag), "{}")
			}
		}
		if !existing[ib.Tag] && !s.xrayInboundExists(ctx, ib.Tag) {
			// создать недостающий inbound горячо.
			// УРОК (QA BUG-9): двойной рестарт панели — inbound уже жив (первый
			// restore/health-watch), AddInbound давал warn «existing tag found».
			// Проверяем наличие в ЖИВОМ xray, не только в config.json.
			if err := s.xray.AddInbound(ctx, buildInboundJSON(ib)); err != nil {
				if !strings.Contains(err.Error(), "already") && !strings.Contains(err.Error(), "exists") && !strings.Contains(err.Error(), "existing tag") {
					s.store.AddEvent("inbound_restore", "warn", fmt.Sprintf("AddInbound %s: %v", ib.Tag, err), "{}")
					continue
				}
			}
		}
		// hy2: доступ пересозданием inbound с clients[] (персист, аудит #2) —
		// AddUserOperation не персистится в settings и терялся при рестарте.
		if ib.Protocol == "hysteria2" || ib.Protocol == "hysteria" {
			added, removed, err := s.syncHysteria2Access(ctx, &ib)
			if err != nil {
				s.store.AddEvent("inbound_restore", "warn", fmt.Sprintf("hy2 sync %s: %v", ib.Tag, err), "{}")
			} else {
				s.store.AddEvent("inbound_restore", "ok",
					fmt.Sprintf("inbound %s: доступ синхронизирован (+%d/-%d, clients[] пересоздан)", ib.Tag, added, removed), "{}")
			}
			continue
		}
		// синхронизация доступа: разрешённых добавляем, запрещённых убираем (реальный запрет)
		added, removed := 0, 0
		for _, cl := range clients {
			flow := ""
			if ib.Protocol == "vless" && (ib.Network == "tcp" || ib.Network == "") && (ib.Security == "reality" || ib.Security == "tls") {
				flow = "xtls-rprx-vision"
			}
			if s.store.ProtocolAllowed(cl.Email, ib.Tag) {
				if err := s.xray.AddUserProto(ctx, ib.Tag, cl.Email, cl.UUID, flow, ib.Protocol); err != nil {
					if !strings.Contains(err.Error(), "already") && !strings.Contains(err.Error(), "exists") {
						s.store.AddEvent("inbound_restore", "warn", fmt.Sprintf("AddUser %s в %s: %v", cl.Email, ib.Tag, err), "{}")
					}
				} else {
					added++
				}
			} else {
				if err := s.xray.RemoveUser(ctx, ib.Tag, cl.Email); err == nil {
					removed++
				}
			}
		}
		s.store.AddEvent("inbound_restore", "ok",
			fmt.Sprintf("inbound %s: доступ синхронизирован (+%d/-%d)", ib.Tag, added, removed), "{}")
	}
	// маскировка по умолчанию: спрятать hideable TCP-протоколы за 443 (идемпотентно)
	bgReq, _ := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	s.applyDefaultMasking(bgReq)
	// УРОК (QA): после рестарта xray routing rules пусты — восстановить (sticky reeval не сделает).
	if s.ctrl != nil {
		s.ctrl.SyncRules(context.Background())
	}
}