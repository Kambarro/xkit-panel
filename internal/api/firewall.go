package api

import (
	"net/http"

	"github.com/kambarro/xkit-panel/internal/firewall"
	"github.com/kambarro/xkit-panel/internal/store"
)

// neededPorts — актуальный набор портов которые панель должна держать открытыми:
// все включённые inbound (tcp) + AWG (udp) + hysteria2 (udp если активен).
// Базовые 22/80/443 добавляются firewall.EnsureBase отдельно.
func (s *Server) neededPorts() map[int]string {
	needed := map[int]string{}
	if ibs, err := s.store.AllInbounds(); err == nil {
		for _, ib := range ibs {
			if !ib.Enabled || ib.Tag == "api-in" || ib.Tag == "api" || ib.Tag == dispatcherTag {
				continue
			}
			// маскировка: hidden-протоколы за 443 — свой порт наружу НЕ открываем
			if ib.Hidden {
				continue
			}
			// hysteria2 — udp, остальные xray inbound — tcp
			proto := "tcp"
			if ib.Protocol == "hysteria2" || ib.Protocol == "hysteria" {
				proto = "udp"
			}
			needed[ib.Port] = proto
		}
	}
	// AWG сервер (udp)
	if s.store.DB() != nil {
		var port int
		var enabled int
		if err := s.store.DB().QueryRow(`SELECT port,enabled FROM awg_server LIMIT 1`).Scan(&port, &enabled); err == nil && enabled == 1 && port > 0 {
			needed[port] = "udp"
		}
	}
	// MTProto FakeTLS (tcp) — Web Proxy за nginx 443, отдельный порт не нужен
	if s.store.GetSetting("tg_mtproto_enabled", "0") == "1" {
		if p := atoiDefault(s.store.GetSetting("tg_mtproto_port", "8449"), 8449); p > 0 {
			needed[p] = "tcp"
		}
	}
	return needed
}

// syncFirewall — привести UFW к актуальным портам (вызывается после любой операции
// с протоколами/нодами/AWG). Автоматика: открыли протокол → порт открыт, удалили → закрыт.
func (s *Server) syncFirewall() {
	if err := firewall.Sync(s.neededPorts()); err != nil {
		s.store.AddEvent("firewall", "warn", "sync UFW: "+err.Error(), "{}")
	}
}

// InitFirewall — базовая политика + сверка при старте панели (автоматика).
func (s *Server) InitFirewall() {
	firewall.EnsureBase()
	firewall.CleanupLegacy(s.neededPorts())
	s.syncFirewall()
}

// GET /api/firewall — статус UFW + какие порты открыты панелью (для UI Настройки).
func (s *Server) firewallStatus(w http.ResponseWriter, r *http.Request) {
	needed := s.neededPorts()
	type portView struct {
		Port  int    `json:"port"`
		Proto string `json:"proto"`
	}
	var ports []portView
	for p, pr := range needed {
		ports = append(ports, portView{p, pr})
	}
	writeJSON(w, map[string]any{
		"status":     firewall.Status(),
		"auto_ports": firewall.AutoPorts(),
		"needed":     ports,
	})
}

// POST /api/firewall/sync — принудительная сверка (кнопка «Применить правила»).
func (s *Server) firewallSync(w http.ResponseWriter, r *http.Request) {
	firewall.EnsureBase()
	firewall.CleanupLegacy(s.neededPorts()) // закрыть лишние старые ALLOW-порты
	s.syncFirewall()
	s.store.AddEvent("firewall", "ok", "UFW синхронизирован с активными протоколами", "{}")
	writeJSON(w, map[string]any{"ok": true, "needed": s.neededPorts(), "auto_ports": firewall.AutoPorts()})
}

var _ = store.Inbound{}