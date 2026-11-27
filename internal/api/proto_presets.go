package api

import (
	"fmt"
	"net/http"
)

// Пресеты протоколов (переиспользование: мастер установки + ручное добавление галочками).
// УРОК (владелец): один вид — просто галочки, без ручного выбора транспорта/порта/ключей.
// Пресет = готовый набор protocol/network/security + авто-порт + авто-ключи.
// Создание идёт через тот же POST /api/inbounds (createInbound) — один код-путь.

type protoPreset struct {
	Protocol string
	Network  string
	Security string
	BasePort int
}

var protoPresets = map[string]protoPreset{
	"reality":      {"vless", "tcp", "reality", 443},
	"xhttp":        {"vless", "xhttp", "reality", 8444},
	"ws-tls":       {"vless", "ws", "tls", 8445},
	"hysteria2":    {"hysteria2", "udp", "tls", 8443},
	"trojan-tls":   {"trojan", "tcp", "reality", 8448},
	"vmess-ws":     {"vmess", "ws", "tls", 8449},
	"ss2022":       {"shadowsocks", "tcp", "ss2022", 8450},
}

// applyProtocolPresets создаёт inbounds для выбранных пресетов (идемпотентно).
// Вызывает createInbound через внутренний ResponseRecorder — тот же код-путь что и ручное
// добавление, без дублирования логики генерации ключей/транспортов.
func (s *Server) applyProtocolPresets(r *http.Request, selected []string) (created []string, errs []string) {
	for _, id := range selected {
		if id == "amnezia" {
			continue // AWG в процессе панели, включается отдельно
		}
		p, ok := protoPresets[id]
		if !ok {
			errs = append(errs, "unknown preset: "+id)
			continue
		}
		tag := "preset-" + id
		if existing, _ := s.store.GetInbound(tag); existing != nil {
			continue // уже создан — идемпотентно
		}
		// УРОК (владелец): существующий эквивалентный протокол не дублируем
		// (напр. установочный vless-reality:443 = пресет reality).
		var cnt int
		s.store.DB().QueryRow(`SELECT COUNT(*) FROM inbounds WHERE protocol=? AND network=? AND security=?`, p.Protocol, p.Network, p.Security).Scan(&cnt)
		if cnt > 0 { continue }
		port := s.freePort(p.BasePort)
		body := fmt.Sprintf(`{"protocol":%q,"network":%q,"security":%q,"port":%d,"tag":%q}`,
			p.Protocol, p.Network, p.Security, port, tag)
		req, _ := http.NewRequestWithContext(r.Context(), "POST", "/api/inbounds", stringReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := &captureWriter{header: http.Header{}}
		s.createInbound(rec, req)
		if rec.status >= 400 {
			errs = append(errs, id+": "+rec.body.String())
			continue
		}
		created = append(created, id)
	}
	return
}

// freePort — первый свободный порт начиная с base (по inbounds БД).
func (s *Server) freePort(base int) int {
	for port := base; port < base+100; port++ {
		var cnt int
		s.store.DB().QueryRow(`SELECT COUNT(*) FROM inbounds WHERE port=?`, port).Scan(&cnt)
		if cnt == 0 {
			return port
		}
	}
	return base
}