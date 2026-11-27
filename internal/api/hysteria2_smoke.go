package api

// hy2 smoke (аудит #2c): реальная auth-проверка hysteria2-inbound, не «порт слушает».
// Порт UDP может быть открыт, но inbound без users отвечает auth 404 на ЛЮБОЙ auth
// (живой случай аудита). Проба повторяет handshake xray-клиента: QUIC + HTTP/3
// POST https://hysteria/auth с заголовком Hysteria-Auth; 233 = auth OK, 404 = users
// нет/неверный auth. salamander-обфускация из finalmask.udp[] применяется к пакетам.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander"

	"github.com/kambarro/xkit-panel/internal/store"
)

// hy2AuthProbe — реальная auth-проба hy2-inbound. Возвращает HTTP-код ответа
// (233 = auth принят, 404 = нет users/неверный auth) или ошибку сети/QUIC.
func hy2AuthProbe(ctx context.Context, host string, port int, sni, auth, obfsPass string) (int, error) {
	if sni == "" {
		sni = host
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, fmt.Errorf("resolve: %w", err)
	}
	raw, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return 0, fmt.Errorf("udp listen: %w", err)
	}
	defer raw.Close()
	var pktConn net.PacketConn = raw
	if obfsPass != "" {
		// salamander как в xray finalmask.udp[]: новый Config — HeaderConn-маска,
		// сырой WrapPacketConnClient даёт буферный контракт (salt-offset), quic-go
		// его не понимает. Штатный путь ядра — FinalMask.DialUDP (headerManagerConn).
		dest := xnet.Destination{Address: xnet.IPAddress(udpAddr.IP), Port: xnet.Port(port), Network: xnet.Network_UDP}
		fm := finalmask.NewFinalMask(nil, []finalmask.UDPMask{&salamander.Config{Password: obfsPass}},
			nil, nil,
			func(context.Context, xnet.Destination) (net.PacketConn, net.Addr, error) { return raw, udpAddr, nil },
			nil)
		conn, derr := fm.DialUDP(ctx, dest)
		if derr != nil {
			return 0, fmt.Errorf("salamander: %w", derr)
		}
		pktConn = conn.(*xnet.PacketConnWrapper).PacketConn
	}
	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // смоук: проверяем AUTH, не валидность серта (LE может быть не выпущен)
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
	}
	quicCfg := &quic.Config{
		EnableDatagrams:       true,
		MaxIdleTimeout:        10 * time.Second,
		HandshakeIdleTimeout:  8 * time.Second,
		DisablePathMTUDiscovery: true,
	}
	rt := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig:      quicCfg,
		EnableDatagrams: true,
		Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			return quic.DialEarly(ctx, pktConn, udpAddr, tc, qc)
		},
	}
	defer rt.Close()
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Scheme: "https", Host: "hysteria", Path: "/auth"},
		Header: http.Header{
			"Hysteria-Auth":    []string{auth},
			"Hysteria-CC-RX":   []string{"0"},
			"Hysteria-Padding": []string{strings.Repeat("x", 256)},
		},
		Host: "hysteria",
	}
	resp, err := rt.RoundTrip(req.WithContext(ctx))
	if err != nil {
		return 0, fmt.Errorf("quic/http3: %w", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// doctorHy2Smoke — проверка всех включённых hy2-inbound: users в БД + реальная
// auth-проба с auth первого разрешённого клиента. 233 = OK; 404 = inbound мёртв.
func (s *Server) doctorHy2Smoke() []DoctorCheck {
	var checks []DoctorCheck
	ibs, _ := s.store.AllInbounds()
	for _, ib := range ibs {
		if !ib.Enabled || (ib.Protocol != "hysteria2" && ib.Protocol != "hysteria") {
			continue
		}
		id := "hy2_" + ib.Tag
		name := "Hysteria2 " + ib.Tag
		var settings, stream map[string]any
		json.Unmarshal([]byte(ib.Settings), &settings)
		json.Unmarshal([]byte(ib.Stream), &stream)
		// version=2 обязателен в settings И stream.hysteriaSettings (аудит #2)
		if v, _ := settings["version"].(float64); v != 2 {
			checks = append(checks, DoctorCheck{ID: id, Name: name, Status: "error",
				Detail: "settings.version != 2 — inbound без валидатора (auth 404)", Fixable: true, FixLabel: "Починить"})
			continue
		}
		// auth первого разрешённого клиента
		auth, email := "", ""
		if cls, ok := settings["clients"].([]any); ok {
			for _, c := range cls {
				if cm, ok := c.(map[string]any); ok {
					if a, _ := cm["auth"].(string); a != "" {
						auth = a
						email, _ = cm["email"].(string)
						break
					}
				}
			}
		}
		if auth == "" {
			// clients[] пуст — возьмём из effective set (мог не синхронизироваться)
			clients, _ := s.store.EnabledClients()
			for _, cl := range clients {
				if s.store.ProtocolAllowed(cl.Email, ib.Tag) {
					auth, email = cl.UUID, cl.Email
					break
				}
			}
		}
		if auth == "" {
			checks = append(checks, DoctorCheck{ID: id, Name: name, Status: "warn",
				Detail: "нет клиентов с доступом — auth не проверить", Fixable: false})
			continue
		}
		sni := ""
		if ts, ok := stream["tlsSettings"].(map[string]any); ok {
			sni, _ = ts["serverName"].(string)
		}
		obfs := hy2ObfsPassword(stream)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		code, err := hy2AuthProbe(ctx, "127.0.0.1", ib.Port, sni, auth, obfs)
		cancel()
		switch {
		case err != nil:
			checks = append(checks, DoctorCheck{ID: id, Name: name, Status: "error",
				Detail: "проба не прошла: " + err.Error(), Fixable: true, FixLabel: "Починить"})
		case code == 233:
			checks = append(checks, DoctorCheck{ID: id, Name: name, Status: "ok",
				Detail: fmt.Sprintf("auth OK (233), клиент %s", email), Fixable: false})
		case code == 404:
			checks = append(checks, DoctorCheck{ID: id, Name: name, Status: "error",
				Detail: "auth 404 — в inbound нет users (мёртвый inbound)", Fixable: true, FixLabel: "Починить"})
		default:
			checks = append(checks, DoctorCheck{ID: id, Name: name, Status: "warn",
				Detail: fmt.Sprintf("неожиданный ответ %d", code), Fixable: false})
		}
	}
	return checks
}

// hy2ObfsPassword — пароль salamander из stream.finalmask.udp[].
func hy2ObfsPassword(stream map[string]any) string {
	fm, ok := stream["finalmask"].(map[string]any)
	if !ok {
		return ""
	}
	udps, ok := fm["udp"].([]any)
	if !ok {
		return ""
	}
	for _, u := range udps {
		um, ok := u.(map[string]any)
		if !ok {
			continue
		}
		if um["type"] == "salamander" {
			if st, ok := um["settings"].(map[string]any); ok {
				if p, _ := st["password"].(string); p != "" {
					return p
				}
			}
		}
	}
	return ""
}

// fixHysteria2 — doctorFix: нормализация + пересоздание inbound с clients[].
func (s *Server) fixHysteria2(tag string) error {
	ib, _ := s.store.GetInbound(tag)
	if ib == nil {
		return fmt.Errorf("inbound %s не найден", tag)
	}
	if ib.Protocol != "hysteria2" && ib.Protocol != "hysteria" {
		return fmt.Errorf("%s не hysteria2", tag)
	}
	normalizeHysteria2(ib, s.domain)
	if s.xray == nil {
		return s.store.UpsertInbound(*ib)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _, err := s.syncHysteria2Access(ctx, ib)
	return err
}

var _ = store.Inbound{}
