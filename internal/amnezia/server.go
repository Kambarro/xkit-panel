package amnezia

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"

	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/crypto/curve25519"
)

// Server — AmneziaWG сервер внутри процесса панели (паттерн Kitsune internal/awg).
// УРОК: amneziawg-go/v3 как библиотека — device+conn+tun, UAPI hex-конфиг, пиры на пользователя.
// Один бинарь без DKMS/3X-UI. TUN-интерфейс awg0, UDP-порт, NAT через iptables (install).
type Server struct {
	mu      sync.Mutex
	dev     *awgdevice.Device
	tun     awgtun.Device
	bind    awgconn.Bind
	port    int
	privKey string
	pubKey  string
	params  AWGParams
	iface   string
	running bool
}

// ServerConfig — конфигурация AWG-сервера.
type ServerConfig struct {
	Iface   string // awg0
	Port    int    // UDP порт (51820 дефолт)
	PrivKey string // серверный private key (base64)
	Params  AWGParams
	Address string // 10.8.1.1/24 (адрес сервера в туннеле)
}

// NewServer создаёт AWG-сервер (не запускает).
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Iface == "" { cfg.Iface = "awg0" }
	if cfg.Port == 0 { cfg.Port = 51820 }
	if cfg.PrivKey == "" { return nil, fmt.Errorf("AWG: нужен private key сервера") }
	return &Server{port: cfg.Port, privKey: cfg.PrivKey, params: cfg.Params, iface: cfg.Iface}, nil
}

// Start запускает AWG-сервер: TUN + UDP bind + device + UAPI-конфиг.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running { return nil }
	// TUN-интерфейс
	tunDev, err := awgtun.CreateTUN(s.iface, s.params.MTU)
	if err != nil { return fmt.Errorf("AWG CreateTUN %s: %w", s.iface, err) }
	s.tun = tunDev
	// UDP bind: НЕ открываем вручную! device.Up()→BindUpdate() сам откроет bind
	// на порту из IpcSet listen_port. УРОК (live-проба): ручной bind.Open() до Up()
	// приводил к тому что BindUpdate закрывал его и открывал на port=0 (случайный).
	// Обычный NewStdNetBind (BatchSize=128): noGSO-обёртка с BatchSize=1 ЛОМАЕТ receive
	// (inner receiveIP читает батч 128 в массив размера 1). EMSGSIZE на virtio не фатален
	// (библиотека ретраит, handshake/data проходят) — проверено live.
	bind := awgconn.NewStdNetBind()
	s.bind = bind
	// device
	logger := awgdevice.NewLogger(awgdevice.LogLevelError, fmt.Sprintf("(%s) ", s.iface))
	dev := awgdevice.NewDevice(tunDev, bind, logger)
	s.dev = dev
	// UAPI-конфиг сервера (private_key + listen_port + AWG-параметры)
	uapi := s.serverUAPI()
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return fmt.Errorf("AWG IpcSet: %w", err)
	}
	// Up() → BindUpdate() открывает bind на listen_port из IpcSet
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("AWG Up: %w", err)
	}
	s.running = true
	// pub key: вычисляем из private key (curve25519), не парсим IpcGet
	// (IpcGetOperation до первого пира не выводит public_key сервера — проверено live).
	if raw, err := base64.StdEncoding.DecodeString(s.privKey); err == nil && len(raw) == 32 {
		var sk [32]byte
		copy(sk[:], raw)
		pub, err := curve25519.X25519(sk[:], curve25519.Basepoint)
		if err == nil {
			s.pubKey = base64.StdEncoding.EncodeToString(pub)
		}
	}
	return nil
}

// serverUAPI — UAPI hex-конфиг сервера (AWG-параметры обфускации).
func (s *Server) serverUAPI() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("private_key=%s\n", hexKey(s.privKey)))
	b.WriteString(fmt.Sprintf("listen_port=%d\n", s.port))
	b.WriteString(fmt.Sprintf("jc=%d\n", s.params.Jc))
	b.WriteString(fmt.Sprintf("jmin=%d\n", s.params.Jmin))
	b.WriteString(fmt.Sprintf("jmax=%d\n", s.params.Jmax))
	b.WriteString(fmt.Sprintf("s1=%d\n", s.params.S1))
	b.WriteString(fmt.Sprintf("s2=%d\n", s.params.S2))
	if s.params.Version != "2.0" {
		b.WriteString(fmt.Sprintf("s3=%d\n", s.params.S3))
		b.WriteString(fmt.Sprintf("s4=%d\n", s.params.S4))
	}
	b.WriteString(fmt.Sprintf("h1=%s\n", s.params.H1))
	b.WriteString(fmt.Sprintf("h2=%s\n", s.params.H2))
	b.WriteString(fmt.Sprintf("h3=%s\n", s.params.H3))
	b.WriteString(fmt.Sprintf("h4=%s\n", s.params.H4))
	if s.params.I1 != "" { b.WriteString(fmt.Sprintf("i1=%s\n", s.params.I1)) }
	// AWG 3.1: randomTrailers=true (УРОК: инвариант), disableCookies=false.
	// 2.0 (роутеры): поля 3.1 не отправляем — старый клиент их не понимает.
	if s.params.Version != "2.0" {
		b.WriteString(fmt.Sprintf("random_trailers=%t\n", s.params.RandomTrailers))
	}
	b.WriteString(fmt.Sprintf("disable_cookies=%t\n", s.params.DisableCookies))
	return b.String()
}

// StartWithPeer — как Start, но пир добавляется В ТОМ ЖЕ IpcSet что params (ДО Up).
// УРОК (AWG каскад): раздельный AddPeer после Up может не инициализировать per-peer
// obfuscation state правильно. Loopback тест с peer в初始 IpcSet работал.
func (s *Server) StartWithPeer(p Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running { return nil }
	tunDev, err := awgtun.CreateTUN(s.iface, s.params.MTU)
	if err != nil { return fmt.Errorf("AWG CreateTUN %s: %w", s.iface, err) }
	s.tun = tunDev
	bind := awgconn.NewStdNetBind()
	s.bind = bind
	logger := awgdevice.NewLogger(awgdevice.LogLevelError, fmt.Sprintf("(%s) ", s.iface))
	dev := awgdevice.NewDevice(tunDev, bind, logger)
	s.dev = dev
	// params + peer В ОДНОМ IpcSet
	uapi := s.serverUAPI()
	uapi += "public_key=" + hexKey(p.PublicKey) + "\n"
	if p.PresharedKey != "" { uapi += "preshared_key=" + hexKey(p.PresharedKey) + "\n" }
	uapi += "allowed_ip=" + strings.TrimSuffix(p.Address, "/32") + "/32\n"
	if err := dev.IpcSet(uapi); err != nil { dev.Close(); return fmt.Errorf("AWG IpcSet: %w", err) }
	if err := dev.Up(); err != nil { dev.Close(); return fmt.Errorf("AWG Up: %w", err) }
	s.running = true
	if raw, err := base64.StdEncoding.DecodeString(s.privKey); err == nil && len(raw) == 32 {
		var sk [32]byte; copy(sk[:], raw)
		if pub, err := curve25519.X25519(sk[:], curve25519.Basepoint); err == nil {
			s.pubKey = base64.StdEncoding.EncodeToString(pub)
		}
	}
	return nil
}

// AddPeer добавляет клиентский пир (горячо, UAPI).
func (s *Server) AddPeer(p Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running { return fmt.Errorf("AWG сервер не запущен") }
	uapi := "public_key=" + hexKey(p.PublicKey) + "\n"
	if p.PresharedKey != "" { uapi += "preshared_key=" + hexKey(p.PresharedKey) + "\n" }
	uapi += "allowed_ip=" + strings.TrimSuffix(p.Address, "/32") + "/32\n"
	if err := s.dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("AWG AddPeer: %w", err)
	}
	return nil
}

// RemovePeer удаляет пир (UAPI remove=true).
func (s *Server) RemovePeer(pubKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running { return fmt.Errorf("AWG сервер не запущен") }
	uapi := "public_key=" + hexKey(pubKey) + "\nremove=true\n"
	return s.dev.IpcSet(uapi)
}

// PubKey — публичный ключ сервера (для клиентских конфигов).
func (s *Server) PubKey() string { return s.pubKey }

// Port — UDP порт сервера.
func (s *Server) Port() int { return s.port }

// PeersUAPI — полный UAPI get (для диагностики: пиры, handshake).
func (s *Server) PeersUAPI() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dev == nil { return "" }
	var buf strings.Builder
	if err := s.dev.IpcGetOperation(&buf); err != nil { return "" }
	return buf.String()
}

// Running — запущен ли сервер.
func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Stop останавливает AWG-сервер.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dev != nil { s.dev.Close() }
	s.running = false
}

// devicePubKey извлекает pub key через UAPI get.
func (s *Server) devicePubKey() string {
	// IpcGet возвращает full конфиг; парсим public_key=
	var buf strings.Builder
	if err := s.dev.IpcGetOperation(&buf); err != nil { return "" }
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, "public_key=") {
			return strings.TrimPrefix(line, "public_key=")
		}
	}
	return ""
}

// hexKey — base64 ключ → hex (UAPI формат amneziawg-go).
func hexKey(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil { return b64 }
	return fmt.Sprintf("%x", raw)
}

// AssignIP — назначает свободный IP пиру из подсети (10.8.1.x).
func AssignIP(subnet string, used map[string]bool) (string, error) {
	_, netw, err := net.ParseCIDR(subnet)
	if err != nil { return "", err }
	ip := netw.IP.To4()
	if ip == nil { return "", fmt.Errorf("только IPv4") }
	base := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	for host := uint32(2); host < 255; host++ {
		cand := fmt.Sprintf("%d.%d.%d.%d/32", byte((base+host)>>24), byte((base+host)>>16), byte((base+host)>>8), byte(base+host))
		if !used[cand] { return cand, nil }
	}
	return "", fmt.Errorf("нет свободных IP в подсети")
}