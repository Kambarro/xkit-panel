package amnezia

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// Client — AmneziaWG КЛИЕНТ внутри процесса (userspace netstack, без TUN/root).
// Для каскада мастер→нода: мастер поднимает AWG-клиента к ноде-серверу,
// трафик идёт через userspace TCP/IP стек (tnet.DialContext). Не нужен root/TUN на мастере.
// УРОК: amneziawg-go netstack.CreateNetTUN — клиентский стек как в официальном примере.
type Client struct {
	mu      sync.Mutex
	dev     *awgdevice.Device
	tnet    *netstack.Net
	running bool
	localIP string
}

// ClientConfig — параметры AWG-клиента (подключение к ноде-серверу).
type ClientConfig struct {
	PlainWG      bool      // без AWG обфускации (обычный WG)
	PrivKey      string    // клиентский private key (base64)
	PeerPubKey   string    // публичный ключ ноды-сервера (base64)
	PresharedKey string    // опционально
	Endpoint     string    // host:port ноды (UDP)
	LocalIP      string    // IP клиента в туннеле (10.9.0.2)
	Params       AWGParams // параметры обфускации (ДОЛЖНЫ совпадать с сервером)
	MTU          int
}

// NewClient создаёт AWG-клиента (не запускает).
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.PrivKey == "" || cfg.PeerPubKey == "" || cfg.Endpoint == "" {
		return nil, fmt.Errorf("AWG client: нужны privKey, peerPubKey, endpoint")
	}
	if cfg.LocalIP == "" { cfg.LocalIP = "10.9.0.2" }
	if cfg.PlainWG { cfg.MTU = 1420 } else {
		if cfg.MTU == 0 { cfg.MTU = cfg.Params.MTU }
		if cfg.MTU == 0 { cfg.MTU = 1280 }
	}
	return &Client{localIP: cfg.LocalIP}, nil
}

// Start поднимает AWG-клиента: netstack TUN + device + peer (нода).
func (c *Client) Start(cfg ClientConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running { return nil }
	// УРОК (AWG каскад): MTU вычислялся в NewClient в ЛОКАЛЬНУЮ копию cfg,
	// а Start получал оригинал с MTU=0 → CreateNetTUN(mtu=0) → gvisor НЕ шлёт SYN
	// (DialContext висит, netstack WriteNotify не срабатывает). Вычисляем ЗДЕСЬ.
	if cfg.PlainWG {
		cfg.MTU = 1420
	} else if cfg.MTU == 0 {
		cfg.MTU = cfg.Params.MTU
		if cfg.MTU == 0 { cfg.MTU = 1280 }
	}
	localAddr, err := netip.ParseAddr(c.localIP)
	if err != nil { return fmt.Errorf("AWG client localIP: %w", err) }
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{localAddr}, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, cfg.MTU)
	if err != nil { return fmt.Errorf("AWG client CreateNetTUN: %w", err) }
	c.tnet = tnet
	bind := awgconn.NewStdNetBind()
	logger := awgdevice.NewLogger(awgdevice.LogLevelError, "(awg-client) ")
	dev := awgdevice.NewDevice(tunDev, bind, logger)
	c.dev = dev
	// UAPI: клиентский private_key + AWG-параметры + peer (нода)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("private_key=%s\n", hexKey(cfg.PrivKey)))
	if !cfg.PlainWG {
	b.WriteString(fmt.Sprintf("jc=%d\n", cfg.Params.Jc))
	b.WriteString(fmt.Sprintf("jmin=%d\n", cfg.Params.Jmin))
	b.WriteString(fmt.Sprintf("jmax=%d\n", cfg.Params.Jmax))
	b.WriteString(fmt.Sprintf("s1=%d\n", cfg.Params.S1))
	b.WriteString(fmt.Sprintf("s2=%d\n", cfg.Params.S2))
	b.WriteString(fmt.Sprintf("s3=%d\n", cfg.Params.S3))
	b.WriteString(fmt.Sprintf("s4=%d\n", cfg.Params.S4))
	b.WriteString(fmt.Sprintf("h1=%s\n", cfg.Params.H1))
	b.WriteString(fmt.Sprintf("h2=%s\n", cfg.Params.H2))
	b.WriteString(fmt.Sprintf("h3=%s\n", cfg.Params.H3))
	b.WriteString(fmt.Sprintf("h4=%s\n", cfg.Params.H4))
	if cfg.Params.I1 != "" { b.WriteString(fmt.Sprintf("i1=%s\n", cfg.Params.I1)) }
	b.WriteString(fmt.Sprintf("random_trailers=%t\n", cfg.Params.RandomTrailers))
	b.WriteString(fmt.Sprintf("disable_cookies=%t\n", cfg.Params.DisableCookies))
	}
	// peer = нода-сервер
	b.WriteString(fmt.Sprintf("public_key=%s\n", hexKey(cfg.PeerPubKey)))
	if cfg.PresharedKey != "" { b.WriteString(fmt.Sprintf("preshared_key=%s\n", hexKey(cfg.PresharedKey))) }
	b.WriteString("allowed_ip=0.0.0.0/0\n")
	b.WriteString(fmt.Sprintf("endpoint=%s\n", cfg.Endpoint))
	b.WriteString("persistent_keepalive_interval=25\n")
	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return fmt.Errorf("AWG client IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("AWG client Up: %w", err)
	}
	c.running = true
	return nil
}

// DialContext — dial через AWG-туннель (userspace). Для SOCKS-форвардинга каскада.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c.mu.Lock()
	tnet := c.tnet
	c.mu.Unlock()
	if tnet == nil { return nil, fmt.Errorf("AWG client не запущен") }
	return tnet.DialContext(ctx, network, addr)
}

// DialTCP — TCP dial через туннель (без DNS, специализированный).
func (c *Client) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	c.mu.Lock()
	tnet := c.tnet
	c.mu.Unlock()
	if tnet == nil { return nil, fmt.Errorf("AWG client не запущен") }
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil { return nil, err }
	return tnet.DialContextTCP(ctx, tcpAddr)
}

// Stop останавливает клиента.
func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dev != nil { c.dev.Close() }
	c.running = false
}

// UAPI — полный конфиг клиента (диагностика handshake).
func (c *Client) UAPI() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dev == nil { return "" }
	var buf strings.Builder
	if err := c.dev.IpcGetOperation(&buf); err != nil { return "" }
	return buf.String()
}

// Running — запущен ли клиент.
func (c *Client) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}