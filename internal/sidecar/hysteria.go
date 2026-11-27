package sidecar

import (
	"fmt"
	"strings"
)

// HysteriaConfig — параметры hysteria2-сервера (оригинал apernet/hysteria).
// УРОК (владелец): скрытность настраивается — obfs salamander, masquerade под реальный
// сайт (proxy), port hopping. Панель генерит server.yaml из этих параметров.
type HysteriaConfig struct {
	Port        int    // UDP порт (443 дефолт — маскировка под HTTPS)
	CertFile    string // TLS серт (LE от домена мастера)
	KeyFile     string
	ObfsEnabled bool   // salamander obfs (скрывает QUIC-паттерн от DPI)
	ObfsPass    string
	MasqMode    string // "proxy" (реальный сайт) | "file" (свой camo) | "" (выкл)
	MasqURL     string // https://www.wikipedia.org (proxy — при зондировании отдаёт реальный сайт)
	MasqDir     string // /var/www/camo (file)
	MasqRewriteHost bool // переписывать Host header (proxy)
	HoppingEnabled bool  // port hopping (клиент скачет по портам — сложнее блокировать)
	HopRange    string // "20000-40000" (диапазон UDP портов)
	HopInterval int    // секунд между сменой порта (30 дефолт)
	Users       []HysteriaUser // auth userpass (панель добавляет клиентов)
	BandwidthUp   string // "100 mbps" (brutal — для клиентов с потерями)
	BandwidthDown string
}

type HysteriaUser struct {
	Name string
	Pass string
}

// RenderServerYAML — server.yaml для оригинального hysteria.
// Формат по документации apernet/hysteria (исследование уточнит детали).
func (c HysteriaConfig) RenderServerYAML() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("listen: :%d\n", c.Port))
	b.WriteString("tls:\n")
	b.WriteString(fmt.Sprintf("  cert: %s\n", c.CertFile))
	b.WriteString(fmt.Sprintf("  key: %s\n", c.KeyFile))
	if c.ObfsEnabled {
		b.WriteString("obfs:\n  type: salamander\n  salamander:\n")
		b.WriteString(fmt.Sprintf("    password: %s\n", c.ObfsPass))
	}
	// masquerade: при HTTP-пробе (активное зондирование ТСПУ) отдаём реальный сайт
	if c.MasqMode != "" {
		b.WriteString("masquerade:\n")
		b.WriteString(fmt.Sprintf("  type: %s\n", c.MasqMode))
		if c.MasqMode == "proxy" {
			b.WriteString(fmt.Sprintf("  proxy:\n    url: %s\n", c.MasqURL))
			b.WriteString(fmt.Sprintf("    rewriteHost: %t\n", c.MasqRewriteHost))
		} else if c.MasqMode == "file" {
			b.WriteString(fmt.Sprintf("  file:\n    dir: %s\n", c.MasqDir))
		}
	}
	// auth: userpass (панель управляет клиентами)
	if len(c.Users) > 0 {
		b.WriteString("auth:\n  type: userpass\n  userpass:\n")
		for _, u := range c.Users {
			b.WriteString(fmt.Sprintf("    %s: %s\n", u.Name, u.Pass))
		}
	}
	// port hopping (серверная часть: диапазон портов слушания)
	if c.HoppingEnabled && c.HopRange != "" {
		b.WriteString(fmt.Sprintf("listen: :%d\n", c.Port)) // основной
		b.WriteString("# port hopping: клиент использует диапазон, сервер слушает через iptables redirect\n")
		b.WriteString(fmt.Sprintf("# hop range: %s, interval: %ds\n", c.HopRange, c.HopInterval))
	}
	if c.BandwidthUp != "" || c.BandwidthDown != "" {
		b.WriteString("bandwidth:\n")
		if c.BandwidthUp != "" { b.WriteString(fmt.Sprintf("  up: %s\n", c.BandwidthUp)) }
		if c.BandwidthDown != "" { b.WriteString(fmt.Sprintf("  down: %s\n", c.BandwidthDown)) }
	}
	return b.String()
}

// HoppingNATRules — iptables правила для port hopping (сервер):
// диапазон UDP портов → redirect на основной порт hysteria.
// Клиент скачет по портам (hop interval), ТСПУ сложнее блокировать по одному порту.
func HoppingNATRules(hopRange string, mainPort int) []string {
	// "20000-40000" → iptables -t nat -A PREROUTING -p udp --dport 20000:40000 -j REDIRECT --to-ports <main>
	parts := strings.SplitN(hopRange, "-", 2)
	if len(parts) != 2 {
		return nil
	}
	return []string{
		fmt.Sprintf("iptables -t nat -A PREROUTING -p udp --dport %s:%s -j REDIRECT --to-ports %d", parts[0], parts[1], mainPort),
	}
}

// ClientLink — hysteria2:// ссылка для клиента (с obfs/hopping параметрами).
func (c HysteriaConfig) ClientLink(user, pass, host, sni string) string {
	params := []string{}
	if sni != "" { params = append(params, "sni="+sni) }
	if c.ObfsEnabled {
		params = append(params, "obfs=salamander", "obfs-password="+c.ObfsPass)
	}
	if c.HoppingEnabled && c.HopRange != "" {
		params = append(params, "hop="+c.HopRange, "hop-interval="+fmt.Sprintf("%d", c.HopInterval))
	}
	q := strings.Join(params, "&")
	return fmt.Sprintf("hysteria2://%s:%s@%s:%d?%s#%s", user, pass, host, c.Port, q, "XKIT-Hy2")
}