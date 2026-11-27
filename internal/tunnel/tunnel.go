// Package tunnel — конфиги каскадного туннеля мастер→нода на разных транспортах.
// УРОК (исследование Xray 26.x): не ограничены 3X-UI — любой транспорт.
// xhttp+reality (приоритет, лучший анти-DPI), ws/grpc/httpupgrade+tls, hysteria2 (UDP brutal), tcp+reality.
// ВАЖНО: flow=xtls-rprx-vision только tcp+reality/tls; h2/h3/quic транспорты УДАЛЕНЫ в 26.x.
// УРОК (эмпирическая проба): транспорт проверяется реальным подключением, не «по коду».
package tunnel

import (
	"encoding/json"
	"fmt"
)

// Transport — тип каскадного туннеля.
type Transport string

const (
	TCPReality   Transport = "tcp-reality"   // дефолт (проверен E2E на MSKtest)
	XHTTPReality Transport = "xhttp-reality" // приоритет: лучший анти-DPI (H1/H2/H3 multiplex)
	WSTLS        Transport = "ws-tls"
	GRPCTLS      Transport = "grpc-tls"
	Hysteria2    Transport = "hysteria2" // UDP, нативный, brutal congestion
)

// Params — параметры туннеля (генерируются при provision ноды).
type Params struct {
	Transport  Transport
	Host       string // адрес ноды (IP или домен)
	Port       int
	UUID       string // tunnel uuid (общий для каскада)
	PublicKey  string // REALITY pub (для *-reality)
	PrivateKey string // REALITY priv (нода inbound)
	ShortID    string
	SNI        string // REALITY serverName / TLS SNI
	TLSCert    string // путь к серту на ноде (для *-tls)
	TLSKey     string
	Hy2Pass    string // hysteria2 auth password
	Hy2Obfs    string // hysteria2 salamander obfs password (опц.)
	MTU        int    // MTU туннеля (0 = не задавать sockopt; для hysteria2 = udpMTU)
	Path       string // ws/xhttp path ("" → /tunnel)
	ServiceName string // grpc serviceName ("" → tunnel)
}

func (p Params) path() string { if p.Path != "" { return p.Path }; return "/tunnel" }
func (p Params) svc() string  { if p.ServiceName != "" { return p.ServiceName }; return "tunnel" }

// NodeInbound — JSON inbound ноды (что слушает нода для туннеля мастера).
func (p Params) NodeInbound() (map[string]any, error) {
	base := map[string]any{
		"tag": "vless-tunnel", "listen": "0.0.0.0", "port": p.Port,
	}
	if p.MTU > 0 { base["sockopt"] = map[string]any{"mtu": p.MTU} }
	switch p.Transport {
	case TCPReality, XHTTPReality:
		network := "tcp"
		stream := map[string]any{"network": network, "security": "reality",
			"realitySettings": map[string]any{"show": false, "dest": "127.0.0.1:8443", "xver": 0,
				"serverNames": []string{p.SNI}, "privateKey": p.PrivateKey, "shortIds": []string{p.ShortID}}}
		if p.Transport == XHTTPReality {
			stream["network"] = "xhttp"
			stream["xhttpSettings"] = map[string]any{"path": p.path(), "mode": "auto"}
		}
		base["protocol"] = "vless"
		base["settings"] = map[string]any{"clients": []any{map[string]any{"id": p.UUID, "email": "master-tunnel"}}, "decryption": "none"}
		base["streamSettings"] = stream
	case WSTLS, GRPCTLS:
		network := "ws"
		if p.Transport == GRPCTLS {
			network = "grpc"
		}
		stream := map[string]any{"network": network, "security": "tls",
			"tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": p.TLSCert, "keyFile": p.TLSKey}}}}
		if network == "ws" {
			stream["wsSettings"] = map[string]any{"path": p.path()}
		} else {
			stream["grpcSettings"] = map[string]any{"serviceName": p.svc()}
		}
		base["protocol"] = "vless"
		base["settings"] = map[string]any{"clients": []any{map[string]any{"id": p.UUID, "email": "master-tunnel"}}, "decryption": "none"}
		base["streamSettings"] = stream
	case Hysteria2:
		// нативный hysteria2 inbound Xray 26.x (UDP, auth password, salamander опц.)
		// УРОК (live-исследование): obfs НЕ в hysteriaSettings.obfs (молча игнорируется!) —
		// правильно: streamSettings.finalmask.udp[] (salamander mask).
		base["protocol"] = "hysteria"
		base["settings"] = map[string]any{"version": 2, "clients": []any{map[string]any{"auth": p.Hy2Pass, "email": "master-tunnel"}}}
		stream := map[string]any{"network": "hysteria", "security": "tls",
			"tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": p.TLSCert, "keyFile": p.TLSKey}}, "alpn": []string{"h3"}},
			"hysteriaSettings": map[string]any{"version": 2}}
		if p.MTU > 0 { stream["hysteriaSettings"].(map[string]any)["udpMTU"] = p.MTU }
		if p.Hy2Obfs != "" {
			// salamander obfs через finalmask.udp (УРОК: порядок [salamander, udphop])
			stream["finalmask"] = map[string]any{"udp": []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": p.Hy2Obfs}}}}
		}
		base["streamSettings"] = stream
	default:
		return nil, fmt.Errorf("неизвестный транспорт: %s", p.Transport)
	}
	return base, nil
}

// MasterOutbound — JSON outbound мастера (как мастер подключается к ноде).
func (p Params) MasterOutbound(tag string) (map[string]any, error) {
	ob := map[string]any{"tag": tag}
	if p.MTU > 0 { ob["sockopt"] = map[string]any{"mtu": p.MTU} }
	switch p.Transport {
	case TCPReality, XHTTPReality:
		network := "tcp"
		stream := map[string]any{"network": network, "security": "reality",
			"realitySettings": map[string]any{"show": false, "fingerprint": "chrome", "serverName": p.SNI, "publicKey": p.PublicKey, "shortId": p.ShortID}}
		if p.Transport == XHTTPReality {
			stream["network"] = "xhttp"
			stream["xhttpSettings"] = map[string]any{"path": p.path(), "mode": "auto"}
		}
		ob["protocol"] = "vless"
		ob["settings"] = map[string]any{"vnext": []any{map[string]any{"address": p.Host, "port": p.Port,
			"users": []any{map[string]any{"id": p.UUID, "encryption": "none", "flow": ""}}}}}
		ob["streamSettings"] = stream
	case WSTLS, GRPCTLS:
		network := "ws"
		if p.Transport == GRPCTLS {
			network = "grpc"
		}
		stream := map[string]any{"network": network, "security": "tls",
			"tlsSettings": map[string]any{"serverName": p.SNI, "fingerprint": "chrome"}}
		if network == "ws" {
			stream["wsSettings"] = map[string]any{"path": p.path()}
		} else {
			stream["grpcSettings"] = map[string]any{"serviceName": p.svc()}
		}
		ob["protocol"] = "vless"
		ob["settings"] = map[string]any{"vnext": []any{map[string]any{"address": p.Host, "port": p.Port,
			"users": []any{map[string]any{"id": p.UUID, "encryption": "none", "flow": ""}}}}}
		ob["streamSettings"] = stream
	case Hysteria2:
		// УРОК (live-исследование): auth НЕ в settings.auth (игнорируется → 404!) —
		// правильно: settings{version,address,port} + streamSettings.hysteriaSettings.auth.
		ob["protocol"] = "hysteria"
		ob["settings"] = map[string]any{"version": 2, "address": p.Host, "port": p.Port}
		stream := map[string]any{"network": "hysteria", "security": "tls",
			"tlsSettings": map[string]any{"serverName": p.SNI, "alpn": []string{"h3"}, "fingerprint": "chrome"},
			"hysteriaSettings": map[string]any{"version": 2, "auth": p.Hy2Pass}}
		if p.MTU > 0 { stream["hysteriaSettings"].(map[string]any)["udpMTU"] = p.MTU }
		if p.Hy2Obfs != "" {
			stream["finalmask"] = map[string]any{"udp": []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": p.Hy2Obfs}}}}
		}
		ob["streamSettings"] = stream
	default:
		return nil, fmt.Errorf("неизвестный транспорт: %s", p.Transport)
	}
	return ob, nil
}

// NodeInboundJSON — готовый JSON inbound ноды.
func (p Params) NodeInboundJSON() (string, error) {
	ib, err := p.NodeInbound()
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(ib, "", "  ")
	return string(b), err
}