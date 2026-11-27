// Package subscription — генерация ссылок/подписок для клиентов XKIT Panel.
// УРОК (владелец): подписки формируются из ВСЕХ включённых протоколов мастера (inbounds таблица),
// переключатель протокола в панели → подписка меняется на лету (динамически при запросе).
// Одна ссылка на протокол (базовый UUID): страна выхода = clients.country в БД,
// меняется через API подписки/бот — vlessRoute/страновые профили удалены.
package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// MasterParams — параметры мастера для ссылок (REALITY дефолт).
type MasterParams struct {
	Address     string // example.com (один адрес для всех)
	Port        int    // 443
	SNI         string // example.com
	PublicKey   string // REALITY publicKey мастера
	ShortID     string // REALITY shortId
	Fingerprint string // chrome
	Flow        string // xtls-rprx-vision
}

// InboundSpec — включённый протокол мастера (из store.Inbound) для генерации ссылок.
type InboundSpec struct {
	Tag      string
	Protocol string // vless/vmess/trojan/shadowsocks/hysteria
	Port     int
	Network  string         // tcp/ws/grpc/xhttp/httpupgrade
	Security string         // reality/tls/none
	Settings map[string]any // JSON settings (clients, realityPub/Sid/Sni, password, method...)
	Stream   map[string]any // JSON streamSettings
}

// VlessLink генерирует vless:// ссылку для клиента (REALITY), базовый UUID.
func VlessLink(uuid, email, name string, m MasterParams) string {
	remark := name
	if remark == "" {
		remark = email
	}
	params := url.Values{}
	params.Set("encryption", "none")
	params.Set("security", "reality")
	params.Set("sni", m.SNI)
	params.Set("fp", m.Fingerprint)
	params.Set("pbk", m.PublicKey)
	params.Set("sid", m.ShortID)
	params.Set("flow", m.Flow)
	params.Set("type", "tcp")
	params.Set("headerType", "none")
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", uuid, m.Address, m.Port, params.Encode(), url.PathEscape(remark))
}

// LinkForInbound — ссылка клиента для конкретного включённого протокола мастера.
// Поддерживает vless (reality/tls/none × tcp/ws/grpc/xhttp), trojan, hysteria2.
// Базовый UUID на все протоколы: страна — clients.country (assignment на сервере).
func LinkForInbound(spec InboundSpec, uuid, email, name string, address string) string {
	remark := name
	if remark == "" {
		remark = email
	}
	protoLabel := spec.Protocol
	if spec.Network != "" && spec.Network != "tcp" {
		protoLabel += "-" + spec.Network
	}
	remark = fmt.Sprintf("%s (%s)", remark, protoLabel)

	switch spec.Protocol {
	case "vless":
		params := url.Values{}
		params.Set("encryption", "none")
		params.Set("type", networkType(spec.Network))
		applySecurity(params, spec, address)
		applyTransport(params, spec)
		// flow только tcp+reality/tls (УРОК Xray 26.x)
		if (spec.Network == "tcp" || spec.Network == "") && (spec.Security == "reality" || spec.Security == "tls") {
			params.Set("flow", "xtls-rprx-vision")
		}
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s", uuid, address, spec.Port, params.Encode(), url.PathEscape(remark))
	case "trojan":
		// УРОК: per-client пароль = uuid (AddUserProto trojan.Account{Password:uuid}).
		// settings.password — общий (может быть пуст); для per-client используем uuid.
		pass := clientAuth(spec.Settings, email)
		if pass == "" {
			pass = strSetting(spec.Settings, "password")
		}
		if pass == "" {
			pass = uuid
		}
		params := url.Values{}
		params.Set("type", networkType(spec.Network))
		applySecurity(params, spec, address)
		applyTransport(params, spec)
		return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", url.QueryEscape(pass), address, spec.Port, params.Encode(), url.PathEscape(remark))
	case "vmess":
		// VMess: base64(JSON) по стандарту v2rayN. alterId=0, security=auto.
		obj := map[string]any{
			"v": "2", "ps": remark, "add": address, "port": spec.Port,
			"id": uuid, "aid": 0, "scy": "auto", "net": networkType(spec.Network),
			"type": "none", "host": "", "path": "", "tls": "",
		}
		if spec.Security == "tls" || spec.Security == "reality" {
			obj["tls"] = "tls"
			sni := strStream(spec.Stream, "tlsSettings", "serverName")
			if sni == "" {
				sni = address
			}
			obj["sni"] = sni
		}
		if wsPath := strStream(spec.Stream, "wsSettings", "path"); wsPath != "" {
			obj["path"] = wsPath
		}
		if grpcSvc := strStream(spec.Stream, "grpcSettings", "serviceName"); grpcSvc != "" {
			obj["path"] = grpcSvc
		}
		b, _ := json.Marshal(obj)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	case "shadowsocks":
		// SS2022: ss://base64(method:password)@host:port#remark
		method := strSetting(spec.Settings, "method")
		pass := strSetting(spec.Settings, "password")
		if method == "" {
			method = "2022-blake3-aes-128-gcm"
		}
		userinfo := base64.StdEncoding.EncodeToString([]byte(method + ":" + pass))
		return fmt.Sprintf("ss://%s@%s:%d#%s", userinfo, address, spec.Port, url.PathEscape(remark))
	case "hysteria", "hysteria2":
		// УРОК: per-user auth = uuid клиента (AddUserProto hysteria account.Auth=uuid).
		pass := uuid
		if p := clientAuth(spec.Settings, email); p != "" {
			pass = p
		}
		params := url.Values{}
		// УРОК (аудит #7): пустой sni → клиент не валидирует TLS (allowInsecure
		// удалён в Xray 26.x). serverName терялся при пересоздании inbound —
		// fallback на address (сертификат выдан на домен мастера).
		sni := strStream(spec.Stream, "tlsSettings", "serverName")
		if sni == "" {
			sni = address
		}
		params.Set("sni", sni)
		// УРОК (live-исследование): obfs в streamSettings.finalmask.udp[] (salamander),
		// НЕ в hysteriaSettings.obfs (Xray молча игнорирует последнее).
		if obfsPass := finalmaskSalamander(spec.Stream); obfsPass != "" {
			params.Set("obfs", "salamander")
			params.Set("obfs-password", obfsPass)
		}
		return fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s", url.QueryEscape(pass), address, spec.Port, params.Encode(), url.PathEscape(remark))
	}
	return ""
}

// finalmaskSalamander — пароль salamander из streamSettings.finalmask.udp[] (правильное место).
func finalmaskSalamander(stream map[string]any) string {
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
				if p, ok := st["password"].(string); ok {
					return p
				}
			}
		}
	}
	return ""
}

func networkType(network string) string {
	switch network {
	case "ws":
		return "ws"
	case "grpc":
		return "grpc"
	case "xhttp", "splithttp":
		return "xhttp"
	case "httpupgrade":
		return "httpupgrade"
	default:
		return "tcp"
	}
}

func applySecurity(params url.Values, spec InboundSpec, address string) {
	switch spec.Security {
	case "reality":
		params.Set("security", "reality")
		pub := strSetting(spec.Settings, "realityPub")
		sid := strSetting(spec.Settings, "realitySid")
		sni := strSetting(spec.Settings, "realitySni")
		if sni == "" {
			sni = address
		}
		params.Set("sni", sni)
		fp := strSetting(spec.Settings, "fingerprint")
		if fp == "" {
			fp = "chrome"
		}
		params.Set("fp", fp)
		params.Set("pbk", pub)
		params.Set("sid", sid)
	case "tls":
		params.Set("security", "tls")
		sni := strStream(spec.Stream, "tlsSettings", "serverName")
		if sni == "" {
			sni = address
		}
		params.Set("sni", sni)
		fp := strSetting(spec.Settings, "fingerprint")
		if fp == "" {
			fp = "chrome"
		}
		params.Set("fp", fp)
	case "ss2022":
		// SS2022 own AEAD encryption — no TLS/REALITY wrapper
		params.Set("security", "ss2022")
	default:
		params.Set("security", "none")
	}
}

func applyTransport(params url.Values, spec InboundSpec) {
	switch spec.Network {
	case "ws":
		params.Set("path", strStream(spec.Stream, "wsSettings", "path"))
	case "grpc":
		params.Set("serviceName", strStream(spec.Stream, "grpcSettings", "serviceName"))
		params.Set("mode", "gun")
	case "xhttp", "splithttp":
		params.Set("path", strStream(spec.Stream, "xhttpSettings", "path"))
		params.Set("mode", "auto")
	case "httpupgrade":
		params.Set("path", strStream(spec.Stream, "httpupgradeSettings", "path"))
	}
}

func strSetting(settings map[string]any, key string) string {
	if v, ok := settings[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func strStream(stream map[string]any, section, key string) string {
	if sec, ok := stream[section].(map[string]any); ok {
		if s, ok := sec[key].(string); ok {
			return s
		}
	}
	return ""
}

func nestedSetting(stream map[string]any, section, key string) map[string]any {
	if sec, ok := stream[section].(map[string]any); ok {
		if m, ok := sec[key].(map[string]any); ok {
			return m
		}
	}
	return nil
}

func strFromMap(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func clientAuth(settings map[string]any, email string) string {
	if clients, ok := settings["clients"].([]any); ok {
		for _, c := range clients {
			if cm, ok := c.(map[string]any); ok {
				if cm["email"] == email {
					if a, ok := cm["auth"].(string); ok {
						return a
					}
					if p, ok := cm["password"].(string); ok {
						return p
					}
				}
			}
		}
	}
	return ""
}

// Subscription генерирует base64-подписку (список ссылок).
func Subscription(links []string) string {
	body := strings.Join(links, "\n")
	return base64.StdEncoding.EncodeToString([]byte(body))
}

// ClientLinks — базовая ссылка клиента (legacy REALITY-fallback, inbounds пусты).
func ClientLinks(uuid, email, name string, m MasterParams) []string {
	return []string{VlessLink(uuid, email, name, m)}
}

// LinksFromInbounds — ссылки клиента из ВСЕХ включённых протоколов мастера.
// УРОК (владелец): одна ссылка на протокол (базовый UUID), страна меняется через
// API подписки/бот (clients.country → assignment). Страновых профилей НЕТ.
func LinksFromInbounds(specs []InboundSpec, uuid, email, name string, address string) []string {
	var links []string
	for _, spec := range specs {
		if l := LinkForInbound(spec, uuid, email, name, address); l != "" {
			links = append(links, l)
		}
	}
	return links
}

// HostEntry — рекламная точка входа мастера (P1 #10, CDN-фронтинг/per-host SNI).
type HostEntry struct {
	Address string
	Port    int
	SNI     string // пусто = Address
	Label   string
}

// LinksFromInboundsHosts — ссылки с НЕСКОЛЬКИМИ точками входа (hosts).
// УРОК (3x-ui managed hosts / Remnawave hosts): домен вместо IP + CDN-фронтинг.
// Каждый host × каждый протокол (базовый UUID). Реальный IP скрыт за CDN.
// Если hosts пуст — fallback на одиночный address (обратная совместимость).
func LinksFromInboundsHosts(specs []InboundSpec, uuid, email, name string, hosts []HostEntry, fallbackAddress string) []string {
	if len(hosts) == 0 {
		return LinksFromInbounds(specs, uuid, email, name, fallbackAddress)
	}
	var links []string
	for _, h := range hosts {
		addr := h.Address
		sni := h.SNI
		if sni == "" {
			sni = addr
		}
		for _, spec := range specs {
			// per-host: подменяем адрес/порт/SNI в spec (копия)
			hs := spec
			hs.Port = h.Port
			if hs.Security == "reality" {
				if hs.Settings == nil {
					hs.Settings = map[string]any{}
				}
				hs.Settings["realitySni"] = sni
			} else if hs.Security == "tls" {
				if hs.Stream == nil {
					hs.Stream = map[string]any{}
				}
				ts, _ := hs.Stream["tlsSettings"].(map[string]any)
				if ts == nil {
					ts = map[string]any{}
				}
				ts["serverName"] = sni
				hs.Stream["tlsSettings"] = ts
			}
			label := name
			if h.Label != "" {
				label = name + " " + h.Label
			}
			// 1 ссылка на протокол на host (страна — параметр подписки, не дубли).
			if l := LinkForInbound(hs, uuid, email, label, addr); l != "" {
				links = append(links, l)
			}
		}
	}
	return links
}

// ParseInboundSpec — store.Inbound JSON → InboundSpec.
func ParseInboundSpec(tag, protocol string, port int, network, security, settingsJSON, streamJSON string) InboundSpec {
	var settings, stream map[string]any
	json.Unmarshal([]byte(settingsJSON), &settings)
	json.Unmarshal([]byte(streamJSON), &stream)
	if settings == nil {
		settings = map[string]any{}
	}
	if stream == nil {
		stream = map[string]any{}
	}
	return InboundSpec{Tag: tag, Protocol: protocol, Port: port, Network: network, Security: security, Settings: settings, Stream: stream}
}
