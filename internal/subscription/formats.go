package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// Генераторы форматов подписок (порт логики XKIT main clash_yaml_gen/singbox_json_gen).
// УРОК (исследование): Hiddify 4.x ломается на Clash-YAML → hiddify получает raw;
// clash/mihomo → YAML, sing-box → JSON, incy → xray-json. RU-routing: geoip/geosite RU direct.

// Proxy — нормализованное представление ссылки для генераторов.
type Proxy struct {
	Name     string
	Type     string // vless/trojan/hysteria2
	Server   string
	Port     int
	UUID     string
	Password string
	Network  string // tcp/ws/grpc/xhttp
	Security string // reality/tls/none
	SNI      string
	PubKey   string
	ShortID  string
	Flow     string
	Path     string
	Service  string
	Obfs     string
	ObfsPass string
	Method   string // shadowsocks method
}

// ParseLink — vless://trojan://hysteria2:// → Proxy (для генераторов форматов).
func ParseLink(link string) *Proxy {
	p := &Proxy{}
	switch {
	case strings.HasPrefix(link, "vless://"):
		p.Type = "vless"
		rest := strings.TrimPrefix(link, "vless://")
		at := strings.Index(rest, "@")
		if at < 0 { return nil }
		p.UUID = rest[:at]
		rest = rest[at+1:]
		p.Name = fragment(rest)
		hostPort, params := splitParams(rest)
		p.Server, p.Port = splitHostPort(hostPort)
		p.Network = params.Get("type")
		p.Security = params.Get("security")
		p.SNI = params.Get("sni")
		p.PubKey = params.Get("pbk")
		p.ShortID = params.Get("sid")
		p.Flow = params.Get("flow")
		p.Path = params.Get("path")
		p.Service = params.Get("serviceName")
	case strings.HasPrefix(link, "trojan://"):
		p.Type = "trojan"
		rest := strings.TrimPrefix(link, "trojan://")
		at := strings.Index(rest, "@")
		if at < 0 { return nil }
		p.Password = rest[:at]
		rest = rest[at+1:]
		p.Name = fragment(rest)
		hostPort, params := splitParams(rest)
		p.Server, p.Port = splitHostPort(hostPort)
		p.Network = params.Get("type")
		p.Security = "tls"
		p.SNI = params.Get("sni")
		p.Path = params.Get("path")
		p.Service = params.Get("serviceName")
	case strings.HasPrefix(link, "hysteria2://"), strings.HasPrefix(link, "hy2://"):
		p.Type = "hysteria2"
		rest := strings.TrimPrefix(strings.TrimPrefix(link, "hysteria2://"), "hy2://")
		at := strings.Index(rest, "@")
		if at < 0 { return nil }
		p.Password = rest[:at]
		rest = rest[at+1:]
		p.Name = fragment(rest)
		hostPort, params := splitParams(rest)
		p.Server, p.Port = splitHostPort(hostPort)
		p.SNI = params.Get("sni")
		p.Obfs = params.Get("obfs")
		p.ObfsPass = params.Get("obfs-password")
	case strings.HasPrefix(link, "vmess://"):
		p.Type = "vmess"
		b64 := strings.TrimPrefix(link, "vmess://")
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil { data, err = base64.RawStdEncoding.DecodeString(b64); if err != nil { return nil } }
		var v map[string]any
		if json.Unmarshal(data, &v) != nil { return nil }
		p.Server, _ = v["add"].(string)
		if pf, ok := v["port"].(float64); ok { p.Port = int(pf) } else if ps, ok := v["port"].(string); ok { fmt.Sscanf(ps, "%d", &p.Port) }
		p.UUID, _ = v["id"].(string)
		p.Name, _ = v["ps"].(string)
		p.Network, _ = v["net"].(string)
		p.Path, _ = v["path"].(string)
		p.SNI, _ = v["sni"].(string)
		if tls, _ := v["tls"].(string); tls == "tls" { p.Security = "tls" }
		p.Service, _ = v["path"].(string) // grpc serviceName in path
	case strings.HasPrefix(link, "ss://"):
		p.Type = "shadowsocks"
		rest := strings.TrimPrefix(link, "ss://")
		p.Name = fragment(rest)
		hostPort, _ := splitParams(rest)
		p.Server, p.Port = splitHostPort(hostPort)
		at := strings.Index(rest, "@")
		if at > 0 {
			userinfo := rest[:at]
			// base64(method:password) или method:password
			if dec, err := base64.StdEncoding.DecodeString(userinfo); err == nil {
				userinfo = string(dec)
			} else if dec, err := base64.RawStdEncoding.DecodeString(userinfo); err == nil {
				userinfo = string(dec)
			}
			colon := strings.Index(userinfo, ":")
			if colon > 0 { p.Method = userinfo[:colon]; p.Password = userinfo[colon+1:] }
		}
	default:
		return nil
	}
	if p.Name == "" { p.Name = fmt.Sprintf("%s-%d", p.Type, p.Port) }
	if p.Network == "" { p.Network = "tcp" }
	// УРОК (аудит #7): пустой sni → клиент не валидирует TLS (allowInsecure удалён
	// в Xray 26.x). Адрес сервера — валидный fallback (сертификат выдан на него).
	if p.SNI == "" { p.SNI = p.Server }
	return p
}

// stunBlockDomains — STUN-домены WebRTC (аудит #5): block заставляет WebRTC
// не показывать реальный IP клиента (TURN/TCP или отказ).
var stunBlockDomains = []string{
	"stun.l.google.com", "stun1.l.google.com", "stun2.l.google.com",
	"stun3.l.google.com", "stun4.l.google.com",
	"stun.services.mozilla.com", "stun.stunprotocol.org",
}

// ClashYAML — Clash.Meta/mihomo YAML подписка (дефолт RU-routing).
func ClashYAML(links []string) string { return ClashYAMLRouting(links, nil) }

// ClashYAMLRouting — с кастомными правилами клиента (P2: наш дефолт + его поверх).
// extraRules — готовые clash-строки (routing.ClashRules), вставляются ПЕРЕД MATCH.
func ClashYAMLRouting(links []string, extraRules []string) string {
	var b strings.Builder
	b.WriteString("mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: info\nipv6: false\n")
	// УРОК (аудит #3): без dns-секции mihomo резолвит системным DNS клиента —
	// DNS-утечка к провайдеру. fake-ip перехватывает резолв, DoH идёт через PROXY,
	// fallback+geoip RU фильтр не даёт подменить ответы foreign-доменам.
	// redir-host не берём: он резолвит напрямую и течёт; владелец выбрал fake-ip.
	b.WriteString(`dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "localhost.ptlogin2.qq.com"
    - "+.msftconnecttest.com"
    - "+.msftncsi.com"
  default-nameserver:
    - 1.1.1.1
    - 8.8.8.8
  proxy-server-nameserver:
    - 1.1.1.1
    - 8.8.8.8
  nameserver:
    - "https://1.1.1.1/dns-query#PROXY"
    - "https://8.8.8.8/dns-query#PROXY"
  fallback:
    - "https://dns.google/dns-query#PROXY"
    - "tls://dns.quad9.net#PROXY"
  fallback-filter:
    geoip: true
    geoip-code: RU
    ipcidr:
      - 240.0.0.0/4
`)
	b.WriteString("proxies:\n")
	var names []string
	for _, l := range links {
		p := ParseLink(l)
		if p == nil { continue }
		names = append(names, p.Name)
		b.WriteString(fmt.Sprintf("  - name: %q\n    type: %s\n    server: %s\n    port: %d\n", p.Name, clashType(p.Type), p.Server, p.Port))
		switch p.Type {
		case "vless":
			// УРОК (аудит #11): TCP-транспорты (reality+vision/xhttp/ws) UDP не несут —
			// udp:true вводил в заблуждение и рвал UDP-сессии. udp:false честно.
			b.WriteString(fmt.Sprintf("    uuid: %s\n    network: %s\n    udp: false\n", p.UUID, p.Network))
			if p.Flow != "" { b.WriteString(fmt.Sprintf("    flow: %s\n", p.Flow)) }
			if p.Security == "reality" {
				b.WriteString(fmt.Sprintf("    tls: true\n    servername: %s\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: %s\n", p.SNI, p.PubKey, p.ShortID))
			} else if p.Security == "tls" {
				b.WriteString(fmt.Sprintf("    tls: true\n    servername: %s\n    client-fingerprint: chrome\n", p.SNI))
			}
			switch p.Network {
			case "ws":
				b.WriteString(fmt.Sprintf("    ws-opts:\n      path: %s\n", p.Path))
			case "grpc":
				b.WriteString(fmt.Sprintf("    grpc-opts:\n      grpc-service-name: %s\n", p.Service))
			}
		case "trojan":
			b.WriteString(fmt.Sprintf("    password: %s\n    sni: %s\n    udp: false\n", p.Password, p.SNI))
		case "hysteria2":
			// hysteria2 — единственный транспорт, реально несущий UDP (QUIC)
			b.WriteString(fmt.Sprintf("    password: %s\n    sni: %s\n    udp: true\n", p.Password, p.SNI))
			if p.Obfs != "" {
				b.WriteString(fmt.Sprintf("    obfs: %s\n    obfs-password: %s\n", p.Obfs, p.ObfsPass))
			}
		}
	}
	b.WriteString("proxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n")
	for _, n := range names { b.WriteString(fmt.Sprintf("      - %q\n", n)) }
	b.WriteString("      - DIRECT\n")
	// url-test автовыбор (как коммерческие VPN)
	b.WriteString("  - name: AUTO\n    type: url-test\n    url: https://www.gstatic.com/generate_204\n    interval: 120\n    proxies:\n")
	for _, n := range names { b.WriteString(fmt.Sprintf("      - %q\n", n)) }
	// RU-routing (урок XKIT main: RU-сайты напрямую, остальное через VPN)
	b.WriteString("rules:\n")
	// кастомные правила клиента (P2) — ПЕРЕД дефолтом и MATCH (приоритет клиента)
	for _, r := range extraRules {
		b.WriteString("  - " + r + "\n")
	}
	// УРОК (аудит #5): block QUIC (браузер не обходит TCP-прокси через HTTP/3)
	// и STUN (WebRTC не показывает реальный IP клиента). Выше RU-direct и MATCH.
	b.WriteString(`  - AND,((NETWORK,udp),(DST-PORT,443)),REJECT
  - AND,((NETWORK,udp),(DST-PORT,3478)),REJECT
  - AND,((NETWORK,udp),(DST-PORT,19302)),REJECT
  - AND,((NETWORK,udp),(DST-PORT,5349)),REJECT
`)
	for _, d := range stunBlockDomains {
		b.WriteString(fmt.Sprintf("  - DOMAIN-SUFFIX,%s,REJECT\n", d))
	}
	b.WriteString("  - DOMAIN-KEYWORD,stun.,REJECT\n")
	b.WriteString("  - DOMAIN-KEYWORD,turn.,REJECT\n")
	// GEOIP с no-resolve: резолв не уходит в системный DNS (утечка, аудит #3).
	// GEOSITE category-ru: списка "ru" НЕТ ни в Loyalsoldier, ни в MetaCubeX
	// geosite.dat (проверено парсингом) — мёртвое правило роняло загрузку конфига.
	b.WriteString(`  - GEOIP,RU,DIRECT,no-resolve
  - GEOSITE,category-ru,DIRECT
  - GEOIP,private,DIRECT,no-resolve
  - MATCH,PROXY
`)
	return b.String()
}

func clashType(t string) string {
	if t == "hysteria2" { return "hysteria2" }
	return t
}

// SingboxJSON — sing-box JSON подписка (route: RU direct).
// УРОК (аудит #4): geoip/geosite-правила БЕЗ объявленных ресурсов мертвы в
// sing-box 1.12+ — надёжные domain_suffix .ru/.su/.рф вместо них.
// УРОК (QA BUG-2, проверено реальными 1.11.15/1.12.0 check+run):
//   - dns.servers LEGACY address-формат: новый type/server 1.11 не парсит вовсе;
//     legacy deprecated в 1.12, удалится в 1.14 (shortcut: перейти на новый формат
//     когда 1.11-клиенты уйдут или появится UA-детект версии).
//   - C-1 (Ops 147be19): local БЕЗ detour dial'ит через outboundManager.Default()
//     = select → proxy → резолв домена сервера → снова local → «DNS query loopback
//     in transport[local]» (1.11 И 1.12, доменный адрес сервера). local ОБЯЗАН
//     нести detour:"direct". Legacy+detour=direct БЕЗОПАСЕН в 1.12: Upgrade()
//     ставит Legacy=true → LegacyDNSDialer пропускает IsEmpty (FATAL «detour to
//     an empty direct outbound» был только у NEW-format серверов); в 1.11
//     проверки IsEmpty нет. Проверено исходниками v1.11.15/v1.12.0 + E2E с доменом.
//   - bootstrap: домены прокси-серверов → dns rule local (иначе DoH remote через
//     select резолвит сам себя — «DNS query loopback in transport[remote]»).
//   - hy2 БЕЗ utls (QUIC: «unsupported usage for uTLS»).
//   - xhttp → transport type=http (h2).
func SingboxJSON(links []string) string {
	var outbounds []map[string]any
	var tags []string
	serverDomains := map[string]bool{}
	for _, l := range links {
		p := ParseLink(l)
		if p == nil { continue }
		tags = append(tags, p.Name)
		serverDomains[p.Server] = true
		ob := map[string]any{"tag": p.Name, "server": p.Server, "server_port": p.Port}
		switch p.Type {
		case "vless":
			ob["type"] = "vless"
			ob["uuid"] = p.UUID
			if p.Flow != "" { ob["flow"] = p.Flow }
		case "trojan":
			ob["type"] = "trojan"
			ob["password"] = p.Password
		case "hysteria2":
			ob["type"] = "hysteria2"
			ob["password"] = p.Password
			if p.Obfs != "" { ob["obfs"] = map[string]any{"type": p.Obfs, "password": p.ObfsPass} }
		}
		// tls (hy2 — БЕЗ utls: sing-box запрещает uTLS на QUIC)
		if p.Security == "tls" || p.Security == "reality" || p.Type == "trojan" || p.Type == "hysteria2" {
			tls := map[string]any{"enabled": true, "server_name": p.SNI}
			if p.Type != "hysteria2" {
				tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
			}
			if p.Security == "reality" {
				tls["reality"] = map[string]any{"enabled": true, "public_key": p.PubKey, "short_id": p.ShortID}
			}
			ob["tls"] = tls
		}
		// transport
		switch p.Network {
		case "ws":
			ob["transport"] = map[string]any{"type": "ws", "path": p.Path}
		case "grpc":
			ob["transport"] = map[string]any{"type": "grpc", "service_name": p.Service}
		case "xhttp", "splithttp":
			ob["transport"] = map[string]any{"type": "http", "path": p.Path}
		}
		outbounds = append(outbounds, ob)
	}
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})
	outbounds = append(outbounds, map[string]any{"type": "block", "tag": "block"})
	// RU-домены: суффиксы матчат и сам домен (ru) и поддомены (x.ru) — надёжнее geosite
	ruSuffixes := []any{"ru", "su", "xn--p1ai"}
	// bootstrap-домены: адреса прокси-серверов (не IP) резолвим ПРЯМЫМ dns до туннеля
	var bootstrapDomains []any
	for d := range serverDomains {
		if net.ParseIP(d) == nil {
			bootstrapDomains = append(bootstrapDomains, d)
		}
	}
	dnsRules := []any{
		map[string]any{"domain_suffix": ruSuffixes, "server": "local"},
	}
	if len(bootstrapDomains) > 0 {
		// ПЕРВЫМ: домен прокси-сервера не должен уходить в DoH через сам туннель
		dnsRules = append([]any{map[string]any{"domain": bootstrapDomains, "server": "local"}}, dnsRules...)
	}
	cfg := map[string]any{
		"log": map[string]any{"level": "info"},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"tag": "remote", "address": "https://1.1.1.1/dns-query", "detour": "select"},
				// C-1: detour=direct обязателен (без него local dial'ит через select→proxy
				// = DNS query loopback при доменном адресе сервера). Legacy-формат →
				// 1.12 пропускает IsEmpty-проверку detour'а (FATAL только у new-format).
				map[string]any{"tag": "local", "address": "77.88.8.8", "detour": "direct"},
			},
			// RU-домены резолвятся локально (direct по политике), остальные — DoH через VPN
			"rules":    dnsRules,
			"final":    "remote",
			"strategy": "ipv4_only",
		},
		"inbounds": []any{map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}},
		"outbounds": append([]any{map[string]any{"type": "selector", "tag": "select", "outbounds": append(append([]string{}, tags...), "direct")}}, toAny(outbounds)...),
		"route": map[string]any{
			"rules": []any{
				// DNS приложений перехватываем в резолвер sing-box (иначе утечка к системному DNS)
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				// block QUIC (udp/443): браузер не обходит TCP-прокси через HTTP/3 (аудит #5)
				map[string]any{"network": "udp", "port": 443, "action": "reject"},
				// block STUN: WebRTC не показывает реальный IP клиента (аудит #5)
				map[string]any{"network": "udp", "port": []any{3478, 19302, 5349}, "action": "reject"},
				map[string]any{"domain_suffix": stunBlockDomains, "action": "reject"},
				map[string]any{"domain_keyword": []any{"stun.", "turn."}, "action": "reject"},
				map[string]any{"ip_is_private": true, "outbound": "direct"},
				map[string]any{"domain_suffix": ruSuffixes, "outbound": "direct"},
			},
			"final": "select",
			"auto_detect_interface": true,
			// резолв dial-адресов: legacy dns rule (domain серверов → local) выше —
			// работает и 1.11, и 1.12. default_domain_resolver — поле 1.12-only
			// (1.11 FATAL unknown field), в общий конфиг не кладём.
		},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

// XrayJSON — xray-client JSON (incy и др.): routing RU direct.
func XrayJSON(links []string) string { return XrayJSONRouting(links, nil) }

// XrayJSONRouting — с кастомными правилами клиента (P2). extraRules вставляются
// ПЕРЕД дефолтным RU-routing (приоритет клиента), block-outbound добавляется при block-правилах.
func XrayJSONRouting(links []string, extraRules []map[string]any) string {
	return xrayJSONBuild(links, extraRules, true)
}

// XrayJSONProfiles — все профили видны и выбираемы (для INCY и др. где балансер
// прячет профили за одним «авто»). Без burstObservatory/balancer — первый профиль активен,
// остальные пользователь выбирает вручную. Серверный балансировщик всё равно делает failover.
func XrayJSONProfiles(links []string, extraRules []map[string]any) string {
	return xrayJSONBuild(links, extraRules, false)
}

func xrayJSONBuild(links []string, extraRules []map[string]any, withBalancer bool) string {
	var outbounds []map[string]any
	firstTag := ""
	for _, l := range links {
		p := ParseLink(l)
		if p == nil { continue }
		tag := p.Name
		if firstTag == "" { firstTag = tag }
		ob := map[string]any{"tag": tag, "protocol": p.Type}
		switch p.Type {
		case "vless":
			user := map[string]any{"id": p.UUID, "encryption": "none"}
			if p.Flow != "" { user["flow"] = p.Flow }
			ob["settings"] = map[string]any{"vnext": []any{map[string]any{"address": p.Server, "port": p.Port, "users": []any{user}}}}
		case "trojan":
			ob["settings"] = map[string]any{"servers": []any{map[string]any{"address": p.Server, "port": p.Port, "password": p.Password}}}
		case "hysteria2":
			ob["protocol"] = "hysteria"
			// УРОК (Ops b737b05): HysteriaClientConfig ядра 26.11.9 = {version,address,port} —
			// auth в settings молча дропается (auth 404). Транспорт читает ТОЛЬКО
			// stream.hysteriaSettings.auth — кладём туда (ниже).
			ob["settings"] = map[string]any{"version": 2, "address": p.Server, "port": p.Port}
		case "vmess":
			ob["settings"] = map[string]any{"vnext": []any{map[string]any{"address": p.Server, "port": p.Port, "users": []any{map[string]any{"id": p.UUID, "alterId": 0, "security": "auto"}}}}}
		case "shadowsocks":
			ob["settings"] = map[string]any{"servers": []any{map[string]any{"address": p.Server, "port": p.Port, "method": p.Method, "password": p.Password}}}
		}
		stream := map[string]any{"network": p.Network}
		switch p.Security {
		case "reality":
			stream["security"] = "reality"
			stream["realitySettings"] = map[string]any{"serverName": p.SNI, "fingerprint": "chrome", "publicKey": p.PubKey, "shortId": p.ShortID}
		case "tls":
			stream["security"] = "tls"
			stream["tlsSettings"] = map[string]any{"serverName": p.SNI, "fingerprint": "chrome"}
		}
		if p.Type == "hysteria2" {
			stream["network"] = "hysteria"
			stream["security"] = "tls"
			stream["tlsSettings"] = map[string]any{"serverName": p.SNI, "alpn": []string{"h3"}}
			// auth — единственное место, которое читает транспорт (hysteria.Config.auth)
			stream["hysteriaSettings"] = map[string]any{"version": 2, "auth": p.Password}
			// obfs salamander из ссылки → finalmask UDP-маска (без неё — таймаут под маскированным сервером)
			if p.Obfs == "salamander" && p.ObfsPass != "" {
				stream["finalmask"] = map[string]any{"udp": []any{map[string]any{
					"type": "salamander", "settings": map[string]any{"password": p.ObfsPass},
				}}}
			}
		}
		switch p.Network {
		case "ws": stream["wsSettings"] = map[string]any{"path": p.Path}
		case "grpc": stream["grpcSettings"] = map[string]any{"serviceName": p.Service}
		case "xhttp": stream["xhttpSettings"] = map[string]any{"path": p.Path, "mode": "auto"}
		}
		ob["streamSettings"] = stream
		outbounds = append(outbounds, ob)
	}
	outbounds = append(outbounds, map[string]any{"tag": "direct", "protocol": "freedom"})
	if firstTag == "" { firstTag = "direct" }
	// КЛИЕНТСКИЙ БАЛАНСИРОВЩИК (P1 #9, 3x-ui subscription-balancers): routing.balancers +
	// burstObservatory — failover на стороне клиента даже при недоступном мастере.
	// Дополняет серверный sticky-балансировщик. Если >1 прокси-outbound — включаем.
	var proxyTags []string
	for _, ob := range outbounds {
		if t, _ := ob["tag"].(string); t != "" && t != "direct" {
			proxyTags = append(proxyTags, t)
		}
	}
	routing := map[string]any{"domainStrategy": "IPIfNonMatch", "rules": []any{}}
	// кастомные правила клиента (P2) — первыми (приоритет над дефолтом)
	for _, r := range extraRules {
		routing["rules"] = append(routing["rules"].([]any), r)
	}
	// УРОК (аудит #5): block QUIC (udp/443 — браузер не обходит TCP-прокси через
	// HTTP/3) и STUN (WebRTC не показывает реальный IP клиента). До RU-direct.
	stunDomains := make([]string, 0, len(stunBlockDomains)+2)
	for _, d := range stunBlockDomains {
		stunDomains = append(stunDomains, "domain:"+d)
	}
	stunDomains = append(stunDomains, "keyword:stun.", "keyword:turn.")
	routing["rules"] = append(routing["rules"].([]any),
		map[string]any{"type": "field", "port": "443", "network": "udp", "outboundTag": "block"},
		map[string]any{"type": "field", "port": "3478,19302,5349", "network": "udp", "outboundTag": "block"},
		map[string]any{"type": "field", "domain": stunDomains, "outboundTag": "block"},
	)
	// RU-direct: банки, госсервисы, VK, маркетплейсы, Яндекс — конкретными доменами
	// (быстрее geoip/geosite, не гоняет RU-трафик через VPN). УРОК: MarselNet86/configs-for-vpn.
	// geosite:category-ru: списка "ru" нет в Loyalsoldier/MetaCubeX geosite.dat —
	// мёртвый geosite:ru ронял загрузку всего конфига (проверено xray-core парсером).
	ruDirectDomains := []string{
		"geosite:category-ru",
		"domain:tbank.ru", "domain:tinkoff.ru", "domain:sberbank.ru", "domain:vtb.ru",
		"domain:alfabank.ru", "domain:otpbank.ru", "domain:nspk.ru", "domain:sbrf.ru",
		"domain:gosuslugi.ru", "domain:gov.ru", "domain:nalog.ru", "domain:mos.ru",
		"domain:vk.com", "domain:vk.ru", "domain:vkuser.net", "domain:vk.me", "domain:ok.ru",
		"domain:yandex.ru", "domain:yandex.net", "domain:yandex.com", "domain:ya.ru", "domain:yastatic.net",
		"domain:ozon.ru", "domain:wildberries.ru", "domain:wb.ru", "domain:avito.ru",
		"domain:mail.ru", "domain:dzen.ru", "domain:rutube.ru", "domain:kinopoisk.ru",
		"domain:2gis.ru", "domain:hh.ru", "domain:drom.ru", "domain:auto.ru",
		"domain:magnit.ru", "domain:5ka.ru", "domain:perekrestok.ru", "domain:lemanapro.ru",
		"domain:megamarket.ru", "domain:lamoda.ru", "domain:detmir.ru",
		"domain:rzd.ru", "domain:aeroflot.ru", "domain:tutu.ru", "domain:ostrovok.ru",
		"domain:cdek.ru", "domain:pochta.ru", "domain:mts.ru", "domain:megafon.ru", "domain:beeline.ru",
		"domain:ivi.ru", "domain:gismeteo.ru", "domain:rambler.ru",
		"regexp:.*\\.ru$", "regexp:.*\\.su$", "regexp:.*\\.xn--p1ai$",
	}
	routing["rules"] = append(routing["rules"].([]any),
		map[string]any{"type": "field", "domain": ruDirectDomains, "outboundTag": "direct"},
		map[string]any{"type": "field", "ip": []string{"geoip:ru", "geoip:private"}, "outboundTag": "direct"},
		map[string]any{"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "direct"},
		map[string]any{"type": "field", "port": "22", "outboundTag": "direct"},
	)
	// block-outbound всегда: дефолтные block QUIC/STUN правила есть в каждом конфиге
	outbounds = append(outbounds, map[string]any{"tag": "block", "protocol": "blackhole"})
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"dns": map[string]any{
			"servers": []any{
				"https://one.one.one.one/dns-query",
				"https://dns.google/dns-query",
				map[string]any{
					"address": "https://common.dot.dns.yandex.net/dns-query",
					"domains": []string{"geosite:category-ru", "regexp:.*\\.ru$", "regexp:.*\\.su$", "regexp:.*\\.xn--p1ai$"},
				},
			},
			"queryStrategy": "UseIPv4",
		},
		"inbounds": []any{map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"udp": true}}},
		"outbounds": outbounds,
	}
	if withBalancer && len(proxyTags) > 1 {
		// burstObservatory: health-check прокси, выбирает живой с наименьшим RTT
		cfg["burstObservatory"] = map[string]any{
			"subjectSelector": proxyTags,
			"pingConfig": map[string]any{
				"destination": "https://www.gstatic.com/generate_204",
				"interval": "30s",
				"sampling": 3,
				"timeout": "5s",
			},
		}
		routing["balancers"] = []any{map[string]any{
			"tag": "auto-balancer",
			"selector": proxyTags,
			"strategy": map[string]any{"type": "leastPing"},
		}}
		routing["rules"] = append(routing["rules"].([]any),
			map[string]any{"type": "field", "port": "0-65535", "balancerTag": "auto-balancer"})
	} else {
		routing["rules"] = append(routing["rules"].([]any),
			map[string]any{"type": "field", "port": "0-65535", "outboundTag": firstTag})
	}
	cfg["routing"] = routing
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

func toAny[T any](s []T) []any {
	out := make([]any, len(s))
	for i, v := range s { out[i] = v }
	return out
}

// helpers
func fragment(rest string) string {
	if i := strings.Index(rest, "#"); i >= 0 {
		f := rest[i+1:]
		// url-decode
		if dec, err := urlQueryUnescape(f); err == nil { return dec }
		return f
	}
	return ""
}

func splitParams(rest string) (hostPort string, params urlValues) {
	if i := strings.Index(rest, "#"); i >= 0 { rest = rest[:i] }
	if i := strings.Index(rest, "?"); i >= 0 {
		return rest[:i], parseQuery(rest[i+1:])
	}
	return rest, urlValues{}
}

func splitHostPort(hp string) (string, int) {
	i := strings.LastIndex(hp, ":")
	if i < 0 { return hp, 443 }
	port := 443
	fmt.Sscanf(hp[i+1:], "%d", &port)
	return hp[:i], port
}

// мини url.Values (без импорта net/url чтобы не тащить Encode порядок)
type urlValues map[string]string
func (v urlValues) Get(k string) string { return v[k] }
func parseQuery(q string) urlValues {
	v := urlValues{}
	for _, kv := range strings.Split(q, "&") {
		i := strings.Index(kv, "=")
		if i < 0 { continue }
		k, val := kv[:i], kv[i+1:]
		if dec, err := urlQueryUnescape(val); err == nil { val = dec }
		v[k] = val
	}
	return v
}
func urlQueryUnescape(s string) (string, error) {
	// простой percent-decode + '+'→пробел
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%':
			if i+2 < len(s) {
				var x int
				if _, err := fmt.Sscanf(s[i+1:i+3], "%02x", &x); err == nil {
					b.WriteByte(byte(x)); i += 2; continue
				}
			}
			b.WriteByte(s[i])
		case '+':
			b.WriteByte(' ')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), nil
}

var _ = base64.StdEncoding