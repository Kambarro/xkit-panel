package routing

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Package routing — роутинг подписки: наш дефолт (владелец) + кастом клиента поверх.
// УРОК (владелец): клиентский роутинг НЕ обходит серверные правила мастера — он лишь
// выбирает direct/proxy/block для СВОЕГО трафика. Серверный слой владельца неприкосновенен.
// Клиент ДОПОЛНЯЕТ наш дефолт (не удаляет его фундамент). Формат Happ routing deeplink
// проверен по roscomvpn-routing (HAPP/DEFAULT.DEEPLINK = base64url(JSON)).

// DefaultRules — наш базовый роутинг (RU мимо VPN, банки РФ direct, block рекламы/шпионов).
// Основа для всех клиентов. Владелец может расширять серверными правилами (не здесь).
var DefaultDirectSites = []string{
	"geosite:private", "geosite:category-ru", "geosite:microsoft", "geosite:apple",
	"geosite:steam", "geosite:epicgames", "geosite:riot",
}
var DefaultProxySites = []string{
	"geosite:google-play", "geosite:github", "geosite:youtube", "geosite:telegram",
}
var DefaultBlockSites = []string{
	"geosite:category-ads", "geosite:win-spy",
	// УРОК (аудит #5): STUN-домены WebRTC — block не даёт показать реальный IP
	// клиента. Happ deeplink умеет только domain/IP списки (портов/udp в формате
	// нет) — QUIC udp/443 режется в clash/singbox/xray-json генераторах.
	"domain:stun.l.google.com", "domain:stun1.l.google.com", "domain:stun2.l.google.com",
	"domain:stun3.l.google.com", "domain:stun4.l.google.com",
	"domain:stun.services.mozilla.com", "domain:stun.stunprotocol.org",
}
var DefaultDirectIP = []string{"geoip:private", "geoip:ru"}
var DefaultProxyIP = []string{}
var DefaultBlockIP = []string{}

// CustomRules — правила клиента (дополняют дефолт).
type CustomRules struct {
	DirectSites []string `json:"direct_sites"`
	ProxySites  []string `json:"proxy_sites"`
	BlockSites  []string `json:"block_sites"`
	DirectIP    []string `json:"direct_ip"`
	ProxyIP     []string `json:"proxy_ip"`
	BlockIP     []string `json:"block_ip"`
}

// BaseRules — базовый набор владельца (редактируется админом, хранится в БД).
// Передаётся из store.DefaultRouting(). Если пуст — используется встроенный дефолт.
type BaseRules struct {
	DirectSites []string
	ProxySites  []string
	BlockSites  []string
	DirectIP    []string
	ProxyIP     []string
	BlockIP     []string
}

// MergedRules — встроенный дефолт + кастом клиента (обратная совместимость).
func MergedRules(mode string, custom CustomRules) (direct, proxy, block, dip, pip, bip []string) {
	return MergedRulesBase(mode, custom, BaseRules{})
}

// MergedRulesBase — базовый набор владельца + кастом клиента (дефолт первым = фундамент).
// Если base пуст — встроенный дефолт. Дедупликация.
func MergedRulesBase(mode string, custom CustomRules, base BaseRules) (direct, proxy, block, dip, pip, bip []string) {
	bd, bp, bb, bdip, bpip, bbip := DefaultDirectSites, DefaultProxySites, DefaultBlockSites, DefaultDirectIP, DefaultProxyIP, DefaultBlockIP
	if len(base.DirectSites) > 0 || len(base.BlockSites) > 0 || len(base.ProxySites) > 0 {
		bd, bp, bb, bdip, bpip, bbip = base.DirectSites, base.ProxySites, base.BlockSites, base.DirectIP, base.ProxyIP, base.BlockIP
	}
	direct = append(direct, bd...)
	proxy = append(proxy, bp...)
	block = append(block, bb...)
	dip = append(dip, bdip...)
	pip = append(pip, bpip...)
	bip = append(bip, bbip...)
	if mode == "custom" {
		direct = appendUniq(direct, custom.DirectSites)
		proxy = appendUniq(proxy, custom.ProxySites)
		block = appendUniq(block, custom.BlockSites)
		dip = appendUniq(dip, custom.DirectIP)
		pip = appendUniq(pip, custom.ProxyIP)
		bip = appendUniq(bip, custom.BlockIP)
	}
	return
}

func appendUniq(base, extra []string) []string {
	seen := map[string]bool{}
	for _, s := range base { seen[s] = true }
	for _, s := range extra {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] { base = append(base, s); seen[s] = true }
	}
	return base
}

// HappRoutingJSON — JSON роутинга для Happ deeplink (формат roscomvpn DEFAULT.JSON).
// GlobalProxy=true: всё через VPN кроме direct-списка. RouteOrder block-proxy-direct.
func HappRoutingJSON(name string, direct, proxy, block, dip, pip, bip []string) map[string]any {
	return map[string]any{
		"Name":          name,
		"GlobalProxy":   "true",
		"UseChunkFiles": "true",
		"RemoteDns":     "8.8.8.8",
		"DomesticDns":   "77.88.8.8",
		"RemoteDNSType": "DoH",
		"RemoteDNSDomain": "https://8.8.8.8/dns-query",
		"RemoteDNSIP":   "8.8.8.8",
		"DomesticDNSType": "DoH",
		"DomesticDNSDomain": "https://77.88.8.8/dns-query",
		"DomesticDNSIP": "77.88.8.8",
		"RouteOrder":    "block-proxy-direct",
		"DirectSites":   direct,
		"DirectIp":      dip,
		"ProxySites":    proxy,
		"ProxyIp":       pip,
		"BlockSites":    block,
		"BlockIp":       bip,
		"DomainStrategy": "IPIfNonMatch",
	}
}

// HappDeeplink — happ://routing/onadd/<base64url(JSON)> (формат проверен по roscomvpn).
func HappDeeplink(name string, direct, proxy, block, dip, pip, bip []string) string {
	cfg := HappRoutingJSON(name, direct, proxy, block, dip, pip, bip)
	b, _ := json.Marshal(cfg)
	enc := base64.RawURLEncoding.EncodeToString(b)
	return "happ://routing/onadd/" + enc
}

// XrayRules — правила для Xray-JSON подписки (routing.rules). direct/proxy/block.
func XrayRules(direct, proxy, block, dip, pip, bip []string) []map[string]any {
	var rules []map[string]any
	if len(block) > 0 {
		rules = append(rules, map[string]any{"type": "field", "domain": block, "outboundTag": "block"})
	}
	if len(bip) > 0 {
		rules = append(rules, map[string]any{"type": "field", "ip": bip, "outboundTag": "block"})
	}
	if len(direct) > 0 {
		rules = append(rules, map[string]any{"type": "field", "domain": direct, "outboundTag": "direct"})
	}
	if len(dip) > 0 {
		rules = append(rules, map[string]any{"type": "field", "ip": dip, "outboundTag": "direct"})
	}
	// proxy — остальное через прокси (catch-all в конце ставит генератор)
	return rules
}

// ClashRules — правила для Clash/mihomo YAML.
func ClashRules(direct, proxy, block, dip, pip, bip []string) []string {
	var rules []string
	for _, s := range block { rules = append(rules, clashRule(s, "REJECT")) }
	for _, s := range bip { rules = append(rules, clashIPRule(s, "REJECT")) }
	for _, s := range direct { rules = append(rules, clashRule(s, "DIRECT")) }
	for _, s := range dip { rules = append(rules, clashIPRule(s, "DIRECT")) }
	for _, s := range proxy { rules = append(rules, clashRule(s, "PROXY")) }
	for _, s := range pip { rules = append(rules, clashIPRule(s, "PROXY")) }
	return rules
}

func clashRule(s, target string) string {
	if strings.HasPrefix(s, "geosite:") {
		return fmt.Sprintf("GEOSITE,%s,%s", strings.TrimPrefix(s, "geosite:"), target)
	}
	if strings.HasPrefix(s, "domain:") {
		return fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", strings.TrimPrefix(s, "domain:"), target)
	}
	return fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", s, target)
}

func clashIPRule(s, target string) string {
	if strings.HasPrefix(s, "geoip:") {
		return fmt.Sprintf("GEOIP,%s,%s,no-resolve", strings.TrimPrefix(s, "geoip:"), target)
	}
	return fmt.Sprintf("IP-CIDR,%s,%s,no-resolve", s, target)
}