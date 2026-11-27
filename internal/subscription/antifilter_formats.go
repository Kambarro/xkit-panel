package subscription

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kambarro/xkit-panel/internal/routing"
)

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }
func jsonMarshalIndent(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }

// clash-токены (те же правила, что routing.ClashRules — формат клиентского YAML).
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

// Antifilter-подписки (решение владельца): инверсия дефолта — заблокированное
// через ноду, остальное DIRECT. always-правила владельца доходят до клиента:
// always-direct ВЫШЕ always-proxy, оба ВЫШЕ blocked-правил.
// Клиент НЕ имеет xkit-blocked.dat/geosite-ru-only.dat мастера — blocked-набор
// отдаётся панелью по подписочному URL (clash rule-provider txt / sing-box srs /
// xray-json inline-домены). RU-исключение (geoip:ru/.ru) сохраняется выше blocked.

// AntifilterRules — всегда-правила + blocked-набор для клиентских генераторов.
type AntifilterRules struct {
	ProxySites  []string // geosite:*/domain:* (always-proxy)
	ProxyIP     []string // geoip:*/CIDR
	DirectSites []string
	DirectIP    []string
	BlockedDomains []string // суффиксы из geosite RU-BLOCKED (для xray-json inline)
}

// AntifilterFromAlways — конвертация always-правил владельца в токены подписки.
func AntifilterFromAlways(ar routing.AlwaysRules) AntifilterRules {
	pd, pi := ar.ProxyTokens()
	dd, di := ar.DirectTokens()
	return AntifilterRules{ProxySites: pd, ProxyIP: pi, DirectSites: dd, DirectIP: di}
}

// clashAntifilterToken — токен master-правила → clash-строка (multi-категории
// geosite:a,b разворачиваются в отдельные GEOSITE-строки).
func clashAntifilterRules(sites, ips []string, target string) []string {
	var out []string
	for _, s := range sites {
		if strings.HasPrefix(s, "geosite:") {
			for _, code := range strings.Split(strings.TrimPrefix(s, "geosite:"), ",") {
				out = append(out, fmt.Sprintf("GEOSITE,%s,%s", code, target))
			}
			continue
		}
		out = append(out, clashRule(s, target))
	}
	for _, s := range ips {
		if strings.HasPrefix(s, "geoip:") {
			for _, code := range strings.Split(strings.TrimPrefix(s, "geoip:"), ",") {
				out = append(out, fmt.Sprintf("GEOIP,%s,%s,no-resolve", code, target))
			}
			continue
		}
		out = append(out, clashIPRule(s, target))
	}
	return out
}

// ClashYAMLAntifilter — clash/mihomo в antifilter-инверсии. providerBaseURL —
// подписочный endpoint панели (…/antifilter), отдающий blocked-списки; пустой
// URL → rule-provider опускается (always-правила и инверсия остаются).
func ClashYAMLAntifilter(links, extraRules []string, ar AntifilterRules, providerBaseURL string) string {
	base := ClashYAMLRouting(links, nil)
	// вырезаем хвост дефолтного RU-routing (GEOIP,RU…MATCH,PROXY) — заменим инверсией
	idx := strings.Index(base, "  - GEOIP,RU,DIRECT,no-resolve")
	if idx < 0 {
		return base
	}
	var b strings.Builder
	b.WriteString(base[:idx])
	// rule-providers (mihomo): blocked-списки с панели, behavior classical/domain/ipcidr
	if providerBaseURL != "" {
		b.WriteString("rule-providers:\n")
		b.WriteString(fmt.Sprintf(`  xkit-blocked-domains:
    type: http
    behavior: domain
    format: text
    url: %q
    path: ./ruleset/xkit-blocked-domains.yaml
    interval: 3600
  xkit-blocked-ip:
    type: http
    behavior: ipcidr
    format: text
    url: %q
    path: ./ruleset/xkit-blocked-ip.yaml
    interval: 3600
`, providerBaseURL+"/blocked-domains.txt", providerBaseURL+"/blocked-ip.txt"))
		// providers в clash живут на верхнем уровне YAML, не внутри rules —
		// переносим блок ПЕРЕД "rules:" (иначе mihomo не распарсит)
		s := b.String()
		pIdx := strings.Index(s, "rule-providers:")
		prov := s[pIdx:]
		s = s[:pIdx]
		rIdx := strings.Index(s, "rules:\n")
		s = s[:rIdx] + prov + s[rIdx:]
		b.Reset()
		b.WriteString(s)
	}
	// кастом клиента (если разрешён) — выше always/blocked
	for _, r := range extraRules {
		b.WriteString("  - " + r + "\n")
	}
	// always-direct → always-proxy (приоритет владельца)
	for _, r := range clashAntifilterRules(ar.DirectSites, ar.DirectIP, "DIRECT") {
		b.WriteString("  - " + r + "\n")
	}
	for _, r := range clashAntifilterRules(ar.ProxySites, ar.ProxyIP, "PROXY") {
		b.WriteString("  - " + r + "\n")
	}
	// РФ-исключение выше blocked (заблокированные РФ-хостинги — осознанный выбор владельца)
	b.WriteString("  - GEOIP,RU,DIRECT,no-resolve\n")
	b.WriteString("  - GEOSITE,category-ru,DIRECT\n")
	if providerBaseURL != "" {
		b.WriteString("  - RULE-SET,xkit-blocked-domains,PROXY\n")
		b.WriteString("  - RULE-SET,xkit-blocked-ip,PROXY\n")
	}
	b.WriteString("  - GEOIP,private,DIRECT,no-resolve\n")
	b.WriteString("  - MATCH,DIRECT\n")
	return b.String()
}

// singboxAlwaysRules — always-правила в sing-box route.rules (domain_suffix/domain/ip_cidr).
func singboxAlwaysRules(sites, ips []string, outbound string) []any {
	var suffixes, exact []any
	var out []any
	for _, s := range sites {
		switch {
		case strings.HasPrefix(s, "geosite:"):
			for _, code := range strings.Split(strings.TrimPrefix(s, "geosite:"), ",") {
				out = append(out, map[string]any{"rule_set": "geosite-" + code, "outbound": outbound})
			}
		case strings.HasPrefix(s, "domain:"):
			suffixes = append(suffixes, strings.TrimPrefix(s, "domain:"))
		default:
			exact = append(exact, s)
		}
	}
	if len(suffixes) > 0 {
		out = append(out, map[string]any{"domain_suffix": suffixes, "outbound": outbound})
	}
	if len(exact) > 0 {
		out = append(out, map[string]any{"domain": exact, "outbound": outbound})
	}
	var cidrs, geos []any
	for _, s := range ips {
		if strings.HasPrefix(s, "geoip:") {
			for _, code := range strings.Split(strings.TrimPrefix(s, "geoip:"), ",") {
				geos = append(geos, "geoip-"+code)
			}
			continue
		}
		cidrs = append(cidrs, s)
	}
	if len(geos) > 0 {
		out = append(out, map[string]any{"rule_set": geos, "outbound": outbound})
	}
	if len(cidrs) > 0 {
		out = append(out, map[string]any{"ip_cidr": cidrs, "outbound": outbound})
	}
	return out
}

// SingboxJSONAntifilter — sing-box в antifilter-инверсии: final=direct,
// blocked через remote rule-set (.srs с панели), RU-исключение сохранено.
// Гео-категории always-правил (geosite-telegram/geoip-ru) ссылаются на
// MetaCubeX-совместимые srs, объявленные remote (jsdelivr meta-rules-dat).
func SingboxJSONAntifilter(links []string, ar AntifilterRules, providerBaseURL string) string {
	base := SingboxJSON(links)
	var cfg map[string]any
	if err := jsonUnmarshal(base, &cfg); err != nil {
		return base
	}
	rt, _ := cfg["route"].(map[string]any)
	if rt == nil {
		return base
	}
	rules, _ := rt["rules"].([]any)
	// вырезаем хвост RU-direct (ip_is_private/domain_suffix ru) — переставим под always
	var kept []any
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			kept = append(kept, r)
			continue
		}
		if rm["ip_is_private"] == true {
			continue
		}
		if ds, ok := rm["domain_suffix"].([]any); ok && len(ds) == 3 && ds[0] == "ru" {
			continue
		}
		kept = append(kept, r)
	}
	var newRules []any
	newRules = append(newRules, kept...)
	// always-direct → always-proxy
	newRules = append(newRules, singboxAlwaysRules(ar.DirectSites, ar.DirectIP, "direct")...)
	newRules = append(newRules, singboxAlwaysRules(ar.ProxySites, ar.ProxyIP, "select")...)
	// РФ-исключение
	newRules = append(newRules,
		map[string]any{"ip_cidr": []any{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}, "outbound": "direct"},
		map[string]any{"domain_suffix": []any{"ru", "su", "xn--p1ai"}, "outbound": "direct"},
	)
	// blocked rule-sets: source-формат (JSON) — панель отдаёт без srs-компилятора,
	// sing-box 1.11/1.12 оба парсят remote source. download_detour=direct: панель
	// доступна клиенту напрямую (её адрес — сам сервер подписки).
	var ruleSets []any
	if providerBaseURL != "" {
		ruleSets = append(ruleSets,
			map[string]any{"tag": "xkit-blocked-domains", "type": "remote", "format": "source",
				"url": providerBaseURL + "/blocked-domains.json", "download_detour": "direct"},
			map[string]any{"tag": "xkit-blocked-ip", "type": "remote", "format": "source",
				"url": providerBaseURL + "/blocked-ip.json", "download_detour": "direct"},
		)
		newRules = append(newRules,
			map[string]any{"rule_set": []any{"xkit-blocked-domains"}, "outbound": "select"},
			map[string]any{"rule_set": []any{"xkit-blocked-ip"}, "outbound": "select"},
		)
	}
	// geo-категории always: remote srs MetaCubeX (совместимы с 1.11/1.12)
	for _, set := range singboxGeoSets(ar) {
		ruleSets = append(ruleSets, set)
	}
	newRules = append(newRules, map[string]any{"ip_is_private": true, "outbound": "direct"})
	rt["rules"] = newRules
	rt["final"] = "direct"
	if len(ruleSets) > 0 {
		rt["rule_set"] = ruleSets
	}
	cfg["route"] = rt
	return jsonMarshalIndent(cfg)
}

// singboxGeoSets — объявление geosite-*/geoip-* категорий always-правил (remote srs).
func singboxGeoSets(ar AntifilterRules) []any {
	seen := map[string]bool{}
	var out []any
	add := func(prefix, kind string, tokens []string) {
		for _, s := range tokens {
			if !strings.HasPrefix(s, prefix) {
				continue
			}
			for _, code := range strings.Split(strings.TrimPrefix(s, prefix), ",") {
				tag := kind + "-" + code
				if seen[tag] {
					continue
				}
				seen[tag] = true
				out = append(out, map[string]any{"tag": tag, "type": "remote", "format": "binary",
					"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/" + kind + "/" + code + ".srs",
					"download_detour": "direct"})
			}
		}
	}
	add("geosite:", "geosite", append(append([]string{}, ar.ProxySites...), ar.DirectSites...))
	add("geoip:", "geoip", append(append([]string{}, ar.ProxyIP...), ar.DirectIP...))
	return out
}

// XrayJSONAntifilter — xray-json в antifilter-инверсии: catch-all direct.
// blocked-домены — inline из набора панели (клиент не имеет наших .dat);
// blocked-IP inline не отдаём (десятки тысяч CIDR раздули бы конфиг) — IP-слой
// режет сервер (мастер), клиент гонит незаблокированное мимо туннеля по доменам.
func XrayJSONAntifilter(links []string, extraRules []map[string]any, ar AntifilterRules, providerBaseURL string) string {
	return xrayJSONAntifilterBuild(links, extraRules, ar, true)
}

// XrayJSONAntifilterProfiles — то же без клиентского балансира (INCY).
func XrayJSONAntifilterProfiles(links []string, extraRules []map[string]any, ar AntifilterRules, providerBaseURL string) string {
	return xrayJSONAntifilterBuild(links, extraRules, ar, false)
}

func xrayJSONAntifilterBuild(links []string, extraRules []map[string]any, ar AntifilterRules, withBalancer bool) string {
	base := xrayJSONBuild(links, nil, withBalancer)
	var cfg map[string]any
	if err := jsonUnmarshal(base, &cfg); err != nil {
		return base
	}
	rt, _ := cfg["routing"].(map[string]any)
	if rt == nil {
		return base
	}
	rules, _ := rt["rules"].([]any)
	// из базового набора берём только block QUIC/STUN (утечки), RU-direct и
	// catch-all/balancer заменяем инверсией
	var kept []any
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if rm["outboundTag"] == "block" {
			kept = append(kept, r)
		}
	}
	var newRules []any
	newRules = append(newRules, kept...)
	for _, r := range extraRules {
		newRules = append(newRules, r)
	}
	newRules = append(newRules, xrayAlwaysRules(ar.DirectSites, ar.DirectIP, "direct")...)
	newRules = append(newRules, xrayAlwaysRules(ar.ProxySites, ar.ProxyIP, "proxy-first")...)
	// РФ-исключение
	newRules = append(newRules,
		map[string]any{"type": "field", "domain": []string{"geosite:category-ru", "regexp:.*\\.ru$", "regexp:.*\\.su$", "regexp:.*\\.xn--p1ai$"}, "outboundTag": "direct"},
		map[string]any{"type": "field", "ip": []string{"geoip:ru", "geoip:private"}, "outboundTag": "direct"},
	)
	// blocked-домены inline (набор панели, суффиксы)
	if len(ar.BlockedDomains) > 0 {
		doms := make([]string, 0, len(ar.BlockedDomains))
		for _, d := range ar.BlockedDomains {
			doms = append(doms, "domain:"+d)
		}
		newRules = append(newRules, map[string]any{"type": "field", "domain": doms, "outboundTag": "proxy-first"})
	}
	// catch-all direct (инверсия). Балансир не нужен: весь proxy-трафик — на
	// первый профиль, серверный балансир мастера делает failover сам.
	newRules = append(newRules, map[string]any{"type": "field", "port": "0-65535", "outboundTag": "direct"})
	rt["rules"] = newRules
	delete(rt, "balancers")
	cfg["routing"] = rt
	// proxy-first: алиас на первый прокси-outbound (tag может быть любым)
	obs, _ := cfg["outbounds"].([]any)
	firstProxy := ""
	for _, o := range obs {
		om, ok := o.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := om["tag"].(string)
		if tag != "direct" && tag != "block" && tag != "" {
			firstProxy = tag
			break
		}
	}
	if firstProxy != "" {
		// УРОК (QA AF-BUG-1, ядро 26.11.9): proxySettings УДАЛЁН из ядра —
		// алиас строится через streamSettings.sockopt.dialerProxy, иначе
		// конфиг подписки не стартует вовсе («feature has been removed»).
		obs = append(obs, map[string]any{"tag": "proxy-first", "protocol": "freedom",
			"streamSettings": map[string]any{"sockopt": map[string]any{"dialerProxy": firstProxy}}})
		cfg["outbounds"] = obs
	} else {
		// прокси нет ( AWG-only подписка): proxy-first → direct, конфиг валиден
		obs = append(obs, map[string]any{"tag": "proxy-first", "protocol": "freedom"})
		cfg["outbounds"] = obs
	}
	delete(cfg, "burstObservatory")
	return jsonMarshalIndent(cfg)
}

// xrayAlwaysRules — always-токены → xray routing rules (multi-категории нативно).
func xrayAlwaysRules(sites, ips []string, out string) []any {
	var rules []any
	if len(sites) > 0 {
		rules = append(rules, map[string]any{"type": "field", "domain": sites, "outboundTag": out})
	}
	if len(ips) > 0 {
		rules = append(rules, map[string]any{"type": "field", "ip": ips, "outboundTag": out})
	}
	return rules
}