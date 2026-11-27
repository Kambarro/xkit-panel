package routing

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

// AlwaysRules — правила владельца поверх дефолта: «Всегда через ноду» / «Всегда напрямую».
// Категории — мультиселект готовых geosite/geoip из .dat мастера; домены — свободный список.
// ПРИОРИТЕТ (решение владельца): always-direct ВЫШЕ always-proxy. Пересечения не запрещают
// сохранение — AlwaysConflicts показывает их в UI, а порядок правил отдаёт победу direct.
type AlwaysRules struct {
	ProxyCategories  []string `json:"proxy_categories"`  // geosite:telegram, geoip:cloudflare…
	ProxyDomains     []string `json:"proxy_domains"`     // голые домены (суффикс-матч)
	DirectCategories []string `json:"direct_categories"`
	DirectDomains    []string `json:"direct_domains"`
}

// AlwaysCategory — готовая категория для мультиселекта UI. Наличие проверено разбором
// Loyalsoldier geoip.dat/geosite.dat (install.sh ставит именно их) — 2026-11-26.
type AlwaysCategory struct {
	Token string `json:"token"` // geosite:telegram / geoip:telegram
	Label string `json:"label"`
	Kind  string `json:"kind"` // site | ip
}

var alwaysCategories = []AlwaysCategory{
	{"geosite:telegram", "Telegram", "site"},
	{"geosite:google", "Google", "site"},
	{"geosite:youtube", "YouTube", "site"},
	{"geosite:twitter", "Twitter / X", "site"},
	{"geosite:netflix", "Netflix", "site"},
	{"geosite:category-ai-!cn", "Нейросети (ChatGPT, Claude, Gemini…)", "site"},
	{"geosite:openai", "OpenAI", "site"},
	{"geosite:meta", "Meta (Facebook, Instagram, WhatsApp)", "site"},
	{"geosite:facebook", "Facebook", "site"},
	{"geosite:instagram", "Instagram", "site"},
	{"geosite:whatsapp", "WhatsApp", "site"},
	{"geosite:cloudflare", "Cloudflare", "site"},
	{"geosite:discord", "Discord", "site"},
	{"geosite:spotify", "Spotify", "site"},
	{"geosite:twitch", "Twitch", "site"},
	{"geosite:reddit", "Reddit", "site"},
	{"geosite:tiktok", "TikTok", "site"},
	{"geosite:linkedin", "LinkedIn", "site"},
	{"geosite:github", "GitHub", "site"},
	{"geosite:category-media-ru-blocked", "Заблокированные медиа РФ", "site"},
	{"geosite:category-ru", "РФ-сайты (category-ru)", "site"},
	{"geosite:category-gov-ru", "Госсервисы РФ", "site"},
	{"geosite:microsoft", "Microsoft", "site"},
	{"geosite:apple", "Apple", "site"},
	{"geosite:steam", "Steam", "site"},
	{"geoip:telegram", "Telegram (IP)", "ip"},
	{"geoip:google", "Google (IP)", "ip"},
	{"geoip:netflix", "Netflix (IP)", "ip"},
	{"geoip:cloudflare", "Cloudflare (IP)", "ip"},
	{"geoip:facebook", "Facebook / Meta (IP)", "ip"},
	{"geoip:twitter", "Twitter / X (IP)", "ip"},
	{"geoip:ru", "РФ-адреса (geoip:ru)", "ip"},
	{"geoip:private", "Локальные сети (private)", "ip"},
}

// AlwaysCategories — копия каталога для API/UI.
func AlwaysCategories() []AlwaysCategory {
	out := make([]AlwaysCategory, len(alwaysCategories))
	copy(out, alwaysCategories)
	return out
}

var knownCategory = func() map[string]bool {
	m := make(map[string]bool, len(alwaysCategories))
	for _, c := range alwaysCategories {
		m[c.Token] = true
	}
	return m
}()

// домен: буквы/цифры/дефисы/точки (Unicode до IDNA), без схемы/пути/пробелов/шела.
var domainLabelRe = regexp.MustCompile(`^[\pL\pN]([\pL\pN-]*[\pL\pN])?$`)

// ValidateAlwaysRules — нормализация (lowercase, trim, IDNA, дедуп) + валидация.
// Конфликты direct∩proxy НЕ ошибка — см. AlwaysConflicts.
func ValidateAlwaysRules(ar AlwaysRules) (AlwaysRules, error) {
	var out AlwaysRules
	var err error
	if out.ProxyCategories, err = normCategories(ar.ProxyCategories); err != nil {
		return out, fmt.Errorf("proxy categories: %w", err)
	}
	if out.DirectCategories, err = normCategories(ar.DirectCategories); err != nil {
		return out, fmt.Errorf("direct categories: %w", err)
	}
	if out.ProxyDomains, err = normDomains(ar.ProxyDomains); err != nil {
		return out, fmt.Errorf("proxy domains: %w", err)
	}
	if out.DirectDomains, err = normDomains(ar.DirectDomains); err != nil {
		return out, fmt.Errorf("direct domains: %w", err)
	}
	return out, nil
}

func normCategories(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" || seen[c] {
			continue
		}
		if !knownCategory[c] {
			return nil, fmt.Errorf("неизвестная категория %q (выберите из списка)", c)
		}
		seen[c] = true
		out = append(out, c)
	}
	return out, nil
}

func normDomains(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimSuffix(d, ".")
		if d == "" || seen[d] {
			continue
		}
		if strings.ContainsAny(d, " \t/\\:*?\"'`$;&|()<>@") || net.ParseIP(d) != nil {
			return nil, fmt.Errorf("недопустимый домен %q (только имя без схемы/пути)", d)
		}
		labels := strings.Split(d, ".")
		if len(labels) < 2 {
			return nil, fmt.Errorf("домен %q без зоны (нужен вид example.com)", d)
		}
		for _, l := range labels {
			if !domainLabelRe.MatchString(l) {
				return nil, fmt.Errorf("недопустимая часть домена %q", l)
			}
		}
		// кириллица → punycode: Xray матчит ASCII-форму
		ascii, err := idna.Lookup.ToASCII(d)
		if err != nil {
			return nil, fmt.Errorf("домен %q не приводится к IDNA: %w", d, err)
		}
		if seen[ascii] {
			continue
		}
		seen[ascii] = true
		out = append(out, ascii)
	}
	return out, nil
}

// AlwaysConflictReport — пересечения always-direct ∩ always-proxy для UI.
// Побеждает direct (порядок правил), но владелец должен видеть конфликт явно.
type AlwaysConflictReport struct {
	Categories []string `json:"categories"`
	Domains    []string `json:"domains"`
}

func AlwaysConflicts(ar AlwaysRules) AlwaysConflictReport {
	var rep AlwaysConflictReport
	dset := map[string]bool{}
	for _, c := range ar.DirectCategories {
		dset[c] = true
	}
	for _, c := range ar.ProxyCategories {
		if dset[c] {
			rep.Categories = append(rep.Categories, c)
		}
	}
	ddom := map[string]bool{}
	for _, d := range ar.DirectDomains {
		ddom[d] = true
	}
	for _, d := range ar.ProxyDomains {
		// суффикс-пересечение: dup.com vs sub.dup.com в разных списках тоже конфликт
		for dd := range ddom {
			if d == dd || strings.HasSuffix(d, "."+dd) || strings.HasSuffix(dd, "."+d) {
				rep.Domains = append(rep.Domains, d)
				break
			}
		}
	}
	return rep
}

// Tokens — списки для ОДНОГО routing-правила: несколько категорий одной природы
// сливаются в один токен (geosite:telegram,google — синтаксис Xray ext-правила).
func splitCategoryTokens(cats []string, kind string) []string {
	var codes []string
	prefix := "geosite:"
	if kind == "ip" {
		prefix = "geoip:"
	}
	for _, c := range cats {
		if strings.HasPrefix(c, prefix) {
			codes = append(codes, strings.TrimPrefix(c, prefix))
		}
	}
	if len(codes) == 0 {
		return nil
	}
	return []string{prefix + strings.Join(codes, ",")}
}

func domainTokens(domains []string) []string {
	var out []string
	for _, d := range domains {
		out = append(out, "domain:"+d)
	}
	return out
}

// ProxyTokens — domain/ip списки правила always-proxy.
func (ar AlwaysRules) ProxyTokens() (domains, ips []string) {
	domains = append(splitCategoryTokens(ar.ProxyCategories, "site"), domainTokens(ar.ProxyDomains)...)
	ips = splitCategoryTokens(ar.ProxyCategories, "ip")
	return
}

// DirectTokens — domain/ip списки правила always-direct.
func (ar AlwaysRules) DirectTokens() (domains, ips []string) {
	domains = append(splitCategoryTokens(ar.DirectCategories, "site"), domainTokens(ar.DirectDomains)...)
	ips = splitCategoryTokens(ar.DirectCategories, "ip")
	return
}

// AntifilterHappRoutingJSON — Happ routing для antifilter-режима: инверсия дефолта.
// GlobalProxy=false: всё DIRECT, кроме proxy-списка (заблокированное). RouteOrder
// block-direct-proxy: direct-правила матчатся раньше proxy (always-direct выше).
func AntifilterHappRoutingJSON(name string, direct, proxy, block, dip, pip, bip []string) map[string]any {
	cfg := HappRoutingJSON(name, direct, proxy, block, dip, pip, bip)
	cfg["GlobalProxy"] = "false"
	cfg["RouteOrder"] = "block-direct-proxy"
	return cfg
}

// AntifilterHappDeeplink — happ://routing/onadd/<base64url(JSON)> в antifilter-инверсии.
func AntifilterHappDeeplink(name string, direct, proxy, block, dip, pip, bip []string) string {
	cfg := AntifilterHappRoutingJSON(name, direct, proxy, block, dip, pip, bip)
	b, _ := json.Marshal(cfg)
	return "happ://routing/onadd/" + base64.RawURLEncoding.EncodeToString(b)
}