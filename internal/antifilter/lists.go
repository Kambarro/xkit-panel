package antifilter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

// BlockedLists — наборы для клиентских подписок (clash provider / sing-box rule-set).
// Читаются из ТЕХ ЖЕ файлов, что матчит ядро мастера (active dat + geosite-ru-only)
// — клиент и сервер не спорят о составе.

// BlockedIPText — clash ipcidr payload: строки CIDR.
func (m *Manager) BlockedIPText() (string, error) {
	ps, err := m.blockedPrefixes()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, p := range ps {
		b.WriteString(p.String())
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// BlockedIPJSON — sing-box source rule-set {version:1,rules:[{ip_cidr:[…]}]}.
func (m *Manager) BlockedIPJSON() (string, error) {
	ps, err := m.blockedPrefixes()
	if err != nil {
		return "", err
	}
	cidrs := make([]string, 0, len(ps))
	for _, p := range ps {
		cidrs = append(cidrs, p.String())
	}
	b, _ := json.Marshal(map[string]any{"version": 1, "rules": []any{map[string]any{"ip_cidr": cidrs}}})
	return string(b), nil
}

func (m *Manager) blockedPrefixes() ([]netip.Prefix, error) {
	data, err := os.ReadFile(filepath.Join(m.AssetDir, m.ActiveDatFile()))
	if err != nil {
		return nil, fmt.Errorf("blocked dat недоступен: %w", err)
	}
	return ParseDatPrefixes(data, BlockedCode)
}

// BlockedDomains — суффиксы категории RU-BLOCKED из geosite-ru-only.dat.
func (m *Manager) BlockedDomains() ([]string, error) {
	data, err := os.ReadFile(filepath.Join(m.AssetDir, GeositeFile))
	if err != nil {
		return nil, fmt.Errorf("geosite dat недоступен: %w", err)
	}
	var list geodata.GeoSiteList
	if err := proto.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	for _, e := range list.Entry {
		if !strings.EqualFold(e.Code, "RU-BLOCKED") {
			continue
		}
		var out []string
		for _, d := range e.Domain {
			// Domain_Domain = суффикс-матч; остальные типы (full/keyword/regex)
			// clash domain-behavior не выражает — пропускаем (IP-слой подстрахует)
			if d.Type == geodata.Domain_Domain {
				out = append(out, d.Value)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("категория RU-BLOCKED не найдена")
}

// BlockedDomainText — clash/mihomo domain payload (format:text).
// УРОК (QA AF-BUG-4): голый домен в mihomo domain-behavior = ТОЧНЫЙ матч —
// поддомены (www.youtube.com) утекали в MATCH,DIRECT. Суффикс требует '+.'
// (domain-trie: '+.x' матчит x И *.x). Проверено исходниками mihomo и живым run.
func (m *Manager) BlockedDomainText() (string, error) {
	ds, err := m.BlockedDomains()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, d := range ds {
		if d == "" || strings.HasPrefix(d, "+.") {
			continue
		}
		b.WriteString("+.")
		b.WriteString(d)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// BlockedDomainJSON — sing-box source rule-set {version:1,rules:[{domain_suffix:[…]}]}.
func (m *Manager) BlockedDomainJSON() (string, error) {
	ds, err := m.BlockedDomains()
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]any{"version": 1, "rules": []any{map[string]any{"domain_suffix": ds}}})
	return string(b), nil
}

// ServeBlocked — HTTP-обработчик наборов для подписочных клиентов (без auth:
// путь содержит случайный subId, как сама подписка). kind:
// blocked-domains.txt | blocked-ip.txt | blocked-domains.json | blocked-ip.json.
func (m *Manager) ServeBlocked(w http.ResponseWriter, r *http.Request, kind string) {
	var body string
	var err error
	ct := "text/plain; charset=utf-8"
	switch kind {
	case "blocked-domains.txt":
		body, err = m.BlockedDomainText()
	case "blocked-ip.txt":
		body, err = m.BlockedIPText()
	case "blocked-domains.json":
		body, err = m.BlockedDomainJSON()
		ct = "application/json"
	case "blocked-ip.json":
		body, err = m.BlockedIPJSON()
		ct = "application/json"
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	sum := sha256.Sum256([]byte(body))
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=1800")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", ct)
	fmt.Fprint(w, body)
}