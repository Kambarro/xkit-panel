package antifilter

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xtls/xray-core/common/geodata"
	"go4.org/netipx"
	"google.golang.org/protobuf/proto"
)

// Генерация xkit-blocked.dat: юнион antifilter lst → collapse → protobuf.
// ИНВАРИАНТ ВЕРСИИ: схема geodata (26.11.x) — та же, что у живого ядра и go.mod
// панели (GeoIPList{Entry[]{Code,Cidr[]{Ip,Prefix}}}), НЕ legacy router.GeoIPList.

// BlockedCode — категория в xkit-blocked.dat (правило ext:xkit-blocked.dat:xkit-blocked).
const BlockedCode = "XKIT-BLOCKED"

// ParseCIDRLines — разбор lst: IPv4/IPv6 CIDR или голый IP (→ /32|/128).
// Пустые строки и #комментарии пропускаются; битая строка = ошибка всего файла
// (sanity: повреждённый источник не должен молча урезать список).
func ParseCIDRLines(data []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			p, err := netip.ParsePrefix(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %q: %w", i+1, line, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %q: %w", i+1, line, err)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Collapse — юнион + схлопывание перекрывающихся/смежных префиксов (netipx.IPSet).
// Дедуп и порядок детерминированы (Ranges отсортированы).
func Collapse(prefixes []netip.Prefix) []netip.Prefix {
	var b netipx.IPSetBuilder
	for _, p := range prefixes {
		b.AddPrefix(p)
	}
	set, err := b.IPSet()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, r := range set.Ranges() {
		out = append(out, r.Prefixes()...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr() != out[j].Addr() {
			return out[i].Addr().Less(out[j].Addr())
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}

// GenerateDat — protobuf geoip.dat (НОВАЯ geodata-схема) с одной категорией XKIT-BLOCKED.
func GenerateDat(prefixes []netip.Prefix) ([]byte, error) {
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("пустой blocked-список: dat не генерируется (режим не включается молча)")
	}
	entry := &geodata.GeoIP{Code: BlockedCode}
	for _, p := range prefixes {
		entry.Cidr = append(entry.Cidr, &geodata.CIDR{
			Ip:     p.Addr().AsSlice(),
			Prefix: uint32(p.Bits()),
		})
	}
	return proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{entry}})
}

// WriteAtomic — tmp+rename в том же каталоге (паттерн панели: файл не бывает半成品).
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".xkit-tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// SanityMin/SanityMax — разумные пределы количества строк на источник
// (замеры 2026-11-26: ayn 16.5k, ipresolve 154k, subnet 69, community 934).
// «Усохший в 10 раз» или раздутый файл отклоняется как повреждённый.
var sanityBounds = map[string][2]int{
	"allyouneed": {5000, 100000},
	"ipresolve":  {50000, 500000},
	"subnet":     {10, 5000},
	"community":  {100, 20000},
}

// SanityCheck — количество строк в разумных пределах для источника.
func SanityCheck(source string, count int) error {
	b, ok := sanityBounds[source]
	if !ok {
		if count == 0 {
			return fmt.Errorf("%s: пустой файл", source)
		}
		return nil
	}
	if count < b[0] || count > b[1] {
		return fmt.Errorf("%s: %d строк вне разумных пределов [%d..%d] — файл повреждён?", source, count, b[0], b[1])
	}
	return nil
}

// ParseDatPrefixes — разбор geoip.dat (geodata-схема) → префиксы категории.
// Для fallback runetfreedom dat и самопроверки сгенерированного файла.
func ParseDatPrefixes(data []byte, code string) ([]netip.Prefix, error) {
	var list geodata.GeoIPList
	if err := proto.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("dat не парсится (geodata-схема 26.11.x): %w", err)
	}
	for _, e := range list.Entry {
		if !strings.EqualFold(e.Code, code) {
			continue
		}
		var out []netip.Prefix
		for _, c := range e.Cidr {
			a, ok := netip.AddrFromSlice(c.Ip)
			if !ok {
				return nil, fmt.Errorf("битый IP в категории %s", code)
			}
			out = append(out, netip.PrefixFrom(a.Unmap(), int(c.Prefix)).Masked())
		}
		return out, nil
	}
	return nil, fmt.Errorf("категория %s не найдена в dat", code)
}

// DatContains — быстрый self-check: сгенерированный dat читается тем же парсером.
func DatContains(data []byte, code string) bool {
	p, err := ParseDatPrefixes(data, code)
	return err == nil && len(p) > 0
}

var _ = bytes.Equal