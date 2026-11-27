package antifilter

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

func TestParseCIDRLines(t *testing.T) {
	data := []byte("1.2.3.0/24\n\n# comment\n5.6.7.8\n2001:db8::/32\n  9.9.9.9/32  \n")
	ps, err := ParseCIDRLines(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 4 {
		t.Fatalf("prefixes=%d want 4: %v", len(ps), ps)
	}
	if ps[1].Bits() != 32 {
		t.Errorf("bare IP must become /32: %v", ps[1])
	}
	// битая строка = ошибка файла (не молчаливый пропуск)
	if _, err := ParseCIDRLines([]byte("1.2.3.4\ngarbage\n")); err == nil {
		t.Error("broken line accepted")
	}
	if _, err := ParseCIDRLines([]byte("1.2.3.4/33\n")); err == nil {
		t.Error("/33 accepted")
	}
}

func TestCollapseUnion(t *testing.T) {
	ps, _ := ParseCIDRLines([]byte("1.2.3.0/25\n1.2.3.128/25\n1.2.3.5/32\n4.4.4.0/24\n"))
	out := Collapse(ps)
	// /25+/25 схлопываются в /24, /32 внутри — дедуп
	if len(out) != 2 {
		t.Fatalf("collapse: %v", out)
	}
	if out[0].String() != "1.2.3.0/24" {
		t.Errorf("want 1.2.3.0/24, got %v", out[0])
	}
}

func TestGenerateDatNewSchema(t *testing.T) {
	ps, _ := ParseCIDRLines([]byte("1.2.3.0/24\n5.6.7.8\n"))
	data, err := GenerateDat(Collapse(ps))
	if err != nil {
		t.Fatal(err)
	}
	// ИНВАРИАНТ: файл обязан парситься НОВОЙ geodata-схемой (как живое ядро 26.11.9)
	var list geodata.GeoIPList
	if err := proto.Unmarshal(data, &list); err != nil {
		t.Fatalf("не новая схема: %v", err)
	}
	if len(list.Entry) != 1 || list.Entry[0].Code != BlockedCode {
		t.Fatalf("entry: %+v", list.Entry)
	}
	if len(list.Entry[0].Cidr) != 2 {
		t.Fatalf("cidrs: %d", len(list.Entry[0].Cidr))
	}
	back, err := ParseDatPrefixes(data, "xkit-blocked") // case-insensitive как Xray
	if err != nil || len(back) != 2 {
		t.Fatalf("roundtrip: %v %v", back, err)
	}
	if back[0] != netip.MustParsePrefix("1.2.3.0/24") {
		t.Errorf("roundtrip prefix: %v", back[0])
	}
	// пустой список — ошибка, не тихий пустой dat
	if _, err := GenerateDat(nil); err == nil {
		t.Error("empty list must fail")
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "xkit-blocked.dat")
	if err := WriteAtomic(p, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(p, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "v2" {
		t.Fatalf("content: %q", b)
	}
	// никаких tmp-хвостов
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("tmp files left: %v", entries)
	}
}

func TestSanityCheck(t *testing.T) {
	if err := SanityCheck("allyouneed", 16557); err != nil {
		t.Errorf("live count rejected: %v", err)
	}
	if err := SanityCheck("allyouneed", 100); err == nil {
		t.Error("shrunk 100x accepted")
	}
	if err := SanityCheck("ipresolve", 154198); err != nil {
		t.Errorf("live ipresolve rejected: %v", err)
	}
	if err := SanityCheck("community", 934); err != nil {
		t.Errorf("live community rejected: %v", err)
	}
	if err := SanityCheck("subnet", 69); err != nil {
		t.Errorf("live subnet rejected: %v", err)
	}
	if err := SanityCheck("subnet", 0); err == nil {
		t.Error("empty subnet accepted")
	}
}

// TestParseFallbackDat — fallback runetfreedom ru-blocked.dat (geodata-схема).
func TestParseFallbackDat(t *testing.T) {
	// минимальный dat как runetfreedom: категория RU-BLOCKED
	src := &geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "RU-BLOCKED", Cidr: []*geodata.CIDR{{Ip: []byte{9, 9, 9, 9}, Prefix: 32}}},
	}}
	b, _ := proto.Marshal(src)
	ps, err := ParseDatPrefixes(b, "RU-BLOCKED")
	if err != nil || len(ps) != 1 {
		t.Fatalf("fallback parse: %v %v", ps, err)
	}
	if _, err := ParseDatPrefixes(b, "NOPE"); err == nil {
		t.Error("missing category accepted")
	}
	if _, err := ParseDatPrefixes([]byte("not protobuf"), "RU-BLOCKED"); err == nil {
		t.Error("garbage accepted")
	}
}