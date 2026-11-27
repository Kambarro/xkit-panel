package amnezia

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func TestGenParamsInvariants(t *testing.T) {
	for i := 0; i < 50; i++ {
		p, err := GenParams()
		if err != nil { t.Fatal(err) }
		// инварианты AWG 3.1 (урок XKIT main)
		if p.Jc < 2 || p.Jc > 6 { t.Errorf("Jc=%d вне 2..6", p.Jc) }
		if p.Jmin >= p.Jmax { t.Errorf("Jmin=%d >= Jmax=%d", p.Jmin, p.Jmax) }
		if p.S1+56 == p.S2 { t.Errorf("S1+56==S2 (%d) — нарушен инвариант", p.S1) }
		if p.MTU != 1280 { t.Errorf("MTU=%d != 1280", p.MTU) }
		if !p.RandomTrailers { t.Error("RandomTrailers должен быть true") }
		// H точечные (не диапазоны — баг #186)
		if p.H1 != "1" || p.H2 != "2" || p.H3 != "3" || p.H4 != "4" {
			t.Errorf("H должны быть точечные 1/2/3/4, got %s/%s/%s/%s", p.H1, p.H2, p.H3, p.H4)
		}
		if strings.Contains(p.H1, "-") { t.Error("H1 диапазон — баг #186!") }
	}
}

func TestClientConfAndVPNLink(t *testing.T) {
	p := Peer{Name: "test", PrivateKey: "privkey", PublicKey: "pubkey", Address: "10.8.1.2/32",
		ServerPub: "serverpub", Endpoint: "vpn.example:51820", DNS: "1.1.1.1",
		Params: AWGParams{Jc: 4, Jmin: 20, Jmax: 80, S1: 30, S2: 40, S3: 5, S4: 6, H1: "1", H2: "2", H3: "3", H4: "4", MTU: 1280, RandomTrailers: true}}
	conf := p.ClientConf()
	for _, want := range []string{"[Interface]", "PrivateKey = privkey", "Jc = 4", "S1 = 30", "H1 = 1", "RandomTrailers = true", "[Peer]", "PublicKey = serverpub", "Endpoint = vpn.example:51820", "AllowedIPs = 0.0.0.0/0"} {
		if !strings.Contains(conf, want) { t.Errorf("conf не содержит %q", want) }
	}
	// аудит #9: ::/0 убран — IPv6 мастера мёртв, чёрная дыра для клиента
	if strings.Contains(conf, "::/0") { t.Error("::/0 в AllowedIPs — IPv6-ловушка (аудит #9)") }
	link := p.VPNLink()
	if !strings.HasPrefix(link, "vpn://") { t.Error("vpn:// prefix") }
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vpn://"))
	if err != nil { t.Fatal(err) }
	if string(decoded) != conf { t.Error("vpn:// round-trip mismatch") }
}

func TestQtCompressRoundTrip(t *testing.T) {
	data := []byte(`{"containers":[{"container":"amnezia-awg"}]}`)
	compressed, err := QtCompress(data)
	if err != nil { t.Fatal(err) }
	// префикс uint32 big-endian длина
	if len(compressed) < 4 { t.Fatal("too short") }
	origLen := binary.BigEndian.Uint32(compressed[:4])
	if int(origLen) != len(data) { t.Errorf("len prefix %d != %d", origLen, len(data)) }
	// zlib decompress
	zr, err := zlib.NewReader(bytes.NewReader(compressed[4:]))
	if err != nil { t.Fatal(err) }
	out, _ := io.ReadAll(zr)
	if string(out) != string(data) { t.Error("zlib round-trip mismatch") }
}

func TestQRChunksRoundTrip(t *testing.T) {
	p := Peer{PrivateKey: "k", Address: "10.8.1.2/32", ServerPub: "sp", Endpoint: "h:51820", DNS: "1.1.1.1",
		Params: AWGParams{Jc: 4, Jmin: 20, Jmax: 80, S1: 30, S2: 40, H1: "1", H2: "2", H3: "3", H4: "4", MTU: 1280, RandomTrailers: true}}
	chunks, err := AWGQRPayload(p, "TestServer")
	if err != nil { t.Fatal(err) }
	if len(chunks) == 0 { t.Fatal("no chunks") }
	// разбор заголовков + сборка
	var assembled strings.Builder
	total := -1
	for i, c := range chunks {
		magic, n, idx, plen, payload, err := ParseChunkHeader(c)
		if err != nil { t.Fatalf("chunk %d: %v", i, err) }
		if magic != 1984 { t.Errorf("magic %d != 1984", magic) }
		if total == -1 { total = n }
		if n != total { t.Errorf("total mismatch") }
		if idx != i { t.Errorf("index %d != %d", idx, i) }
		if len(payload) != plen { t.Errorf("payload len %d != %d", len(payload), plen) }
		assembled.WriteString(payload)
	}
	// assembled = base64(compressed) → decode → QtDecompress → containers JSON
	compressed, err := base64.StdEncoding.DecodeString(assembled.String())
	if err != nil { t.Fatal(err) }
	origLen := binary.BigEndian.Uint32(compressed[:4])
	zr, _ := zlib.NewReader(bytes.NewReader(compressed[4:]))
	out, _ := io.ReadAll(zr)
	if len(out) != int(origLen) { t.Errorf("reassembled len %d != %d", len(out), origLen) }
	if !strings.Contains(string(out), "amnezia-awg") { t.Error("containers JSON corrupted") }
	if !strings.Contains(string(out), "junkPacketCount") { t.Error("camelCase mapping lost") }
}