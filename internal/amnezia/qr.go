package amnezia

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

// AWGQR — пайплайн Amnezia QR (порт из XKIT main src/28_subscription_v7.sh sub_qr_awg_gif).
// УРОК (исследование): conf → containers JSON (camelCase маппинг) → zlib+uint32 len (Qt qCompress)
// → чанки 850 → base64url('>hBBI',1984,n,i,len) → multi-frame QR.
// В Go: stdlib compress/zlib + encoding/binary + skip2/go-qrcode (внешний API запрещён).

// ContainersJSON — Amnezia containers JSON (camelCase маппинг Jc→junkPacketCount и т.д.).
// last_config + isThirdPartyConfig=true (урок src/28).
func ContainersJSON(p Peer, serverName string) (string, error) {
	conf := p.ClientConf()
	container := map[string]any{
		"container": "amnezia-awg",
		"awg": map[string]any{
			"last_config": conf,
			"isThirdPartyConfig": true,
			"port": strings.Split(p.Endpoint, ":")[1],
			"transport_protocol": "udp",
			"junkPacketCount": p.Params.Jc,
			"junkPacketMinSize": p.Params.Jmin,
			"junkPacketMaxSize": p.Params.Jmax,
			"initPacketJunkSize": p.Params.S1,
			"responsePacketJunkSize": p.Params.S2,
			"initPacketMagicHeader": p.Params.S3,
			"responsePacketMagicHeader": p.Params.S4,
			"firstMagicHeader": p.Params.H1,
			"secondMagicHeader": p.Params.H2,
			"thirdMagicHeader": p.Params.H3,
			"fourthMagicHeader": p.Params.H4,
			"mtu": p.Params.MTU,
			"randomTrailers": p.Params.RandomTrailers,
		},
	}
	if p.Params.I1 != "" {
		container["awg"].(map[string]any)["specialJunk1"] = p.Params.I1
	}
	containers := map[string]any{
		"containers": []any{container},
		"defaultContainer": "amnezia-awg",
		"description": serverName,
		"hostname": p.Endpoint,
	}
	b, err := json.Marshal(containers)
	return string(b), err
}

// QtCompress — zlib-сжатие с uint32 big-endian длиной префиксом (Qt qCompress формат).
// УРОК src/28: Amnezia ждёт именно Qt qCompress (4 байта длины + zlib), не голый zlib.
func QtCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	// uint32 big-endian длина исходных данных
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	buf.Write(lenBuf)
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil { return nil, err }
	if err := zw.Close(); err != nil { return nil, err }
	return buf.Bytes(), nil
}

// QRChunks — разбивка сжатого base64 на чанки с заголовком '>hBBI' (1984,n,i,len).
// УРОК src/28: каждый чанк ≤850 байт payload, заголовок big-endian:
// magic(1984) + total(n) + index(i) + payload_len. Формат multi-frame QR Amnezia.
func QRChunks(compressed []byte) []string {
	b64 := base64.StdEncoding.EncodeToString(compressed)
	const chunkSize = 850
	var chunks []string
	for i := 0; i < len(b64); i += chunkSize {
		end := i + chunkSize
		if end > len(b64) { end = len(b64) }
		chunks = append(chunks, b64[i:end])
	}
	n := len(chunks)
	var out []string
	for i, c := range chunks {
		// заголовок '>hBBI': magic=1984(h), total=n(B)... фактически формат Amnezia:
		// base64url(struct.pack('>hBBI', 1984, n, i, len(payload))) + payload
		hdr := make([]byte, 9)
		binary.BigEndian.PutUint16(hdr[0:2], 1984)
		hdr[2] = byte(n)
		binary.BigEndian.PutUint16(hdr[3:5], uint16(i))
		binary.BigEndian.PutUint32(hdr[5:9], uint32(len(c)))
		hdrB64 := base64.URLEncoding.EncodeToString(hdr)
		out = append(out, hdrB64+c)
	}
	return out
}

// AWGQRPayload — полный пайплайн: conf → containers → QtCompress → chunks.
func AWGQRPayload(p Peer, serverName string) ([]string, error) {
	cj, err := ContainersJSON(p, serverName)
	if err != nil { return nil, err }
	compressed, err := QtCompress([]byte(cj))
	if err != nil { return nil, err }
	return QRChunks(compressed), nil
}

// ParseChunkHeader — разбор заголовка чанка (для проверки/сборки multi-frame).
func ParseChunkHeader(chunk string) (magic, total, index, payloadLen int, payload string, err error) {
	// заголовок = первые 12 символов base64url (9 байт → 12 base64)
	if len(chunk) < 12 { return 0,0,0,0,"", fmt.Errorf("чанк слишком короткий") }
	hdr, err := base64.URLEncoding.DecodeString(chunk[:12])
	if err != nil { return 0,0,0,0,"", err }
	if len(hdr) < 9 { return 0,0,0,0,"", fmt.Errorf("заголовок короткий") }
	magic = int(binary.BigEndian.Uint16(hdr[0:2]))
	total = int(hdr[2])
	index = int(binary.BigEndian.Uint16(hdr[3:5]))
	payloadLen = int(binary.BigEndian.Uint32(hdr[5:9]))
	payload = chunk[12:]
	return
}