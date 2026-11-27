// Package amnezia — AmneziaWG сервер внутри панели (amneziawg-go библиотека)
// + генератор параметров AWG 3.1 + конфиги пиров + vpn:// ссылки + QR-пайплайн.
// УРОК (исследование): Xray 26.x НЕ умеет amneziawg нативно — встраиваем amneziawg-go/v3
// библиотекой (паттерн Kitsune internal/awg), один бинарь без DKMS/3X-UI.
// Генератор параметров — порт awg31_gen_params из XKIT main со всеми инвариантами.
package amnezia

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// AWGParams — параметры AmneziaWG 3.1 (инварианты из XKIT main awg31_gen_params).
type AWGParams struct {
	Jc int // junkPacketCount ≤6
	Jmin int // junkPacketMinSize
	Jmax int // junkPacketMaxSize
	S1 int // initPacketJunkSize
	S2 int // responsePacketJunkSize
	S3 int // initPacketMagicHeader (AWG3.1)
	S4 int // responsePacketMagicHeader (AWG3.1)
	H1 string // initPacketMagicHeader (точечное! диапазонные H = баг amneziawg-go#186)
	H2 string // responsePacketMagicHeader
	H3 string // underloadPacketMagicHeader
	H4 string // transportPacketMagicHeader
	I1 string // special junk (AWG3.1, опц.)
	MTU int // 1280 (фикс — фрагментация ломает DPI-обход)
	RandomTrailers bool // true (AWG3.1)
	DisableCookies bool // false
	Version string // "3.1" (default) | "2.0" — роутеры (Keenetic и др.) на 2.0
}

// GenParams — генератор параметров AWG 3.1 (порт инвариантов XKIT main):
// H1-H4 точечные значения 1/2/3/4 (НЕ диапазоны — баг #186 потеря до 75%),
// S1+56≠S2, MTU 1280, randomTrailers=true, Jc≤6, Jmin<Jmax.
func GenParams() (AWGParams, error) { return GenParamsVersion("3.1") }

// GenParamsVersion — генератор параметров для версии AWG.
// 2.0: только Jc/Jmin/Jmax/S1/S2/H1-H4 (роутеры Keenetic/AmneziaVPN 2.x),
// БЕЗ S3/S4/I1/RandomTrailers — поля 3.1, старый клиент их не понимает.
func GenParamsVersion(version string) (AWGParams, error) {
	p := AWGParams{MTU: 1280, RandomTrailers: true, DisableCookies: false, Version: "3.1"}
	if version == "2.0" {
		p.Version = "2.0"
		p.RandomTrailers = false
	}
	// Jc 2..6
	jc, err := randInt(2, 6); if err != nil { return p, err }
	p.Jc = int(jc)
	// Jmin 8..64, Jmax Jmin+32..Jmin+128
	jmin, err := randInt(8, 64); if err != nil { return p, err }
	p.Jmin = int(jmin)
	jmax, err := randInt(int64(p.Jmin)+32, int64(p.Jmin)+128); if err != nil { return p, err }
	p.Jmax = int(jmax)
	// S1 15..150, S2 такой что S1+56≠S2 (инвариант!)
	s1, err := randInt(15, 150); if err != nil { return p, err }
	p.S1 = int(s1)
	for {
		s2, err := randInt(15, 150); if err != nil { return p, err }
		p.S2 = int(s2)
		if p.S1+56 != p.S2 { break }
	}
	// S3/S4 (AWG3.1 magic headers init/response) — только 3.1
	if p.Version != "2.0" {
		s3, _ := randInt(1, 255); p.S3 = int(s3)
		s4, _ := randInt(1, 255); p.S4 = int(s4)
	}
	// H1-H4 ТОЧЕЧНЫЕ 1/2/3/4 (диапазонные H = баг amneziawg-go#186)
	p.H1 = "1"; p.H2 = "2"; p.H3 = "3"; p.H4 = "4"
	return p, nil
}

func randInt(min, max int64) (int64, error) {
	if max <= min { return min, nil }
	n, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil { return 0, err }
	return n.Int64() + min, nil
}

// Peer — клиентский пир AmneziaWG.
type Peer struct {
	Name       string
	PrivateKey string // клиентский priv (генерится)
	PublicKey  string // клиентский pub (для сервера)
	PresharedKey string
	Address    string // 10.8.1.x/32
	ServerPub  string // pub сервера
	Endpoint   string // host:port сервера
	Params     AWGParams
	DNS        string
}

// ClientConf — клиентский .conf AmneziaWG (для vpn:// и QR).
func (p Peer) ClientConf() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", p.PrivateKey))
	b.WriteString(fmt.Sprintf("Address = %s\n", p.Address))
	b.WriteString(fmt.Sprintf("DNS = %s\n", p.DNS))
	b.WriteString(fmt.Sprintf("MTU = %d\n", p.Params.MTU))
	b.WriteString(fmt.Sprintf("Jc = %d\n", p.Params.Jc))
	b.WriteString(fmt.Sprintf("Jmin = %d\n", p.Params.Jmin))
	b.WriteString(fmt.Sprintf("Jmax = %d\n", p.Params.Jmax))
	b.WriteString(fmt.Sprintf("S1 = %d\n", p.Params.S1))
	b.WriteString(fmt.Sprintf("S2 = %d\n", p.Params.S2))
	if p.Params.Version != "2.0" {
		b.WriteString(fmt.Sprintf("S3 = %d\n", p.Params.S3))
		b.WriteString(fmt.Sprintf("S4 = %d\n", p.Params.S4))
	}
	b.WriteString(fmt.Sprintf("H1 = %s\n", p.Params.H1))
	b.WriteString(fmt.Sprintf("H2 = %s\n", p.Params.H2))
	b.WriteString(fmt.Sprintf("H3 = %s\n", p.Params.H3))
	b.WriteString(fmt.Sprintf("H4 = %s\n", p.Params.H4))
	if p.Params.Version != "2.0" {
		if p.Params.I1 != "" { b.WriteString(fmt.Sprintf("I1 = %s\n", p.Params.I1)) }
		b.WriteString(fmt.Sprintf("RandomTrailers = %t\n", p.Params.RandomTrailers))
	}
	b.WriteString("\n[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", p.ServerPub))
	if p.PresharedKey != "" { b.WriteString(fmt.Sprintf("PresharedKey = %s\n", p.PresharedKey)) }
	// УРОК (аудит #9): AWG-клиенты выходят СОЛО с мастера (MASQUERADE eth0),
	// каскад мастер→нода — userspace SOCKS, L3-маршрутизации через него нет.
	// ::/0 при мёртвом IPv6 мастера = чёрная дыра для IPv6 клиента → только IPv4.
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	b.WriteString(fmt.Sprintf("Endpoint = %s\n", p.Endpoint))
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

// VPNLink — vpn:// ссылка Amnezia (plain base64 клиентского .conf, урок src/09:124-186).
func (p Peer) VPNLink() string {
	return "vpn://" + base64.StdEncoding.EncodeToString([]byte(p.ClientConf()))
}

// ServerPeerConfig — UAPI hex-конфиг пира для сервера (amneziawg-go device).
// Формат: public_key=<hex>\npreshared_key=<hex>\nallowed_ip=...\n
func (p Peer) ServerPeerConfig() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("public_key=%s\n", p.PublicKey))
	if p.PresharedKey != "" { b.WriteString(fmt.Sprintf("preshared_key=%s\n", p.PresharedKey)) }
	b.WriteString(fmt.Sprintf("allowed_ip=%s\n", strings.TrimSuffix(p.Address, "/32")+"/32"))
	return b.String()
}