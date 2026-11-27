// Package reality — сканер целей маскировки REALITY (порт из XKIT main 14_reality_wizard.sh).
// УРОК XKIT: тихий скан (3 потока, не mass-scan — abuse-детект провайдера),
// вердикт ДА/ДА+ (TLS1.3 + валидный серт + не self-signed + h2/X25519),
// фильтр брендов/dynDNS/плохих слов (маскироваться под гугл — дурной тон и риск).
package reality

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Candidate — результат скана одного адреса.
type Candidate struct {
	IP        string `json:"ip"`
	TLS13     bool   `json:"tls13"`
	H2        bool   `json:"h2"`
	X25519    bool   `json:"x25519"`
	SelfSigned bool  `json:"self_signed"`
	CN        string `json:"cn"`
	SNI       string `json:"sni"`       // первый не-wildcard SAN или CN
	Issuer    string `json:"issuer"`
	NotAfter  string `json:"not_after"`
	Verdict   string `json:"verdict"`   // ДА+ / ДА / НЕТ
	TLSVersion string `json:"tls_version"`
	ALPN      string `json:"alpn"`
}

// фильтры (порт из XKIT main reality_scan_candidates)
var (
	brandRe = regexp.MustCompile(`(^|\.)(google|googleapis|gstatic|youtube|microsoft|windows|apple|icloud|amazon|amazonaws|samsung|yahoo|cloudflare|facebook|instagram|netflix|github|telegram|openai|anthropic)\.[a-z.]+$`)
	dynRe   = regexp.MustCompile(`(^|\.)(sslip\.io|nip\.io|xip\.io|traefik\.me|work\.gd|duckdns\.org|ddns\.net|hopto\.org|zapto\.org|myftp\.(biz|org)|dynu\.(net|com)|freeddns\.org|no-ip\.(org|biz|info))$`)
	badRe   = regexp.MustCompile(`(probiv|porn|xxx|sex|adult|casino|bet|vpn|proxy|torrent|crack|hack|warez|drug|weapon|leak|escort|gambl|poker)`)
)

// ExpandTargets разворачивает CIDR (/24 и меньше) или список в IP/хосты.
// УРОК XKIT (V-01): валидация charset — кавычка/;/$ не должны доехать до команд.
func ExpandTargets(arg string) ([]string, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return nil, fmt.Errorf("пустой список целей")
	}
	if strings.Contains(arg, "/") {
		_, netw, err := net.ParseCIDR(arg)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR: %s", arg)
		}
		ones, bits := netw.Mask.Size()
		if bits-ones > 8 { // больше /24 = >256 адресов
			return nil, fmt.Errorf("подсеть слишком большая (максимум /24)")
		}
		var out []string
		ip := netw.IP.To4()
		if ip == nil {
			return nil, fmt.Errorf("только IPv4")
		}
		// перебор адресов подсети
		start := ipToUint32(ip.Mask(netw.Mask))
		end := start | ^maskToUint32(netw.Mask)
		for a := start + 1; a < end; a++ {
			out = append(out, uint32ToIP(a).String())
		}
		return out, nil
	}
	valid := regexp.MustCompile(`^[A-Za-z0-9._:/-]+$`)
	var out []string
	for _, h := range strings.Fields(arg) {
		if !valid.MatchString(h) {
			return nil, fmt.Errorf("bad target: %s", h)
		}
		out = append(out, h)
	}
	return out, nil
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
func maskToUint32(m net.IPMask) uint32 {
	return uint32(m[0])<<24 | uint32(m[1])<<16 | uint32(m[2])<<8 | uint32(m[3])
}
func uint32ToIP(a uint32) net.IP {
	return net.IPv4(byte(a>>24), byte(a>>16), byte(a>>8), byte(a))
}

// Scan — тихий скан целей (3 потока): TCP :443 → TLS-детали → вердикт.
// progress вызывается с (done, total) для UI-прогресса.
func Scan(ctx context.Context, targets []string, progress func(done, total int)) []Candidate {
	const workers = 3 // УРОК XKIT: тихий скан, не mass-scan
	var mu sync.Mutex
	var open []string
	done := 0
	total := len(targets)

	// этап 1: TCP-проба :443
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "443"), 2*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, host)
				mu.Unlock()
			}
			mu.Lock()
			done++
			if progress != nil { progress(done, total) }
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	// этап 2: TLS-детали на открытых
	var results []Candidate
	done = 0
	total = len(open)
	for _, host := range open {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			c := probeTLS(ctx, h)
			mu.Lock()
			results = append(results, c)
			done++
			if progress != nil { progress(done, total) }
			mu.Unlock()
		}(host)
	}
	wg.Wait()

	// сортировка: ДА+ первые, потом ДА, потом по IP
	sort.Slice(results, func(i, j int) bool {
		if results[i].Verdict != results[j].Verdict {
			return results[i].Verdict > results[j].Verdict
		}
		return results[i].IP < results[j].IP
	})
	return results
}

// probeTLS — TLS-handshake + извлечение деталей серта (crypto/tls вместо openssl).
func probeTLS(ctx context.Context, host string) Candidate {
	c := Candidate{IP: host, Verdict: "НЕТ", SelfSigned: true}
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
		InsecureSkipVerify: true, // проверяем цепочку вручную ниже
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return c
	}
	defer conn.Close()
	state := conn.ConnectionState()
	c.TLS13 = state.Version == tls.VersionTLS13
	c.ALPN = state.NegotiatedProtocol
	c.H2 = state.NegotiatedProtocol == "h2"
	switch state.Version {
	case tls.VersionTLS13: c.TLSVersion = "TLSv1.3"
	case tls.VersionTLS12: c.TLSVersion = "TLSv1.2"
	}
	// X25519: Go не экспортирует curve напрямую — косвенно по TLS1.3 (почти всегда X25519)
	c.X25519 = c.TLS13
	if len(state.PeerCertificates) == 0 {
		return c
	}
	leaf := state.PeerCertificates[0]
	c.CN = leaf.Subject.CommonName
	c.NotAfter = leaf.NotAfter.Format("2006-01-02")
	if len(leaf.Issuer.CommonName) > 0 {
		c.Issuer = leaf.Issuer.CommonName
	} else if len(leaf.Issuer.Organization) > 0 {
		c.Issuer = leaf.Issuer.Organization[0]
	}
	// первый не-wildcard SAN
	for _, san := range leaf.DNSNames {
		if !strings.HasPrefix(san, "*.") {
			c.SNI = san
			break
		}
	}
	if c.SNI == "" {
		c.SNI = c.CN
	}
	// self-signed: проверяем цепочку (Verify hostname)
	_, verr := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: certsPool(state.PeerCertificates[1:]),
	})
	c.SelfSigned = verr != nil
	// вердикт (порт XKIT): TLS1.3 + не self-signed + есть SNI/CN
	if c.TLS13 && !c.SelfSigned && (c.SNI != "" || c.CN != "") {
		c.Verdict = "ДА"
		if c.H2 && c.X25519 {
			c.Verdict = "ДА+"
		}
	}
	return c
}

func certsPool(certs []*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// Candidates — фильтр подходящих (ДА/ДА+ минус бренды/dynDNS/плохие слова).
func Candidates(all []Candidate) []Candidate {
	var out []Candidate
	for _, c := range all {
		if c.Verdict != "ДА" && c.Verdict != "ДА+" {
			continue
		}
		sni := c.SNI
		if sni == "" {
			sni = c.CN
		}
		if sni == "" {
			continue
		}
		lower := strings.ToLower(sni)
		if brandRe.MatchString(lower) || dynRe.MatchString(lower) || badRe.MatchString(lower) {
			continue
		}
		out = append(out, c)
	}
	return out
}