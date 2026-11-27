package tgproxy

// Manager — ОДИН процесс mtg-multi (dolonet fork) для обоих Telegram-прокси:
//   - MTProto FakeTLS: ee-секрет под свой домен, публичный порт, SOCKS5 каскад через ноду
//   - WEB mode: [web] секция, loopback HTTP, decoy = наш camo, dd/plain секрет,
//     tg://webproxy ссылка. Заменяет tproxy-server + official C mtproxy.
//
// УРОК (владелец): каскад через любую живую ноду (авто-failover, без выбора страны),
// nftables не нужен (UFW deny), ни одного нового публичного порта для WEB (за nginx 443).
// mtg-multi: Go, arm64, SOCKS5 upstream, multi-secret, SIGHUP reload.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	mtgMultiBin = "/usr/local/bin/mtg-multi"
	mtgConfPath = "/etc/xkit-mtg/config.toml"
	webPort     = 18080 // loopback WEB relay (nginx /<slug>/ → сюда)
)

// Manager — один mtg-multi процесс.
type Manager struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	mtEnabled  bool
	mtPort     int
	mtSecret   string // ee...
	webEnabled bool
	webSecret  string // 16-byte hex (plain)
	webSlug    string
	domain     string
	socks      string
	running    bool
}

// GenFakeTLSSecret — ee + 16 random hex + hex(domain).
func GenFakeTLSSecret(domain string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ee" + hex.EncodeToString(b) + hex.EncodeToString([]byte(domain)), nil
}

// GenSlug — случайный base_path.
func GenSlug() string {
	b := make([]byte, 7)
	rand.Read(b)
	return strings.ToLower(base64.RawStdEncoding.EncodeToString(b))[:10]
}

// TgLink — tg://proxy (MTProto FakeTLS).
func TgLink(host string, port int, secret string) string {
	return fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", host, port, secret)
}

// WebLink — tg://webproxy (dd + 16-byte key, base64url).
// УРОК mtg-multi: WEB secret = dd<32hex> (тот же ключ что ee, без hostname).
func WebLink(domain, slug, eeSecret string) string {
	// ee + 32hex(key) + hex(hostname) → key = ee[2:34]
	key := ""
	if len(eeSecret) >= 34 && strings.HasPrefix(eeSecret, "ee") {
		key = eeSecret[2:34]
	}
	marked := "dd" + key
	addr := domain + "/" + slug
	return fmt.Sprintf("tg://webproxy?server=%s&secret=%s", addr, marked)
}

// Config — TOML для mtg-multi.
func (m *Manager) buildConfig() string {
	var b strings.Builder
	b.WriteString("# XKIT Panel — mtg-multi (MTProto FakeTLS + WEB mode)\n")
	b.WriteString("auto-update = false\n")
	// bind: MTProto публичный порт (если включён), иначе loopback-only
	if m.mtEnabled && m.mtPort > 0 {
		b.WriteString(fmt.Sprintf("bind-to = \"0.0.0.0:%d\"\n", m.mtPort))
	} else {
		b.WriteString("bind-to = \"127.0.0.1:18081\"\n")
	}
	// network: SOCKS5 каскад через ноду
	b.WriteString("\n[network]\n")
	b.WriteString("dns = \"https://1.1.1.1\"\n")
	if m.socks != "" {
		b.WriteString(fmt.Sprintf("proxies = [\"socks5://%s\"]\n", m.socks))
	} else {
		b.WriteString("proxies = []\n")
	}
	// WEB mode
	if m.webEnabled {
		b.WriteString("\n[web]\n")
		b.WriteString(fmt.Sprintf("bind-to = \"127.0.0.1:%d\"\n", webPort))
		b.WriteString(fmt.Sprintf("host = %q\n", m.domain))
		b.WriteString("secret-mode = \"dd\"\n")
		b.WriteString("decoy-dir = \"/var/www/camo\"\n")
		if m.webSlug != "" {
			b.WriteString(fmt.Sprintf("base-path = %q\n", m.webSlug))
		}
	}
	// [secrets] ПОСЛЕДНИМ (TOML: ключи после section принадлежат ей;
	// глобальные bind-to должны быть ДО любой [section]).
	if (m.mtEnabled && m.mtSecret != "") || (m.webEnabled && m.webSecret != "") {
		b.WriteString("\n[secrets]\n")
		if m.mtEnabled && m.mtSecret != "" {
			b.WriteString(fmt.Sprintf("mtproto = %q\n", m.mtSecret))
		}
		if m.webEnabled && m.webSecret != "" {
			// [secrets] ждёт ee-формат; WEB link derive = dd+key (без hostname).
			b.WriteString(fmt.Sprintf("web = %q\n", m.webSecret))
		}
	}
	return b.String()
}

// Apply — пишет конфиг + перезапускает mtg-multi (или SIGHUP если только secrets).
func (m *Manager) Apply(domain string, mtEnabled bool, mtPort int, mtSecret string, webEnabled bool, webSecret, webSlug, socks string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.domain = domain
	m.mtEnabled = mtEnabled
	m.mtPort = mtPort
	m.mtSecret = mtSecret
	m.webEnabled = webEnabled
	m.webSecret = webSecret
	m.webSlug = webSlug
	m.socks = socks

	if _, err := os.Stat(mtgMultiBin); err != nil {
		return fmt.Errorf("mtg-multi не установлен (%s)", mtgMultiBin)
	}
	os.MkdirAll("/etc/xkit-mtg", 0700)
	conf := m.buildConfig()
	if err := os.WriteFile(mtgConfPath, []byte(conf), 0600); err != nil {
		return err
	}
	// полный рестарт (bind/web секции читаются только при старте)
	m.stopLocked()
	cmd := exec.Command(mtgMultiBin, "run", mtgConfPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("mtg-multi start: %w", err)
	}
	m.cmd = cmd
	m.running = true
	go func() {
		cmd.Wait()
		m.mu.Lock()
		if m.cmd == cmd {
			m.running = false
		}
		m.mu.Unlock()
	}()
	time.Sleep(1500 * time.Millisecond)
	log.Printf("mtg-multi: mtproto=%v(:%d) web=%v(/%s/) socks=%s", mtEnabled, mtPort, webEnabled, webSlug, socks)
	return nil
}

// RestartWithSocks — перезапуск с новым SOCKS (нода сменилась).
func (m *Manager) RestartWithSocks(socks string) {
	m.mu.Lock()
	domain, mtE, mtP, mtS := m.domain, m.mtEnabled, m.mtPort, m.mtSecret
	webE, webS, webSl := m.webEnabled, m.webSecret, m.webSlug
	m.mu.Unlock()
	if !mtE && !webE {
		return
	}
	m.Apply(domain, mtE, mtP, mtS, webE, webS, webSl, socks)
}

// Stop — гасит процесс.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

func (m *Manager) stopLocked() {
	if m.cmd != nil && m.cmd.Process != nil {
		syscall.Kill(-m.cmd.Process.Pid, syscall.SIGTERM)
		done := make(chan struct{})
		go func() { m.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			syscall.Kill(-m.cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	m.cmd = nil
	m.running = false
}

// Status — состояние.
func (m *Manager) Status() (running, mtEnabled bool, mtPort int, mtSecret string, webEnabled bool, webSecret, webSlug string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running, m.mtEnabled, m.mtPort, m.mtSecret, m.webEnabled, m.webSecret, m.webSlug
}

// NginxLocation — location /<slug>/ → WEB relay (loopback).
func NginxLocation(slug string) string {
	return fmt.Sprintf(`location /%s/ {
    proxy_pass http://127.0.0.1:%d;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    proxy_buffering off;
}
`, slug, webPort)
}