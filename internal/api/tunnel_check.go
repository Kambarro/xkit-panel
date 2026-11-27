package api

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Тест туннеля мастер→нода (POST /api/nodes/test-tunnel {id}).
// УРОК (владелец): после выбора транспорта до ноды нужно тестировать туннель.
// Проверки: SSH-доступ (по ключу панели), Xray active на ноде, порт слушает,
// TLS/TCP handshake с мастера до ноды (реальная сетевая достижимость туннеля).

func (s *Server) testTunnel(w http.ResponseWriter, r *http.Request) {
	var body struct{ ID string `json:"id"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "id required", 400); return
	}
	var host, tunnelCfg string
	var port int
	err := s.store.DB().QueryRow(`SELECT host,port,tunnel_cfg FROM nodes WHERE id=?`, body.ID).Scan(&host, &port, &tunnelCfg)
	if err != nil { http.Error(w, "node not found", 404); return }
	if port == 0 { port = 443 }

	type check struct {
		Name string `json:"name"`
		OK   bool   `json:"ok"`
		Msg  string `json:"msg"`
	}
	var checks []check

	// 1. SSH-доступ по ключу панели (нода управляема)
	keyPath := "/var/lib/xkit-panel/node_key"
	sshArgs := []string{"-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/var/lib/xkit-panel/known_hosts", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes"}
	if fileExists(keyPath) { sshArgs = append(sshArgs, "-i", keyPath) }
	sshArgs = append(sshArgs, "root@"+host, "echo OK")
	out, err := exec.Command("ssh", sshArgs...).CombinedOutput()
	sshOK := err == nil && strings.Contains(string(out), "OK")
	checks = append(checks, check{"ssh", sshOK, ternary(sshOK, "SSH по ключу панели работает", "SSH недоступен: "+strings.TrimSpace(string(out)))})

	// 2. Xray active на ноде
	if sshOK {
		out, err := exec.Command("ssh", append(sshArgs[:len(sshArgs)-1], "systemctl is-active xray")...).CombinedOutput()
		active := err == nil && strings.TrimSpace(string(out)) == "active"
		checks = append(checks, check{"xray", active, ternary(active, "Xray запущен на ноде", "Xray не active: "+strings.TrimSpace(string(out)))})
		// 3. порт слушает на ноде
		out, err = exec.Command("ssh", append(sshArgs[:len(sshArgs)-1], fmt.Sprintf("ss -tln | grep -q ':%d ' && echo LISTEN || echo NO", port))...).CombinedOutput()
		listen := err == nil && strings.Contains(string(out), "LISTEN")
		checks = append(checks, check{"port", listen, ternary(listen, fmt.Sprintf("Порт %d слушает", port), fmt.Sprintf("Порт %d не слушает", port))})
	}

	// 4. TLS/TCP handshake с мастера до ноды (сетевая достижимость туннеля)
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	tlsOK := false
	if conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS12}); err == nil {
		conn.Close()
		tlsOK = true
	}
	netOK := tlsOK
	if !netOK {
		if c, err := net.DialTimeout("tcp", addr, 4*time.Second); err == nil { c.Close(); netOK = true }
	}
	checks = append(checks, check{"tunnel", netOK, ternary(tlsOK, "TLS handshake до ноды OK (туннель жив)", ternary(netOK, "TCP до ноды OK (TLS не прошёл — REALITY fallback?)", "Нода недоступна с мастера: "+addr))})

	allOK := true
	for _, c := range checks { if !c.OK { allOK = false } }
	s.store.AddEvent("tunnel_test", ternary(allOK, "ok", "warn"), fmt.Sprintf("тест туннеля %s: %v", body.ID, allOK), "{}")
	writeJSON(w, map[string]any{"ok": allOK, "node": body.ID, "checks": checks})
}

func ternary(b bool, t, f string) string { if b { return t }; return f }
func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }