package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Агент ноды: мастер опрашивает лёгкий xkit-agent на ноде ЧЕРЕЗ SSH-туннель
// (агент слушает 127.0.0.1:9101, публичного API нет). Ключ SSH уже есть после provision.
// GET /api/nodes/agent?id=<nodeID> — метрики ноды изнутри (CPU/RAM/диск/сеть).

const agentPort = 9101
const agentBinPath = "/usr/local/bin/xkit-agent"

// nodeSSHKey — путь к SSH-ключу панели для нод (ставится при provision по паролю).
func nodeSSHKey() string {
	return "/var/lib/xkit-panel/node_key"
}

// agentToken — токен агента ноды (хранится в БД nodes.agent_token).
func (s *Server) agentToken(nodeID string) string {
	var tok string
	s.store.DB().QueryRow(`SELECT agent_token FROM nodes WHERE id=?`, nodeID).Scan(&tok)
	return tok
}

// sshToNode — выполнить команду на ноде по ключу панели.
func (s *Server) sshToNode(host, remote string) (string, error) {
	key := nodeSSHKey()
	args := []string{"-i", key, "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/var/lib/xkit-panel/known_hosts", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=12", "root@" + host, remote}
	out, err := exec.Command("ssh", args...).CombinedOutput()
	return string(out), err
}

// installAgent — залить бинарь агента на ноду + токен + systemd unit (идемпотентно).
// Вызывается при provision и по кнопке «Установить агент».
func (s *Server) installAgent(nodeID, host string) error {
	// токен (если нет — сгенерить)
	tok := s.agentToken(nodeID)
	if tok == "" {
		b := make([]byte, 24)
		rand.Read(b)
		tok = hex.EncodeToString(b)
		s.store.DB().Exec(`UPDATE nodes SET agent_token=? WHERE id=?`, tok, nodeID)
	}
	// бинарь агента на мастере (кладётся при сборке/установке панели)
	localBin := "/usr/local/bin/xkit-agent"
	if _, err := os.Stat(localBin); err != nil {
		return fmt.Errorf("бинарь агента не найден на мастере (%s): соберите cmd/agent", localBin)
	}
	// scp бинарь во временный путь (запущенный бинарь нельзя перезаписать — text file busy)
	key := nodeSSHKey()
	tmpBin := "/tmp/xkit-agent-new"
	scpArgs := []string{"-i", key, "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/var/lib/xkit-panel/known_hosts", "-o", "LogLevel=ERROR", localBin, "root@" + host + ":" + tmpBin}
	if out, err := exec.Command("scp", scpArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("scp agent: %v: %s", err, out)
	}
	// токен + unit + запуск (остановить старый → заменить бинарь → запустить)
	setup := fmt.Sprintf(`mkdir -p /etc/xkit-agent
echo '%s' > /etc/xkit-agent/token
chmod 600 /etc/xkit-agent/token
systemctl stop xkit-agent 2>/dev/null
install -m755 %s %s
rm -f %s
cat > /etc/systemd/system/xkit-agent.service << 'XEOF'
[Unit]
Description=XKIT node agent (metrics + AWG cascade, localhost only)
After=network.target
[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=3
Environment=XKIT_AGENT_ADDR=127.0.0.1:%d
[Install]
WantedBy=multi-user.target
XEOF
systemctl daemon-reload
systemctl enable --now xkit-agent >/dev/null 2>&1
systemctl restart xkit-agent
sleep 1
systemctl is-active xkit-agent`, tok, tmpBin, agentBinPath, tmpBin, agentBinPath, agentPort)
	out, err := s.sshToNode(host, setup)
	if err != nil {
		return fmt.Errorf("agent setup: %v: %s", err, out)
	}
	if strings.TrimSpace(out) != "active" {
		return fmt.Errorf("agent не запустился: %s", out)
	}
	s.store.DB().Exec(`UPDATE nodes SET agent_installed=1 WHERE id=?`, nodeID)
	return nil
}

// fetchAgentMetrics — SSH-туннель к агенту ноды → GET /metrics.
// Локальный проброс порта: ssh -L 127.0.0.1:<lp>:127.0.0.1:9101, затем curl через него.
func (s *Server) fetchAgentMetrics(ctx context.Context, host, token string) (map[string]any, error) {
	// одноразовый SSH с удалённым curl (проще чем туннель: агент на localhost ноды,
	// выполняем curl прямо на ноде через SSH — без проброса порта)
	remote := fmt.Sprintf("curl -s --max-time 8 -H 'X-Agent-Token: %s' http://127.0.0.1:%d/metrics", token, agentPort)
	out, err := s.sshToNode(host, remote)
	if err != nil {
		return nil, fmt.Errorf("ssh agent metrics: %v: %s", err, out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &m); err != nil {
		return nil, fmt.Errorf("agent metrics decode: %v (raw: %s)", err, out[:min(120, len(out))])
	}
	return m, nil
}

func min(a, b int) int { if a < b { return a }; return b }

// GET /api/nodes/agent?id — метрики ноды изнутри (через агента).
func (s *Server) nodeAgentMetrics(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" { http.Error(w, "id обязателен", 400); return }
	var host string
	var installed int
	if err := s.store.DB().QueryRow(`SELECT host,agent_installed FROM nodes WHERE id=?`, id).Scan(&host, &installed); err != nil {
		http.Error(w, "нода не найдена", 404); return
	}
	if installed == 0 {
		writeJSON(w, map[string]any{"installed": false, "hint": "агент не установлен — нажмите «Установить агент»"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	m, err := s.fetchAgentMetrics(ctx, host, s.agentToken(id))
	if err != nil {
		writeJSON(w, map[string]any{"installed": true, "error": err.Error()})
		return
	}
	m["installed"] = true
	writeJSON(w, m)
}

// POST /api/nodes/agent/install {id} — установить/переустановить агент на ноде.
func (s *Server) nodeAgentInstall(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string `json:"id"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "id обязателен", 400); return
	}
	var host string
	if err := s.store.DB().QueryRow(`SELECT host FROM nodes WHERE id=?`, req.ID).Scan(&host); err != nil {
		http.Error(w, "нода не найдена", 404); return
	}
	if err := s.installAgent(req.ID, host); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("node_agent", "ok", "агент установлен на ноде "+req.ID, "{}")
	writeJSON(w, map[string]any{"ok": true, "id": req.ID})
}