package api

// fail2ban — защита от брутфорса на мастере и нодах (директива владельца:
// «fail2ban должен быть в панели и нодах», эскалация 5 попыток → 5м → 1ч → навсегда).
// Панель сама ставит/настраивает fail2ban (jail sshd), показывает статус/бан-лист,
// даёт разбанить. На нодах — при provision. Как UFW: домохозяйка не трогает терминал.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

// f2bJailLocal — конфиг эскалации (5 попыток за 10м, бан 5м→1ч→навсегда).
const f2bJailLocal = `[DEFAULT]
maxretry = 5
findtime = 10m
bantime  = 5m
bantime.increment = true
bantime.factor = 12
bantime.maxtime = -1
backend = systemd

[sshd]
enabled = true
port    = 22
mode    = aggressive
`

// f2bSetupScript — bash-скрипт установки/настройки fail2ban (мастер или нода по SSH).
// Идемпотентен: ставит если нет, пишет jail.local, рестартует.
func f2bSetupScript() string {
	return `command -v fail2ban-client >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban >/dev/null 2>&1; }
cat > /etc/fail2ban/jail.local << 'F2BEOF'
` + f2bJailLocal + `F2BEOF
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1
sleep 2
fail2ban-client status >/dev/null 2>&1 && echo F2B_OK || echo F2B_FAIL`
}

// InitFail2ban — установка/настройка fail2ban на мастере при старте панели (идемпотентно).
func (s *Server) InitFail2ban() {
	out, err := exec.Command("bash", "-c", f2bSetupScript()).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "F2B_OK") {
		s.store.AddEvent("fail2ban", "warn", "fail2ban не настроен на мастере: "+strings.TrimSpace(string(out)), "{}")
		return
	}
	s.store.AddEvent("fail2ban", "ok", "fail2ban настроен на мастере (sshd: 5 попыток → 5м/1ч/навсегда)", "{}")
}

// f2bStatus — статус jail + бан-лист (через fail2ban-client).
func f2bStatus(jail string) map[string]any {
	out, err := exec.Command("fail2ban-client", "status", jail).Output()
	if err != nil {
		return map[string]any{"running": false, "jail": jail}
	}
	res := map[string]any{"running": true, "jail": jail, "banned": []string{}, "total_banned": 0, "total_failed": 0, "currently_banned": 0, "currently_failed": 0}
	var totalBanned, totalFailed, curBanned, curFailed int
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Banned IP list:") {
			ips := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			if ips != "" {
				res["banned"] = strings.Fields(ips)
			}
		}
		if strings.Contains(line, "Total banned:") {
			fmt.Sscanf(strings.TrimSpace(strings.SplitN(line, ":", 2)[1]), "%d", &totalBanned)
		}
		if strings.Contains(line, "Total failed:") {
			fmt.Sscanf(strings.TrimSpace(strings.SplitN(line, ":", 2)[1]), "%d", &totalFailed)
		}
		if strings.Contains(line, "Currently banned:") {
			fmt.Sscanf(strings.TrimSpace(strings.SplitN(line, ":", 2)[1]), "%d", &curBanned)
		}
		if strings.Contains(line, "Currently failed:") {
			fmt.Sscanf(strings.TrimSpace(strings.SplitN(line, ":", 2)[1]), "%d", &curFailed)
		}
	}
	res["total_banned"] = totalBanned
	res["total_failed"] = totalFailed
	res["currently_banned"] = curBanned
	res["currently_failed"] = curFailed
	return res
}

// fail2banStatus — GET /api/fail2ban: статус мастера (+ нод если ?node=id).
func (s *Server) fail2banStatus(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node")
	if nodeID != "" {
		var host string
		if err := s.store.DB().QueryRow(`SELECT host FROM nodes WHERE id=?`, nodeID).Scan(&host); err != nil {
			http.Error(w, "нода не найдена", 404)
			return
		}
		out, err := s.sshToNode(host, "fail2ban-client status sshd 2>/dev/null || echo F2B_NOT_RUNNING")
		running := err == nil && !strings.Contains(out, "F2B_NOT_RUNNING")
		var banned []string
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "Banned IP list:") {
				ips := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				if ips != "" {
					banned = strings.Fields(ips)
				}
			}
		}
		writeJSON(w, map[string]any{"node": nodeID, "running": running, "banned": banned})
		return
	}
	writeJSON(w, map[string]any{"master": f2bStatus("sshd")})
}

// fail2banUnban — POST /api/fail2ban/unban {ip, node?}: разбанить IP.
func (s *Server) fail2banUnban(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP   string `json:"ip"`
		Node string `json:"node"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		http.Error(w, "ip обязателен", 400)
		return
	}
	// защита от инъекции: только IP-символы
	for _, c := range req.IP {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '.' || c == ':') {
			http.Error(w, "некорректный ip", 400)
			return
		}
	}
	if req.Node != "" {
		var host string
		if err := s.store.DB().QueryRow(`SELECT host FROM nodes WHERE id=?`, req.Node).Scan(&host); err != nil {
			http.Error(w, "нода не найдена", 404)
			return
		}
		out, err := s.sshToNode(host, "fail2ban-client set sshd unbanip "+req.IP)
		if err != nil {
			http.Error(w, "разбан: "+out, 500)
			return
		}
	} else {
		out, err := exec.Command("fail2ban-client", "set", "sshd", "unbanip", req.IP).CombinedOutput()
		if err != nil {
			http.Error(w, "разбан: "+string(out), 500)
			return
		}
	}
	s.store.AddEvent("fail2ban", "ok", "разбанен IP "+req.IP, "{}")
	writeJSON(w, map[string]any{"ok": true, "unbanned": req.IP})
}

// fail2banSetupNode — POST /api/fail2ban/setup {node}: установить/настроить fail2ban на ноде.
func (s *Server) fail2banSetupNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Node string `json:"node"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Node == "" {
		http.Error(w, "node обязателен", 400)
		return
	}
	var host string
	if err := s.store.DB().QueryRow(`SELECT host FROM nodes WHERE id=?`, req.Node).Scan(&host); err != nil {
		http.Error(w, "нода не найдена", 404)
		return
	}
	out, err := s.sshToNode(host, f2bSetupScript())
	if err != nil || !strings.Contains(out, "F2B_OK") {
		http.Error(w, "fail2ban на ноде: "+out, 500)
		return
	}
	s.store.AddEvent("fail2ban", "ok", "fail2ban настроен на ноде "+req.Node, "{}")
	writeJSON(w, map[string]any{"ok": true})
}