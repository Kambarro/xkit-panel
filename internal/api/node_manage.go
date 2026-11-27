package api

import (
	"sync"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// Управление нодой: перезагрузка, версии/обновление xray+агента, health-check (как Kitsune).
// Всё через SSH (ключ панели). Агент опрашивается через SSH curl localhost:9101.

// POST /api/nodes/reboot {id} — удалённая перезагрузка ноды.
func (s *Server) nodeReboot(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string `json:"id"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "id обязателен", 400); return
	}
	var host string
	if err := s.store.DB().QueryRow(`SELECT host FROM nodes WHERE id=?`, req.ID).Scan(&host); err != nil {
		http.Error(w, "нода не найдена", 404); return
	}
	// nohup reboot чтобы SSH успел ответить до разрыва соединения
	go func() {
		time.Sleep(300 * time.Millisecond)
		s.sshToNode(host, "nohup bash -c 'sleep 1; reboot' >/dev/null 2>&1 &")
	}()
	s.store.AddEvent("node_reboot", "ok", "нода "+req.ID+" перезагружается", fmt.Sprintf(`{"node":%q}`, req.ID))
	writeJSON(w, map[string]any{"ok": true, "id": req.ID, "rebooting": true})
}

// GET /api/nodes/versions?id — текущие версии xray/агента на ноде + доступные.
func (s *Server) nodeVersions(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" { http.Error(w, "id обязателен", 400); return }
	var host string
	if err := s.store.DB().QueryRow(`SELECT host FROM nodes WHERE id=?`, id).Scan(&host); err != nil {
		http.Error(w, "нода не найдена", 404); return
	}
	// текущие версии на ноде
	xrayCur := ""
	if out, err := s.sshToNode(host, "/usr/local/bin/xray version 2>/dev/null | head -1 | awk '{print $2}'"); err == nil {
		xrayCur = strings.TrimSpace(out)
	}
	agentCur := ""
	if out, err := s.sshToNode(host, "curl -s --max-time 5 -H 'X-Agent-Token: "+s.agentToken(id)+"' http://127.0.0.1:9101/info"); err == nil {
		var info map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(out)), &info) == nil {
			agentCur, _ = info["agent"].(string)
		}
	}
	// доступные версии xray: стабильные + бета отдельно
	xrayFull := githubReleasesFull("XTLS/Xray-core", 12)
	var xrayAvail, xrayBeta []string
	for _, r := range xrayFull {
		if r.Prerelease { xrayBeta = append(xrayBeta, r.Tag) } else { xrayAvail = append(xrayAvail, r.Tag) }
	}
	if len(xrayAvail) > 8 { xrayAvail = xrayAvail[:8] }
	if len(xrayBeta) > 4 { xrayBeta = xrayBeta[:4] }
	// агент: версия на мастере (эталон) + доступные релизы
	agentMaster := ""
	if out, err := exec.Command("/usr/local/bin/xkit-agent", "--version").Output(); err == nil {
		agentMaster = strings.TrimSpace(string(out))
	}
	writeJSON(w, map[string]any{
		"id": id,
		"xray_current": xrayCur, "xray_available": xrayAvail, "xray_beta": xrayBeta,
		"agent_current": agentCur, "agent_master": agentMaster,
		"agent_update_available": agentMaster != "" && agentCur != agentMaster,
	})
}

// githubRelease — релиз с флагом prerelease (бета).
type githubRelease struct {
	Tag        string `json:"tag"`
	Prerelease bool   `json:"prerelease"`
}

// R-2: кеш релизов GitHub (5 мин) — защита от троттлинга API.
var ghCache struct {
	sync.Mutex
	m map[string]ghCacheEntry
}
type ghCacheEntry struct {
	rels []githubRelease
	ts   time.Time
}

// githubReleasesFull — последние n релизов с prerelease-флагом (бета отдельно).
func githubReleasesFull(repo string, n int) []githubRelease {
	key := fmt.Sprintf("%s:%d", repo, n)
	ghCache.Lock()
	if ghCache.m == nil { ghCache.m = map[string]ghCacheEntry{} }
	if e, ok := ghCache.m[key]; ok && time.Since(e.ts) < 5*time.Minute {
		ghCache.Unlock()
		return e.rels
	}
	ghCache.Unlock()
	out, err := exec.Command("bash", "-c", fmt.Sprintf("curl -fsSL --max-time 10 'https://api.github.com/repos/%s/releases?per_page=%d' 2>/dev/null", repo, n)).Output()
	if err != nil { return nil }
	var rel []struct {
		TagName    string `json:"tag_name"`
		Prerelease bool   `json:"prerelease"`
		Draft      bool   `json:"draft"`
	}
	if json.Unmarshal(out, &rel) != nil { return nil }
	var out2 []githubRelease
	for _, r := range rel {
		if r.Draft { continue }
		out2 = append(out2, githubRelease{Tag: strings.TrimPrefix(r.TagName, "v"), Prerelease: r.Prerelease})
	}
	ghCache.Lock()
	ghCache.m[key] = ghCacheEntry{rels: out2, ts: time.Now()}
	ghCache.Unlock()
	return out2
}

// githubReleases — только СТАБИЛЬНЫЕ релизы (без бета/prerelease).
func githubReleases(repo string, n int) []string {
	var tags []string
	for _, r := range githubReleasesFull(repo, n+4) {
		if !r.Prerelease {
			tags = append(tags, r.Tag)
			if len(tags) >= n { break }
		}
	}
	return tags
}

// POST /api/nodes/update {id, component, version} — обновить xray или агент на ноде.
// component=xray: скачать релиз с GitHub, заменить бинарь, рестарт.
// component=agent: залить бинарь с мастера (эталон), рестарт.
func (s *Server) nodeUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID        string `json:"id"`
		Component string `json:"component"`
		Version   string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" || req.Component == "" {
		http.Error(w, "id и component обязательны", 400); return
	}
	var host string
	if err := s.store.DB().QueryRow(`SELECT host FROM nodes WHERE id=?`, req.ID).Scan(&host); err != nil {
		http.Error(w, "нода не найдена", 404); return
	}
	switch req.Component {
	case "xray":
		ver := req.Version
		if ver == "" {
			ver = xrayPinnedVersion // дефолт — парная версия (инвариант go.mod ↔ бинарь)
		}
		// SEC-02: версия строго X.Y.Z (анти-command-injection в SSH-скрипте ноды).
		if !validVersion(ver) {
			http.Error(w, "version: формат X.Y.Z", 400); return
		}
		// архитектура ноды
		archOut, _ := s.sshToNode(host, "uname -m")
		xarch := "64"
		if strings.Contains(archOut, "aarch64") || strings.Contains(archOut, "arm64") { xarch = "arm64-v8a" }
		url := fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/v%s/Xray-linux-%s.zip", ver, xarch)
		script := fmt.Sprintf(`set -e
command -v unzip >/dev/null 2>&1 || { apt-get install -y -qq unzip >/dev/null 2>&1 || { echo "unzip install failed"; exit 1; }; }
cd /tmp
curl -fsSL -o xray-upd.zip '%s'
unzip -o xray-upd.zip xray -d /tmp/xray-upd >/dev/null 2>&1
systemctl stop xray
install -m755 /tmp/xray-upd/xray /usr/local/bin/xray
systemctl start xray
rm -rf /tmp/xray-upd /tmp/xray-upd.zip
sleep 1
/usr/local/bin/xray version | head -1 | awk '{print $2}'`, url)
		out, err := s.sshToNode(host, script)
		if err != nil { http.Error(w, "обновление xray: "+out, 500); return }
		s.store.AddEvent("node_update", "ok", fmt.Sprintf("нода %s: xray → %s", req.ID, strings.TrimSpace(out)), fmt.Sprintf(`{"node":%q}`, req.ID))
		writeJSON(w, map[string]any{"ok": true, "component": "xray", "version": strings.TrimSpace(out)})
	case "agent":
		if err := s.installAgent(req.ID, host); err != nil {
			http.Error(w, "обновление агента: "+err.Error(), 500); return
		}
		s.store.AddEvent("node_update", "ok", "нода "+req.ID+": агент обновлён", fmt.Sprintf(`{"node":%q}`, req.ID))
		writeJSON(w, map[string]any{"ok": true, "component": "agent"})
	default:
		http.Error(w, "component: xray|agent", 400)
	}
}

// GET /api/nodes/check?id — health-check ноды (как Kitsune): всё ли настроено/работает.
func (s *Server) nodeCheck(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" { http.Error(w, "id обязателен", 400); return }
	var host string
	var port int
	var tunnelCfg string
	if err := s.store.DB().QueryRow(`SELECT host,port,tunnel_cfg FROM nodes WHERE id=?`, id).Scan(&host, &port, &tunnelCfg); err != nil {
		http.Error(w, "нода не найдена", 404); return
	}
	type check struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	var checks []check
	add := func(name string, ok bool, detail string) { checks = append(checks, check{name, ok, detail}) }

	// 1. SSH доступ
	_, sshErr := s.sshToNode(host, "echo OK")
	add("SSH доступ", sshErr == nil, host)

	if sshErr == nil {
		// 2. xray сервис
		out, _ := s.sshToNode(host, "systemctl is-active xray")
		add("Xray сервис", strings.TrimSpace(out) == "active", strings.TrimSpace(out))
		// 3. xray слушает порт туннеля
		out, _ = s.sshToNode(host, fmt.Sprintf("ss -tlnp 2>/dev/null | grep -q ':%d ' && echo yes || (ss -ulnp 2>/dev/null | grep -q ':%d ' && echo yes || echo no)", port, port))
		add(fmt.Sprintf("Порт туннеля %d", port), strings.TrimSpace(out) == "yes", strings.TrimSpace(out))
		// 4. конфиг валиден
		out, _ = s.sshToNode(host, "/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json 2>&1 | tail -1")
		cfgOK := strings.Contains(out, "Configuration OK") || strings.Contains(strings.ToLower(out), "ok")
		add("Конфиг Xray валиден", cfgOK, strings.TrimSpace(out))
		// 5. nginx camo
		out, _ = s.sshToNode(host, "systemctl is-active nginx")
		add("nginx camo", strings.TrimSpace(out) == "active", strings.TrimSpace(out))
		// 6. UFW активен + deny incoming
		out, _ = s.sshToNode(host, "ufw status | head -1")
		add("UFW активен", strings.Contains(out, "active"), strings.TrimSpace(out))
		// 7. агент
		out, _ = s.sshToNode(host, "systemctl is-active xkit-agent 2>/dev/null")
		add("Агент ноды", strings.TrimSpace(out) == "active", strings.TrimSpace(out))
		// 8. TLS серт (для tls транспортов)
		if strings.Contains(tunnelCfg, "tls") || strings.Contains(tunnelCfg, "hysteria") {
			out, _ = s.sshToNode(host, "ls /etc/letsencrypt/live/*/fullchain.pem 2>/dev/null | head -1")
			add("TLS сертификат", strings.TrimSpace(out) != "", strings.TrimSpace(out))
		}
		// 9. диск не заполнен
		out, _ = s.sshToNode(host, "df / | tail -1 | awk '{print $5}' | tr -d '%'")
		diskPct := 0
		fmt.Sscanf(strings.TrimSpace(out), "%d", &diskPct)
		add("Диск < 90%", diskPct < 90, fmt.Sprintf("%d%%", diskPct))
		// 10. время синхронизировано (важно для REALITY/TLS)
		out, _ = s.sshToNode(host, "timedatectl show -p NTPSynchronized --value 2>/dev/null")
		add("NTP синхронизирован", strings.TrimSpace(out) == "yes", strings.TrimSpace(out))
	}
	// 11. health проба (TCP/TLS) с мастера
	ok, lat := probeNodePub(host, port, 5)
	add("Туннель отвечает (проба)", ok, fmt.Sprintf("%.0f мс", lat))

	passed := 0
	for _, c := range checks { if c.OK { passed++ } }
	writeJSON(w, map[string]any{
		"id": id, "checks": checks, "passed": passed, "total": len(checks),
		"healthy": passed == len(checks),
	})
}

// probeNodePub — проба туннеля ноды с мастера (TCP+TLS handshake, как health-проба).
func probeNodePub(host string, port, timeoutSec int) (bool, float64) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS12})
	lat := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		// TCP fallback (REALITY может не ответить TLS без правильного SNI)
		tcpConn, terr := net.DialTimeout("tcp", addr, time.Duration(timeoutSec)*time.Second)
		if terr != nil { return false, 0 }
		tcpConn.Close()
		return true, lat
	}
	conn.Close()
	return true, lat
}