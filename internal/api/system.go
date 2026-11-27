package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// Проверка версий компонентов + обновлений + перезапуск сервисов (админ, Настройки).
// GET /api/system/versions — текущие + последние доступные версии.
// POST /api/system/restart {service} — перезапуск panel/xray/nginx/all.

type componentVersion struct {
	Name      string `json:"name"`
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Update    bool   `json:"update_available"`
	Critical  string `json:"critical_note"`
}

func (s *Server) systemVersions(w http.ResponseWriter, r *http.Request) {
	var comps []componentVersion
	// nginx
	ngCur := cmdOut("nginx", "-v")
	ngCur = extractVer(ngCur)
	ngLatest := nginxLatestStable()
	comps = append(comps, componentVersion{
		Name: "nginx", Current: ngCur, Latest: ngLatest,
		Update: ngLatest != "" && ngCur != ngLatest,
		Critical: nginxCriticalNote(ngCur),
	})
	// xray
	xrCur := cmdOut("/usr/local/bin/xray", "version")
	xrCur = extractVer(xrCur)
	xrLatest := githubLatest("XTLS/Xray-core")
	comps = append(comps, componentVersion{Name: "xray", Current: xrCur, Latest: xrLatest, Update: xrLatest != "" && xrCur != xrLatest})
	// панель
	comps = append(comps, componentVersion{Name: "xkit-panel", Current: s.version, Latest: "", Update: false})
	// hysteria2: standalone-бинарь если стоит, иначе внутри xray (наш дефолт)
	comps = append(comps, hysteriaComponent(xrCur, xrLatest))
	// AmneziaWG: встроена в панель как библиотека amneziawg-go — отдельного бинаря нет
	comps = append(comps, awgComponent())
	writeJSON(w, map[string]any{"components": comps, "checked_at": time.Now().Unix()})
}

// hysteriaComponent — версия hysteria: standalone hysteria-server если развёрнут,
// иначе hysteria2 живёт внутри xray-core (версия = версия xray, с пометкой).
func hysteriaComponent(xrayCur, xrayLatest string) componentVersion {
	if p, err := exec.LookPath("hysteria-server"); err == nil {
		cur := extractVer(cmdOut(p, "version"))
		latest := githubLatest("apernet/hysteria")
		return componentVersion{Name: "hysteria", Current: cur, Latest: latest, Update: latest != "" && cur != latest}
	}
	return componentVersion{
		Name: "hysteria2 (via xray)", Current: xrayCur, Latest: xrayLatest,
		Update: false, // обновляется вместе с xray — отдельной кнопки нет
	}
}

// awgComponent — AmneziaWG встроен в панель (amneziawg-go/v3), current из go.mod
// через BuildInfo; latest — из тегов GitHub (релизов у репозитория нет).
func awgComponent() componentVersion {
	cur := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/amnezia-vpn/amneziawg-go/v3" {
				cur = strings.TrimPrefix(dep.Version, "v")
				break
			}
		}
	}
	latest := githubLatestTag("amnezia-vpn/amneziawg-go")
	return componentVersion{
		Name: "AmneziaWG (встроена)", Current: cur, Latest: latest,
		Update: latest != "" && cur != "" && cur != latest,
	}
}

func cmdOut(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func extractVer(s string) string {
	// nginx/1.30.7 или Xray 26.11.9 ...
	for _, f := range strings.Fields(s) {
		f = strings.TrimPrefix(f, "nginx/")
		if len(f) > 0 && f[0] >= '0' && f[0] <= '9' && strings.Contains(f, ".") {
			return strings.Split(f, " ")[0]
		}
	}
	return s
}

func nginxLatestStable() string {
	// nginx.org download page: секция "Stable version" (не mainline!).
	// Репо nginx.org/packages ставит stable-ветку — сравнивать надо с ней,
	// иначе UI вечно просит обновиться до mainline, которого нет в apt.
	out, err := exec.Command("bash", "-c", `curl -fsSL --max-time 8 https://nginx.org/en/download.html 2>/dev/null | tr '\n' ' ' | grep -oE 'Stable version.{0,400}' | grep -oE 'nginx-[0-9]+\.[0-9]+\.[0-9]+' | head -1`).Output()
	if err != nil || len(out) == 0 {
		return ""
	}
	return strings.TrimPrefix(strings.TrimSpace(string(out)), "nginx-")
}

func nginxCriticalNote(cur string) string {
	// NGINX2Root (18.11.2026): фикс в 1.30.7 stable / 1.31.9 mainline
	if cur == "" {
		return ""
	}
	parts := strings.Split(cur, ".")
	if len(parts) < 3 {
		return ""
	}
	// stable ветка 1.30.x: < 1.30.7 уязвим; 1.24/1.26/1.28 старые — уязвимы
	major, minor, patch := parts[0], parts[1], parts[2]
	if major == "1" {
		if minor == "30" && atoiSafe(patch) < 7 {
			return "УЯЗВИМ: NGINX2Root (CVSS 9.2, RCE). Обновите до 1.30.7+"
		}
		if minor == "31" && atoiSafe(patch) < 9 {
			return "УЯЗВИМ: NGINX2Root. Обновите до 1.31.9+"
		}
		if atoiSafe(minor) < 30 {
			return "УЯЗВИМ: старая ветка nginx, NGINX2Root не исправлен. Обновите до 1.30.7+"
		}
	}
	return ""
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func githubLatest(repo string) string {
	out, err := exec.Command("bash", "-c", fmt.Sprintf("curl -fsSL --max-time 8 https://api.github.com/repos/%s/releases/latest 2>/dev/null | grep -oE '\"tag_name\": *\"[^\"]+\"' | head -1 | sed 's/.*\"\\([^\"]*\\)\"/\\1/'", repo)).Output()
	if err != nil {
		return ""
	}
	// apernet/hysteria теги вида app/v2.14.0 — срезаем и префикс app/
	return strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(string(out)), "app/"), "v")
}

// githubLatestTag — последний тег репозитория без GitHub-релизов (amneziawg-go
// публикует только теги). Кеш 5 мин по паттерну ghCache.
var ghTagCache struct {
	sync.Mutex
	m map[string]ghTagEntry
}
type ghTagEntry struct {
	tag string
	ts  time.Time
}

func githubLatestTag(repo string) string {
	ghTagCache.Lock()
	if ghTagCache.m == nil {
		ghTagCache.m = map[string]ghTagEntry{}
	}
	if e, ok := ghTagCache.m[repo]; ok && time.Since(e.ts) < 5*time.Minute {
		ghTagCache.Unlock()
		return e.tag
	}
	ghTagCache.Unlock()
	out, err := exec.Command("bash", "-c", fmt.Sprintf("curl -fsSL --max-time 8 'https://api.github.com/repos/%s/tags?per_page=1' 2>/dev/null | grep -oE '\"name\": *\"[^\"]+\"' | head -1 | sed 's/.*\"\\([^\"]*\\)\"/\\1/'", repo)).Output()
	tag := ""
	if err == nil {
		tag = strings.TrimPrefix(strings.TrimSpace(string(out)), "v")
	}
	if tag != "" {
		ghTagCache.Lock()
		ghTagCache.m[repo] = ghTagEntry{tag: tag, ts: time.Now()}
		ghTagCache.Unlock()
	}
	return tag
}

func (s *Server) systemRestart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Service string `json:"service"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	svc := req.Service
	allowed := map[string]string{"panel": "xkit-panel", "xray": "xray", "nginx": "nginx"}
	if svc == "all" {
		// перезапуск всех: nginx, xray, panel (panel последним)
		go func() {
			time.Sleep(500 * time.Millisecond)
			exec.Command("systemctl", "restart", "nginx").Run()
			exec.Command("systemctl", "restart", "xray").Run()
			time.Sleep(1 * time.Second)
			exec.Command("systemctl", "restart", "xkit-panel").Run()
		}()
		s.store.AddEvent("system", "ok", "перезапущены все сервисы", "{}")
		writeJSON(w, map[string]any{"ok": true, "restarting": "all"})
		return
	}
	unit, ok := allowed[svc]
	if !ok {
		http.Error(w, "сервис: panel|xray|nginx|all", 400)
		return
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		exec.Command("systemctl", "restart", unit).Run()
		// УРОК (QA): рестарт xray убивает горячие preset-inbound — восстановить из БД.
		if svc == "xray" {
			time.Sleep(3 * time.Second)
			if s.xray != nil { s.xray.Reconnect() }
			s.RestoreInbounds()
		}
	}()
	s.store.AddEvent("system", "ok", "перезапущен "+svc, "{}")
	writeJSON(w, map[string]any{"ok": true, "restarting": svc})
}