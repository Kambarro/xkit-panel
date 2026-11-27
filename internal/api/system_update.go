package api

// Обновление компонентов МАСТЕРА (xray/nginx) прямо из UI «Версии компонентов».
// УРОК (владелец): релизы и бета отдельно; обновление с подтверждением; xray —
// горячий рестарт + RestoreInbounds + SyncRules (иначе клиенты DIRECT).
// nginx — apt (системный пакет). Панель — самообновление позже (релиз-инфраструктура).

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// xrayPinnedVersion — ИНВАРИАНТ деплоя: версия xray-бинаря, который панель
// ставит на мастер/ноды (install.sh XRAY_PIN, дефолт update-путей), ОБЯЗАНА
// совпадать с xray-core в go.mod панели: gRPC wire-format routing/hysteria
// ломается между схемами (живой баг: панель v1.260327.0 + ядро 26.11.9 →
// ReplaceRules «invalid wire-format», balancer/survey/failover мертвы).
// Поднял go.mod — подними здесь и XRAY_PIN в install.sh, и наоборот.
const xrayPinnedVersion = "26.11.9"

// xrayVersions — GET /api/system/xray-versions: текущая + стабильные + бета (для мастера).
func (s *Server) xrayVersions(w http.ResponseWriter, r *http.Request) {
	cur := extractVer(cmdOut("/usr/local/bin/xray", "version"))
	full := githubReleasesFull("XTLS/Xray-core", 14)
	var stable, beta []string
	for _, rel := range full {
		if rel.Prerelease {
			beta = append(beta, rel.Tag)
		} else {
			stable = append(stable, rel.Tag)
		}
	}
	if len(stable) > 8 {
		stable = stable[:8]
	}
	if len(beta) > 4 {
		beta = beta[:4]
	}
	writeJSON(w, map[string]any{"current": cur, "pinned": xrayPinnedVersion, "stable": stable, "beta": beta})
}

// systemUpdate — POST /api/system/update {component, version}.
// component=xray: скачать релиз GitHub, заменить бинарь, рестарт + restore.
// component=nginx: apt-get install nginx (стабильный из nginx.org репо).
func (s *Server) systemUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Component string `json:"component"`
		Version   string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Component == "" {
		http.Error(w, "component обязателен", 400)
		return
	}
	switch req.Component {
	case "xray":
		ver := req.Version
		if ver == "" {
			ver = xrayPinnedVersion // дефолт — парная версия (инвариант go.mod ↔ бинарь)
		}
		// SEC-01: версия строго X.Y.Z и только из списка релизов GitHub —
		// иначе JSON-поле интерполируется в shell-скрипт (command injection).
		if !validVersion(ver) {
			http.Error(w, "version: формат X.Y.Z", 400)
			return
		}
		if !knownXrayVersion(ver) {
			http.Error(w, "неизвестная версия xray (нет в релизах GitHub)", 400)
			return
		}
		// архитектура мастера
		archOut, _ := exec.Command("uname", "-m").Output()
		xarch := "64"
		if strings.Contains(string(archOut), "aarch64") || strings.Contains(string(archOut), "arm64") {
			xarch = "arm64-v8a"
		}
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
		out, err := exec.Command("bash", "-c", script).CombinedOutput()
		if err != nil {
			http.Error(w, "обновление xray: "+string(out), 500)
			return
		}
		newVer := strings.TrimSpace(string(out))
		s.store.AddEvent("system_update", "ok", fmt.Sprintf("мастер: xray → %s", newVer), "{}")
		// горячий restore inbound + routing rules (иначе клиенты DIRECT после рестарта)
		go func() {
			time.Sleep(3 * time.Second)
			if s.xray != nil {
				s.xray.Reconnect()
			}
			s.RestoreInbounds()
		}()
		writeJSON(w, map[string]any{"ok": true, "component": "xray", "version": newVer})
	case "nginx":
		out, err := exec.Command("bash", "-c", "apt-get update -qq && apt-get install -y -qq --only-upgrade nginx 2>&1 | tail -3; nginx -v 2>&1").CombinedOutput()
		if err != nil {
			http.Error(w, "обновление nginx: "+string(out), 500)
			return
		}
		exec.Command("systemctl", "reload", "nginx").Run()
		s.store.AddEvent("system_update", "ok", "мастер: nginx обновлён", "{}")
		writeJSON(w, map[string]any{"ok": true, "component": "nginx", "output": strings.TrimSpace(string(out))})
	default:
		http.Error(w, "component: xray|nginx (панель — самообновление позже)", 400)
	}
}
// GET /api/system/panel-update — проверка обновления панели (GitHub releases).
func (s *Server) panelUpdateCheck(w http.ResponseWriter, r *http.Request) {
	rels := githubReleases("kambarro/xkit-panel", 1)
	latest := ""
	if len(rels) > 0 { latest = rels[0] }
	available := latest != "" && latest != s.version && latest != "v"+s.version
	writeJSON(w, map[string]any{
		"current": s.version,
		"latest": latest,
		"update_available": available,
	})
}

// knownXrayVersion — SEC-01: версия должна присутствовать в списке релизов
// XTLS/Xray-core (стабильные + бета, как в UI «Версии компонентов»).
func knownXrayVersion(ver string) bool {
	for _, rel := range githubReleasesFull("XTLS/Xray-core", 14) {
		if rel.Tag == ver {
			return true
		}
	}
	return false
}

// verifyReleaseFile — SEC-05: скачать SHA256SUMS + SHA256SUMS.sig релиза,
// проверить Ed25519-подпись (ssh-keygen -Y verify, namespace xkit-release,
// ключ — embedded assets/allowed_signers), затем SHA-256 скачанного файла.
// Любая проверка не прошла → ошибка, установка ЗАПРЕЩЕНА.
func verifyReleaseFile(tag, assetName, filePath string) error {
	dir, err := os.MkdirTemp("", "xkit-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	base := fmt.Sprintf("https://github.com/kambarro/xkit-panel/releases/download/%s", tag)
	sumsPath := filepath.Join(dir, "SHA256SUMS")
	sigPath := filepath.Join(dir, "SHA256SUMS.sig")
	signersPath := filepath.Join(dir, "allowed_signers")
	for _, dl := range []struct{ url, path string }{
		{base + "/SHA256SUMS", sumsPath},
		{base + "/SHA256SUMS.sig", sigPath},
	} {
		if out, err := exec.Command("curl", "-fsSL", "--max-time", "30", "-o", dl.path, dl.url).CombinedOutput(); err != nil {
			return fmt.Errorf("скачивание %s: %v: %s", filepath.Base(dl.path), err, out)
		}
	}
	// ключ подписи — встроен в бинарь (не скачиваем: иначе MITM подменит и ключ)
	if err := os.WriteFile(signersPath, []byte(allowedSigners), 0600); err != nil {
		return err
	}
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	verify := exec.Command("ssh-keygen", "-Y", "verify", "-f", signersPath,
		"-I", "xkit-release", "-n", "xkit-release", "-s", sigPath)
	verify.Stdin = bytes.NewReader(sums)
	if out, err := verify.CombinedOutput(); err != nil {
		return fmt.Errorf("подпись релиза НЕВЕРНА (ssh-keygen -Y verify): %v: %s", err, out)
	}
	// SHA-256 конкретного артефакта из подписанного SHA256SUMS
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == assetName {
			want = fields[0]
			break
		}
	}
	if want == "" {
		return fmt.Errorf("артефакт %s отсутствует в SHA256SUMS", assetName)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	got := fmt.Sprintf("%x", sha256.Sum256(data))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("SHA-256 %s НЕ СОВПАЛ (want %s, got %s)", assetName, want, got)
	}
	return nil
}

// POST /api/system/panel-update — скачать, ПРОВЕРИТЬ ПОДПИСЬ и установить обновление панели.
func (s *Server) panelUpdateApply(w http.ResponseWriter, r *http.Request) {
	rels := githubReleasesFull("kambarro/xkit-panel", 1)
	if len(rels) == 0 { http.Error(w, "не удалось получить релизы", 500); return }
	tag := rels[0].Tag
	if !validVersion(strings.TrimPrefix(tag, "v")) {
		http.Error(w, "некорректный тег релиза", 500); return
	}
	// архитектура
	arch := "linux-64"
	if out, _ := exec.Command("uname", "-m").Output(); strings.Contains(string(out), "aarch64") { arch = "linux-arm64-v8a" }
	assetName := "xkit-panel-" + arch
	dlURL := fmt.Sprintf("https://github.com/kambarro/xkit-panel/releases/download/%s/%s", tag, assetName)
	// скачиваем во временный каталог
	tmpDir, err := os.MkdirTemp("", "xkit-panel-update-")
	if err != nil { http.Error(w, "tmp: "+err.Error(), 500); return }
	defer os.RemoveAll(tmpDir)
	tmp := filepath.Join(tmpDir, assetName)
	if out, err := exec.Command("curl", "-fsSL", "--max-time", "120", "-o", tmp, dlURL).CombinedOutput(); err != nil {
		http.Error(w, "download: "+string(out), 500); return
	}
	// SEC-05: SHA256SUMS + Ed25519-подпись ДО установки (иначе подмена бинаря = RCE)
	if err := verifyReleaseFile(tag, assetName, tmp); err != nil {
		s.store.AddEvent("system_update", "error", "обновление панели отклонено: "+err.Error(), "{}")
		http.Error(w, "проверка релиза: "+err.Error(), 400); return
	}
	// устанавливаем + рестарт
	if out, err := exec.Command("bash", "-c", "install -m755 "+tmp+" /usr/local/bin/xkit-panel && rm -f "+tmp+" && systemctl restart xkit-panel").CombinedOutput(); err != nil {
		http.Error(w, "install: "+string(out), 500); return
	}
	writeJSON(w, map[string]any{"ok": true, "version": tag})
}
