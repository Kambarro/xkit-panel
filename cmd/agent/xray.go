// Единая доставка xray-конфига на ноду через агента (принцип проекта:
// «всё должно быть единообразно, если есть агент — переиспользуем код»).
// Раньше xray-конфиг ехал по SSH (cat + restart), AWG — через агента. Теперь ОБА через агента.
// POST /xray {action:apply|status, config} — валидация → применение → откат при провале.
// GET /xray — текущий статус (active + hash конфига для drift-detection).
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const xrayCfgPath = "/usr/local/etc/xray/config.json"
const xrayBackupPath = "/usr/local/etc/xray/config.json.bak"

func handleXray(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, xrayStatus())
		return
	}
	var req struct {
		Action string          `json:"action"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	switch req.Action {
	case "status":
		writeJSON(w, xrayStatus())
	case "apply":
		if len(req.Config) == 0 {
			http.Error(w, "config обязателен", 400)
			return
		}
		// config может прийти как JSON-объект или как строка (мастер шлёт строку)
		cfgStr := string(req.Config)
		var asString string
		if json.Unmarshal(req.Config, &asString) == nil {
			cfgStr = asString
		}
		if err := applyXrayConfig(cfgStr); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true, "status": xrayStatus()})
	default:
		http.Error(w, "action: apply|status", 400)
	}
}

// xrayStatus — active + hash текущего конфига (drift-detection мастером).
func xrayStatus() map[string]any {
	active := exec.Command("systemctl", "is-active", "xray").Run() == nil
	hash := ""
	if b, err := os.ReadFile(xrayCfgPath); err == nil {
		hash = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	return map[string]any{"active": active, "hash": hash, "version": xrayVersion()}
}

func xrayVersion() string {
	out, err := exec.Command("/usr/local/bin/xray", "version").Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	if len(f) >= 2 {
		return f[1]
	}
	return ""
}

// applyXrayConfig — валидация → backup → запись → restart → проверка active → откат при провале.
// УРОК: пустой REALITY privateKey = crash-loop; валидация `xray run -test` ловит ДО применения.
func applyXrayConfig(cfg string) error {
	// 1) валидация JSON + xray config test (ловит empty privateKey и пр. ДО рестарта)
	var m map[string]any
	if json.Unmarshal([]byte(cfg), &m) != nil {
		return fmt.Errorf("невалидный JSON")
	}
	tmp := "/tmp/xray-cfg-validate.json"
	if err := os.WriteFile(tmp, []byte(cfg), 0644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	defer os.Remove(tmp)
	if out, err := exec.Command("/usr/local/bin/xray", "run", "-test", "-config", tmp).CombinedOutput(); err != nil {
		return fmt.Errorf("валидация xray: %s", strings.TrimSpace(string(out)))
	}
	// 2) backup текущего (для отката)
	prev, _ := os.ReadFile(xrayCfgPath)
	if len(prev) > 0 {
		os.WriteFile(xrayBackupPath, prev, 0644)
	}
	// 3) запись + restart
	if err := os.WriteFile(xrayCfgPath, []byte(cfg), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	exec.Command("systemctl", "restart", "xray").Run()
	// 4) проверка active (ретрай до 6с — окно activating)
	for i := 0; i < 6; i++ {
		time.Sleep(1 * time.Second)
		if exec.Command("systemctl", "is-active", "xray").Run() == nil {
			return nil
		}
	}
	// 5) откат к backup
	if len(prev) > 0 {
		os.WriteFile(xrayCfgPath, prev, 0644)
		exec.Command("systemctl", "restart", "xray").Run()
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("xray не поднялся после применения (откат выполнен)")
}