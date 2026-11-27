package main

// tunneluuid.go — SEC-03: инициализация tunnel_uuid каскада при старте панели.
// Источник: <data_dir>/tunnel.env (install.sh пишет TUNNEL_UUID=xxx / tunnel_uuid=xxx).
// Файла нет или значение пустое → генерируем crypto/rand UUID v4 и сохраняем в settings.
// Хардкод-дефолт запрещён: предсказуемый общий UUID открывает каскад мастер↔нода.

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kambarro/xkit-panel/internal/store"
)

// initTunnelUUID — читает tunnel.env из dataDir, кладёт UUID в settings.
// Уже сохранённый непустой tunnel_uuid не перезатирается (стабильность каскада).
func initTunnelUUID(st *store.Store, dataDir string) {
	if cur := st.GetSetting("tunnel_uuid", ""); cur != "" {
		return
	}
	uuid := tunnelUUIDFromEnv(filepath.Join(dataDir, "tunnel.env"))
	if uuid == "" {
		uuid = randUUIDv4()
	}
	if err := st.SetSetting("tunnel_uuid", uuid); err != nil {
		fmt.Fprintf(os.Stderr, "WARN tunnel_uuid: %v\n", err)
	}
}

// tunnelUUIDFromEnv — парсит KEY=VALUE (TUNNEL_UUID, регистр ключа не важен).
func tunnelUUIDFromEnv(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "TUNNEL_UUID") {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// randUUIDv4 — UUID v4 из crypto/rand (RFC 4122).
func randUUIDv4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand не должен падать; fallback всё равно НЕ хардкод
		return fmt.Sprintf("xkit-%d", os.Getpid())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}