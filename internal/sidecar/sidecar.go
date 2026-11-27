// Package sidecar — управление нативными протокол-демонами (панель=оркестратор).
// УРОК (владелец): не запихивать всё в Xray — для каждого протокола лучшая реализация
// отдельным процессом. Панель: SQLite=правда, systemd lifecycle, конфиг-генерация,
// статистика, обновление версий. Xray остаётся для vless/vmess/trojan/xhttp/reality.
package sidecar

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Kind — тип сайдкара (нативная реализация протокола).
type Kind string

const (
	Hysteria2 Kind = "hysteria2" // github.com/apernet/hysteria (оригинал: hopping/masquerade/brutal)
	TUIC      Kind = "tuic"      // github.com/EAimTY/tuic или sing-box
	Naive     Kind = "naive"     // naiveproxy (sing-box naive inbound)
	SS2022    Kind = "ss2022"    // shadowsocks-rust (или Xray — решает исследование)
	MTProto   Kind = "mtproto"   // mtg (Telegram)
	Mieru     Kind = "mieru"     // mita
)

// Spec — описание сайдкара (что панель знает о демоне).
type Spec struct {
	Kind       Kind
	BinaryName string // hysteria, tuic-server, sing-box, mtg, mita
	ConfigDir  string // /etc/xkit-sidecars
	UnitPrefix string // xkit-
}

var specs = map[Kind]Spec{
	Hysteria2: {Hysteria2, "hysteria", "/etc/xkit-sidecars", "xkit-"},
	TUIC:      {TUIC, "tuic-server", "/etc/xkit-sidecars", "xkit-"},
	Naive:     {Naive, "sing-box", "/etc/xkit-sidecars", "xkit-"},
	SS2022:    {SS2022, "ssserver", "/etc/xkit-sidecars", "xkit-"},
	MTProto:   {MTProto, "mtg", "/etc/xkit-sidecars", "xkit-"},
	Mieru:     {Mieru, "mita", "/etc/xkit-sidecars", "xkit-"},
}

// Manager — управляет сайдкарами через systemd (панель генерит unit+конфиг).
// Выбор systemd (не exec.Cmd): переживает рестарт панели, автозапуск при буте,
// journalctl логи, стандартный для домохозяйки сервера. Бэкап включает конфиги.
type Manager struct {
	configDir string
}

func NewManager(configDir string) *Manager {
	if configDir == "" {
		configDir = "/etc/xkit-sidecars"
	}
	os.MkdirAll(configDir, 0700)
	return &Manager{configDir: configDir}
}

func (m *Manager) ConfigDir() string { return m.configDir }

// UnitName — systemd unit для сайдкара.
func UnitName(id string) string { return "xkit-" + id }

// ConfigPath — путь конфига сайдкара.
func (m *Manager) ConfigPath(id string) string {
	return filepath.Join(m.configDir, id+".yaml")
}

// WriteConfig — записывает конфиг (источник правды — панельная БД, это рендер).
func (m *Manager) WriteConfig(id, content string) error {
	p := m.ConfigPath(id)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		return fmt.Errorf("write config %s: %w", p, err)
	}
	return nil
}

// InstallUnit — создаёт systemd unit (идемпотентно).
func (m *Manager) InstallUnit(id, binary, configPath, args string) error {
	unit := fmt.Sprintf(`[Unit]
Description=XKIT sidecar %s
After=network.target
[Service]
Type=simple
ExecStart=%s %s
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
`, id, binary, args)
	unitPath := "/etc/systemd/system/" + UnitName(id) + ".service"
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("daemon-reload: %v: %s", err, out)
	}
	return nil
}

// Start — запускает сайдкар (enable+start).
func (m *Manager) Start(id string) error {
	if out, err := exec.Command("systemctl", "enable", "--now", UnitName(id)).CombinedOutput(); err != nil {
		return fmt.Errorf("start %s: %v: %s", id, err, out)
	}
	return nil
}

// Stop — останавливает сайдкар (disable+stop).
func (m *Manager) Stop(id string) error {
	if out, err := exec.Command("systemctl", "disable", "--now", UnitName(id)).CombinedOutput(); err != nil {
		return fmt.Errorf("stop %s: %v: %s", id, err, out)
	}
	return nil
}

// Restart — перезапуск (после смены конфига).
func (m *Manager) Restart(id string) error {
	if out, err := exec.Command("systemctl", "restart", UnitName(id)).CombinedOutput(); err != nil {
		return fmt.Errorf("restart %s: %v: %s", id, err, out)
	}
	return nil
}

// Reload — мягкая перечитка конфига (если демон поддерживает SIGHUP; иначе restart).
func (m *Manager) Reload(id string) error {
	// hysteria/tuic не поддерживают hot reload конфига — restart.
	// (исследование уточнит per-kind; пока restart — безопасно, сессии рвутся кратко)
	return m.Restart(id)
}

// IsRunning — живой ли сайдкар (systemctl is-active — эффект, не статус-строка).
func (m *Manager) IsRunning(id string) bool {
	out, err := exec.Command("systemctl", "is-active", UnitName(id)).Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// Status — статус + последние логи (для UI/диагностики).
func (m *Manager) Status(id string) (string, string) {
	out, _ := exec.Command("systemctl", "is-active", UnitName(id)).Output()
	status := strings.TrimSpace(string(out))
	logs, _ := exec.Command("journalctl", "-u", UnitName(id), "--no-pager", "-n", "10").Output()
	return status, string(logs)
}

// RemoveUnit — ПОЛНОЕ удаление сайдкара (УРОК владельца: «если протокол удалять именно
// не отключать, то и удалять его демона для экономии ресурсов»).
// Stop + unit + конфиг + БИНАРЬ (если он принадлежит только этому сайдкару) + логи.
// sharedBinary=true → бинарь общий (sing-box для naive+tuic) — НЕ удаляем.
func (m *Manager) RemoveUnit(id, binary string, sharedBinary bool) {
	m.Stop(id)
	os.Remove("/etc/systemd/system/" + UnitName(id) + ".service")
	os.Remove(m.ConfigPath(id))
	exec.Command("systemctl", "daemon-reload").Run()
	// удаляем бинарь демона если не общий (экономия диска/RAM при будущем старте)
	if !sharedBinary && binary != "" && strings.HasPrefix(binary, "/usr/local/bin/") {
		os.Remove(binary)
	}
	// чистим journal логи юнита (экономия диска)
	exec.Command("journalctl", "--rotate", "--vacuum-time=1s", "-u", UnitName(id)).Run()
}

// IsSharedBinary — используется ли бинарь другими сайдкарами (sing-box: naive+tuic).
// Вызывается перед удалением чтобы не снести общий бинарь.
func IsSharedBinary(binary string, otherBinaries []string) bool {
	for _, b := range otherBinaries {
		if b == binary {
			return true
		}
	}
	return false
}

// BinaryPath — где лежит бинарь демона (или "" если не установлен).
func BinaryPath(kind Kind) string {
	spec, ok := specs[kind]
	if !ok {
		return ""
	}
	if p, err := exec.LookPath(spec.BinaryName); err == nil {
		return p
	}
	// стандартное место установки панелью
	p := "/usr/local/bin/" + spec.BinaryName
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// Version — версия бинаря (для UI/обновлений).
func Version(binary string) string {
	for _, arg := range []string{"version", "--version", "-v"} {
		out, err := exec.Command(binary, arg).Output()
		if err == nil && len(out) > 0 {
			return strings.TrimSpace(strings.Split(string(out), "\n")[0])
		}
	}
	return ""
}

var _ = time.Now