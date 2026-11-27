package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kambarro/xkit-panel/internal/auth"
	"github.com/kambarro/xkit-panel/internal/store"
)

// RESCUE-CLI (P1 #7, panels-research Remnawave rescue-cli / Hiddify CLI / 3x-ui меню x-ui).
// УРОК (владелец): «забыла пароль / панель не открывается» — без паники и SSH-экспедиций.
// Подкоманды через SSH на сервер: reset-password / admin-url / status / restore / help.
// CLI нужен ТОЛЬКО для первой установки и аварийного переезда (директива владельца).

func runRescueCLI(cmd string) {
	dbPath := env("XKIT_DB", "/var/lib/xkit-panel/panel.db")
	switch cmd {
	case "help", "--help", "-h":
		fmt.Print(rescueHelp)
		return
	case "reset-password":
		rescueResetPassword(dbPath)
	case "admin-url":
		rescueAdminURL(dbPath)
	case "status":
		rescueStatus(dbPath)
	case "restore":
		rescueRestore(dbPath)
	}
}

const rescueHelp = `XKIT Panel — аварийный CLI (через SSH на сервер)

  xkit-panel reset-password   Сбросить пароль админа (новый одноразовый, сменить при входе)
  xkit-panel admin-url        Показать адрес панели + логин (если забыли URL)
  xkit-panel status           Статус: панель/Xray/ноды/клиенты/бэкапы
  xkit-panel restore [файл]   Восстановить из бэкапа (последний или указанный tar.gz)
  xkit-panel help             Эта справка

Пароль/логин также в /var/lib/xkit-panel/first-login.txt после сброса.
`

func rescueResetPassword(dbPath string) {
	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()
	au := auth.New(st)
	user := au.AdminUsername()
	if user == "" {
		fmt.Fprintln(os.Stderr, "админ не найден в базе")
		os.Exit(1)
	}
	newPass := randPassword()
	if err := au.ResetPassword(user, newPass); err != nil {
		fmt.Fprintf(os.Stderr, "reset: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Пароль сброшен.\n  login: %s\n  одноразовый пароль: %s\n  Сменить при входе. Все активные сессии завершены.\n", user, newPass)
	os.WriteFile(parentDir(dbPath)+"/first-login.txt", []byte(fmt.Sprintf("login=%s\npassword=%s\nодноразовый — сменить при входе\n", user, newPass)), 0600)
}

func rescueAdminURL(dbPath string) {
	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()
	// УРОК (live): CLI через SSH не наследует env systemd-сервиса — читаем drop-in.
	domain := env("XKIT_DOMAIN", "")
	secret := env("XKIT_SECRET_PATH", "")
	if domain == "" || secret == "" {
		d, s := readServiceEnv()
		if domain == "" { domain = d }
		if secret == "" { secret = s }
	}
	if domain == "" { domain = "localhost" }
	au := auth.New(st)
	user := au.AdminUsername()
	url := "https://" + domain + "/"
	if secret != "" {
		url += strings.Trim(secret, "/") + "/"
	}
	fmt.Printf("Адрес панели: %s\n  login: %s\n", url, user)
	fmt.Println("Пароль: если забыли — xkit-panel reset-password")
	if b, err := os.ReadFile(parentDir(dbPath) + "/first-login.txt"); err == nil {
		fmt.Printf("\nПоследний сброс:\n%s", string(b))
	}
}

// readServiceEnv — читает XKIT_DOMAIN/XKIT_SECRET_PATH из systemd unit + drop-in панели
// (CLI через SSH не наследует Environment сервиса). УРОК live: DOMAIN/SECRET в основном
// unit, drop-in только pass/reality — читаем ОБА.
func readServiceEnv() (domain, secret string) {
	files := []string{"/etc/systemd/system/xkit-panel.service"}
	matches, _ := filepath.Glob("/etc/systemd/system/xkit-panel.service.d/*.conf")
	files = append(files, matches...)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil { continue }
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Environment=") {
				for _, kv := range strings.Fields(strings.TrimPrefix(line, "Environment=")) {
					if strings.HasPrefix(kv, "XKIT_DOMAIN=") { domain = strings.TrimPrefix(kv, "XKIT_DOMAIN=") }
					if strings.HasPrefix(kv, "XKIT_SECRET_PATH=") { secret = strings.TrimPrefix(kv, "XKIT_SECRET_PATH=") }
				}
			}
		}
	}
	return
}

func rescueStatus(dbPath string) {
	fmt.Println("=== XKIT Panel status ===")
	// сервисы
	for _, svc := range []string{"xkit-panel", "xray", "nginx"} {
		out, _ := exec.Command("systemctl", "is-active", svc).Output()
		fmt.Printf("  %-14s %s\n", svc, strings.TrimSpace(string(out)))
	}
	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store: %v\n", err)
		return
	}
	defer st.Close()
	var nodes, clients, alive int
	st.DB().QueryRow(`SELECT COUNT(*) FROM nodes`).Scan(&nodes)
	st.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE health='alive'`).Scan(&alive)
	st.DB().QueryRow(`SELECT COUNT(*) FROM clients WHERE enabled=1`).Scan(&clients)
	fmt.Printf("  ноды:          %d (живых %d)\n", nodes, alive)
	fmt.Printf("  клиенты:       %d активных\n", clients)
	// бэкапы
	backupDir := env("XKIT_BACKUP_DIR", parentDir(dbPath)+"/backups")
	if entries, err := os.ReadDir(backupDir); err == nil {
		cnt := 0
		var latest string
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "xkit-panel-backup-") && strings.HasSuffix(e.Name(), ".tar.gz") {
				cnt++
				latest = e.Name()
			}
		}
		fmt.Printf("  бэкапы:        %d (последний: %s)\n", cnt, latest)
	} else {
		fmt.Println("  бэкапы:        нет директории")
	}
	// AWG
	if out, err := exec.Command("ip", "-br", "addr", "show", "awg0").Output(); err == nil && len(out) > 0 {
		fmt.Printf("  AmneziaWG:     %s\n", strings.TrimSpace(string(out)))
	}
}

func rescueRestore(dbPath string) {
	backupDir := env("XKIT_BACKUP_DIR", parentDir(dbPath)+"/backups")
	// аргумент: путь к файлу или последний
	var archive string
	if len(os.Args) > 2 {
		archive = os.Args[2]
	} else {
		entries, err := os.ReadDir(backupDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "бэкапы не найдены: %v\n", err)
			os.Exit(1)
		}
		var names []string
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "xkit-panel-backup-") && strings.HasSuffix(e.Name(), ".tar.gz") {
				names = append(names, e.Name())
			}
		}
		if len(names) == 0 {
			fmt.Fprintln(os.Stderr, "нет бэкапов для восстановления")
			os.Exit(1)
		}
		// последний по имени (timestamp в имени)
		archive = backupDir + "/" + names[len(names)-1]
		for _, n := range names {
			if n > names[len(names)-1] {
				archive = backupDir + "/" + n
			}
		}
	}
	if _, err := os.Stat(archive); err != nil {
		fmt.Fprintf(os.Stderr, "архив не найден: %s\n", archive)
		os.Exit(1)
	}
	fmt.Printf("Восстановление из: %s\n", archive)
	fmt.Println("Останавливаю панель и Xray…")
	exec.Command("systemctl", "stop", "xkit-panel", "xray").Run()
	// распаковка в / (архив содержит полные пути var/lib/... etc/...)
	out, err := exec.Command("tar", "xzf", archive, "-C", "/").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "распаковка: %v\n%s\n", err, out)
		os.Exit(1)
	}
	fmt.Println("Запускаю Xray и панель…")
	exec.Command("systemctl", "start", "xray").Run()
	exec.Command("systemctl", "start", "xkit-panel").Run()
	fmt.Println("Готово. UUID/subId клиентов сохранены — подписки заработают без перенастройки.")
	fmt.Println("Если IP сменился — переключите A-запись домена на новый IP.")
	fmt.Println("Проверьте: xkit-panel status")
}