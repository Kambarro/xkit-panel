package firewall

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Менеджер UFW для панели. ПРИНЦИП (требование владельца, «домохозяйка»):
// firewall — автоматика панели, не ручная работа. Default deny incoming.
// Включили протокол → открыли его порт. Выключили/удалили → закрыли.
// Лишние порты закрыты. SSH (22) НЕ трогаем никогда (иначе потеряем доступ).
//
// Все правила панели помечены комментарием "XKIT:auto" чтобы отличать от ручных
// и безопасно чистить. Базовые (22/80/443) управляются отдельно и не удаляются.

const tag = "XKIT:auto"

func ufwActive() bool {
	return exec.Command("bash", "-c", "command -v ufw >/dev/null && ufw status | grep -q 'Status: active'").Run() == nil
}

// EnsureBase — базовая политика: deny incoming, allow outgoing, SSH/HTTP/HTTPS открыты.
// Вызывается при старте панели и установке. НЕ закрывает SSH.
func EnsureBase() error {
	if !ufwActive() {
		// включаем ufw с дефолтной политикой (ssh уже разрешён правилом ниже)
		exec.Command("ufw", "default", "deny", "incoming").Run()
		exec.Command("ufw", "default", "allow", "outgoing").Run()
		exec.Command("ufw", "allow", "22/tcp", "comment", "XKIT:ssh").Run()
		exec.Command("ufw", "--force", "enable").Run()
	}
	// базовые порты всегда открыты (ssh/http/https) — идемпотентно
	exec.Command("ufw", "allow", "22/tcp", "comment", "XKIT:ssh").Run()
	exec.Command("ufw", "allow", "80/tcp", "comment", "XKIT:http").Run()
	exec.Command("ufw", "allow", "443/tcp", "comment", "XKIT:https").Run()
	return nil
}

// OpenPort — открыть порт протокола (tcp/udp) с меткой XKIT:auto. Идемпотентно.
func OpenPort(port int, proto string) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("неверный порт %d", port)
	}
	if proto != "tcp" && proto != "udp" {
		proto = "tcp"
	}
	if !ufwActive() {
		EnsureBase()
	}
	rule := fmt.Sprintf("%d/%s", port, proto)
	out, err := exec.Command("ufw", "allow", rule, "comment", tag).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ufw allow %s: %v: %s", rule, err, out)
	}
	return nil
}

// ClosePort — закрыть порт протокола (удалить XKIT:auto правило). Базовые 22/80/443 не трогаем.
func ClosePort(port int, proto string) error {
	if port == 22 || port == 80 || port == 443 {
		return nil // базовые порты не закрываем
	}
	if proto != "tcp" && proto != "udp" {
		proto = "tcp"
	}
	if !ufwActive() {
		return nil
	}
	rule := fmt.Sprintf("%d/%s", port, proto)
	exec.Command("ufw", "delete", "allow", rule).Run()
	return nil
}

// AutoPorts — список портовcurrently открытых панелью (XKIT:auto), для сверки.
func AutoPorts() []string {
	out, err := exec.Command("bash", "-c", "ufw status | grep '"+tag+"' | awk '{print $1}'").Output()
	if err != nil {
		return nil
	}
	var ports []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			ports = append(ports, l)
		}
	}
	return ports
}

// CleanupLegacy — закрыть ВСЕ лишние ALLOW-порты кроме базовых (22/80/443) и нужных (needed).
// УРОК (директива «закрыть ufw полностью кроме нужных»): на стенде накопились старые
// ручные/XKIT-порты (xhttp/случайные) от прошлых тестов. Default deny уже блокирует остальное,
// но явные ALLOW лишних портов = дыры. Чистим их. SSH/базовые НЕ трогаем. DENY не трогаем.
func CleanupLegacy(needed map[int]string) {
	if !ufwActive() {
		return
	}
	// базовые порты которые всегда открыты
	base := map[int]bool{22: true, 80: true, 443: true}
	out, _ := exec.Command("bash", "-c", "ufw status numbered").Output()
	// собираем номера правил ALLOW на лишние порты (удаляем с конца чтобы номера не съезжали)
	type rule struct {
		num   int
		rule  string
	}
	var toDelete []rule
	for _, line := range strings.Split(string(out), "\n") {
		// формат: "[ 3] 43419/tcp ALLOW IN Anywhere # XKIT:xhttp"
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[") || !strings.Contains(line, "ALLOW IN") {
			continue
		}
		if strings.Contains(line, "(v6)") {
			continue // v6 обработаем отдельно ниже
		}
		// извлечём номер и порт
		closeBracket := strings.Index(line, "]")
		if closeBracket < 0 {
			continue
		}
		numStr := strings.TrimSpace(line[1:closeBracket])
		n, err := strconv.Atoi(numStr)
		if err != nil {
			continue
		}
		rest := strings.TrimSpace(line[closeBracket+1:])
		portField := strings.Fields(rest)[0] // "43419/tcp"
		pp := strings.SplitN(portField, "/", 2)
		port, _ := strconv.Atoi(pp[0])
		if base[port] {
			continue
		}
		if _, ok := needed[port]; ok {
			continue
		}
		toDelete = append(toDelete, rule{n, portField})
	}
	// удаляем с конца (номера не съезжают)
	for i := len(toDelete) - 1; i >= 0; i-- {
		exec.Command("bash", "-c", fmt.Sprintf("echo y | ufw delete %d", toDelete[i].num)).Run()
	}
	// v6: удалим лишние ALLOW v6 по правилу (ufw delete allow <port>/<proto> удаляет и v4 и v6)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "(v6)") || !strings.Contains(line, "ALLOW IN") {
			continue
		}
		closeBracket := strings.Index(line, "]")
		if closeBracket < 0 {
			continue
		}
		rest := strings.TrimSpace(line[closeBracket+1:])
		portField := strings.Fields(rest)[0]
		pp := strings.SplitN(portField, "/", 2)
		port, _ := strconv.Atoi(pp[0])
		if base[port] {
			continue
		}
		if _, ok := needed[port]; ok {
			continue
		}
		exec.Command("ufw", "delete", "allow", portField).Run()
	}
}

// Sync — привести firewall к актуальному набору портов: открыть нужные, закрыть лишние XKIT:auto.
// needed = map[port]proto для всех активных протоколов/сервисов панели.
// Базовые 22/80/443 и SSH не трогаются. Лишние auto-порты (которых нет в needed) закрываются.
func Sync(needed map[int]string) error {
	if !ufwActive() {
		EnsureBase()
	}
	// открываем нужные
	for port, proto := range needed {
		OpenPort(port, proto)
	}
	// закрываем лишние auto-порты
	for _, rule := range AutoPorts() {
		// rule вида "8444/tcp"
		parts := strings.SplitN(rule, "/", 2)
		if len(parts) != 2 {
			continue
		}
		p, _ := strconv.Atoi(parts[0])
		if _, ok := needed[p]; !ok {
			ClosePort(p, parts[1])
		}
	}
	return nil
}

// Status — текстовый статус ufw для UI.
func Status() string {
	out, _ := exec.Command("ufw", "status", "verbose").CombinedOutput()
	return string(out)
}