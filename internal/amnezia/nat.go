package amnezia

import (
	"fmt"
	"os/exec"
	"strings"
)

// SetupNAT — включает forwarding + NAT для AWG-подсети (идемпотентно).
// ОГРАНИЧЕНИЕ (аудит #9): AWG-клиенты (10.8.1.0/24) выходят НАПРЯМУЮ с мастера
// (MASQUERADE на внешнем интерфейсе) — это СОЛО-выход с IP мастера, НЕ через ноду.
// AWG-каскад мастер→нода — userspace netstack + SOCKS5 (TCP CONNECT), L3-пакеты
// AWG-клиентов через него не маршрутизируются; для выхода через ноду клиенту
// нужны xray-протоколы (Reality/XHTTP/WS/Hy2). Полный AWG-каскад (TPROXY+dokodemo
// или TUN-каскад с policy routing) — отдельная архитектурная задача, см. README.
// УРОК XKIT: ошибки не глотать; проверять эффект живым замером.
// УРОК MSKtest (live-проба AWG): ufw с policy DROP съедает и INPUT (UDP порт),
// и FORWARD (трафик туннеля). Правила -A в конец НЕ работают — ufw-reject раньше.
// Поэтому: ufw allow <port>/udp + ufw route allow in/out on <iface>, либо -I в начало.
// Вызывается при старте AWG-сервера (панель работает от root на мастере).
func SetupNAT(iface, subnet string, port int) error {
	// ip_forward
	if out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
		return fmt.Errorf("sysctl ip_forward: %v: %s", err, out)
	}
	// определим внешний интерфейс (default route)
	ext := externalIface()
	if ext == "" {
		return fmt.Errorf("не найден внешний интерфейс (default route)")
	}
	// MASQUERADE для подсети (проверка -C перед -A — идемпотентно)
	rule := []string{"-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", ext, "-j", "MASQUERADE"}
	check := []string{"-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-o", ext, "-j", "MASQUERADE"}
	if exec.Command("iptables", check...).Run() != nil {
		if out, err := exec.Command("iptables", rule...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables MASQUERADE: %v: %s", err, out)
		}
	}
	// FORWARD для туннеля: ufw активен → ufw route allow; иначе -I в НАЧАЛО цепочки
	// (урок: -A в конец бесполезен при ufw policy DROP — reject срабатывает раньше).
	if ufwActive() {
		exec.Command("ufw", "route", "allow", "in", "on", iface).Run()
		exec.Command("ufw", "route", "allow", "out", "on", iface).Run()
	} else {
		for _, args := range [][]string{
			{"-I", "FORWARD", "1", "-i", iface, "-j", "ACCEPT"},
			{"-I", "FORWARD", "2", "-o", iface, "-j", "ACCEPT"},
		} {
			chk := []string{"-C", "FORWARD", args[3], args[4], "-j", "ACCEPT"}
			if exec.Command("iptables", chk...).Run() != nil {
				if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
					return fmt.Errorf("iptables FORWARD: %v: %s", err, out)
				}
			}
		}
	}
	// INPUT: UDP порт AWG (handshake иначе дропается — проверено live)
	if err := OpenFirewallPort(port); err != nil {
		return err
	}
	// INPUT на TUN-интерфейсе: расшифрованные пакеты из туннеля попадают в INPUT
	// (dst = локальный IP ноды, напр. ping/health-check) и при ufw policy DROP
	// умирают ДО FORWARD. УРОК live-проба: loopback AWG падал с DIAL ERR,
	// `iptables -I INPUT -i <tun> -j ACCEPT` → сразу SUCCESS. Панель делает сама.
	AllowTunInput(iface)
	// адрес на интерфейсе: 10.8.1.1/24 из подсети
	addr := subnetAddress(subnet)
	if addr != "" {
		exec.Command("ip", "addr", "add", addr, "dev", iface).Run() // может уже быть — не ошибка
		exec.Command("ip", "link", "set", iface, "up").Run()
	}
	// MSS clamping (AWG MTU 1280 — иначе TCP-сессии виснут)
	mss := []string{"-t", "mangle", "-A", "FORWARD", "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"}
	mssChk := append([]string{"-t", "mangle", "-C"}, mss[2:]...)
	if exec.Command("iptables", mssChk...).Run() != nil {
		exec.Command("iptables", mss...).Run()
	}
	return nil
}

func ufwActive() bool {
	return exec.Command("bash", "-c", "command -v ufw >/dev/null && ufw status | grep -q 'Status: active'").Run() == nil
}

// OpenFirewallPort — открывает UDP порт AWG в INPUT (ufw или iptables).
// Вызывается из startAWGServer с реальным портом.
func OpenFirewallPort(port int) error {
	// ufw активен?
	if exec.Command("bash", "-c", "command -v ufw >/dev/null && ufw status | grep -q 'Status: active'").Run() == nil {
		out, err := exec.Command("ufw", "allow", fmt.Sprintf("%d/udp", port)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ufw allow %d/udp: %v: %s", port, err, out)
		}
		return nil
	}
	// чистый iptables: проверим policy INPUT — если DROP, добавим ACCEPT в начало
	out, _ := exec.Command("iptables", "-L", "INPUT", "-n").Output()
	if strings.Contains(string(out), "policy DROP") {
		rule := []string{"-I", "INPUT", "-p", "udp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT"}
		chk := []string{"-C", "INPUT", "-p", "udp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT"}
		if exec.Command("iptables", chk...).Run() != nil {
			if o, err := exec.Command("iptables", rule...).CombinedOutput(); err != nil {
				return fmt.Errorf("iptables INPUT: %v: %s", err, o)
			}
		}
	}
	return nil
}

// AllowTunInput — разрешает INPUT на туннельном интерфейсе (идемпотентно).
// Без этого ufw policy DROP убивает расшифрованные пакеты, destined к самому хосту.
func AllowTunInput(iface string) {
	rule := []string{"-I", "INPUT", "-i", iface, "-j", "ACCEPT"}
	chk := []string{"-C", "INPUT", "-i", iface, "-j", "ACCEPT"}
	if exec.Command("iptables", chk...).Run() != nil {
		exec.Command("iptables", rule...).Run()
	}
}

// CloseFirewallPort — закрывает порт при выключении AWG.
func CloseFirewallPort(port int) {
	if exec.Command("bash", "-c", "command -v ufw >/dev/null && ufw status | grep -q 'Status: active'").Run() == nil {
		exec.Command("ufw", "delete", "allow", fmt.Sprintf("%d/udp", port)).Run()
		return
	}
	exec.Command("iptables", "-D", "INPUT", "-p", "udp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT").Run()
}

// TeardownNAT — убирает правила AWG (при выключении сервера).
func TeardownNAT(iface, subnet string, port int) {
	ext := externalIface()
	if ext != "" {
		exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-o", ext, "-j", "MASQUERADE").Run()
	}
	if ufwActive() {
		exec.Command("ufw", "route", "delete", "allow", "in", "on", iface).Run()
		exec.Command("ufw", "route", "delete", "allow", "out", "on", iface).Run()
	} else {
		exec.Command("iptables", "-D", "FORWARD", "-i", iface, "-j", "ACCEPT").Run()
		exec.Command("iptables", "-D", "FORWARD", "-o", iface, "-j", "ACCEPT").Run()
	}
	CloseFirewallPort(port)
	exec.Command("iptables", "-D", "INPUT", "-i", iface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-t", "mangle", "-D", "FORWARD", "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
	exec.Command("ip", "link", "del", iface).Run()
}

func externalIface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	// "default via X.X.X.X dev eth0 ..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// subnetAddress — адрес сервера .1/маска из подсети ("10.8.1.0/24" → "10.8.1.1/24").
func subnetAddress(subnet string) string {
	parts := strings.SplitN(subnet, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	oct := strings.Split(parts[0], ".")
	if len(oct) != 4 {
		return ""
	}
	oct[3] = "1"
	return strings.Join(oct, ".") + "/" + parts[1]
}