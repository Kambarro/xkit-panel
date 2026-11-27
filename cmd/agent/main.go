// Command xkit-agent — лёгкий агент на НОДЕ (принцип проекта: «спросить у ноды»).
// НЕ целая панель: мини-раннер кита + метрики. Слушает ТОЛЬКО 127.0.0.1 (без публичного API),
// мастер опрашивает через SSH-туннель (ключ уже есть после provision).
//
// Возможности:
//   GET /metrics  — CPU/RAM/диск/сеть/online (как дашборд мастера, но ноды)
//   GET /health   — жив ли агент
//   POST /tunnel  — поднять/сменить каскадный туннель (xray-транспорт уже есть; AWG/hysteria — этапы)
//
// Безопасность: bind 127.0.0.1, токен в заголовке X-Agent-Token (из /etc/xkit-agent/token).
package main

import (
	"os/exec"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const agentVersion = "0.1.0"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Println(agentVersion)
		return
	}
	addr := env("XKIT_AGENT_ADDR", "127.0.0.1:9101")
	token := readToken()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/metrics", auth(token, handleMetrics))
	mux.HandleFunc("/info", auth(token, handleInfo))
	mux.HandleFunc("/tunnel", auth(token, handleTunnel))
	mux.HandleFunc("/xray", auth(token, handleXray))
	mux.HandleFunc("/doctor", auth(token, handleDoctor))
	srv := &http.Server{Addr: addr, Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	// восстановим AWG-каскад если был настроен
	go restoreAWGTunnel()
	fmt.Fprintf(os.Stderr, "xkit-agent %s слушает %s (localhost only)\n", agentVersion, addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" { return v }
	return def
}

func readToken() string {
	if b, err := os.ReadFile("/etc/xkit-agent/token"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return env("XKIT_AGENT_TOKEN", "")
}

func auth(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token != "" {
			got := r.Header.Get("X-Agent-Token")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "unauthorized", 401)
				return
			}
		}
		next(w, r)
	}
}

func handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"agent": agentVersion, "hostname": hostname(), "go": runtime.Version()})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := map[string]any{}
	// CPU
	m["cpu_cores"] = runtime.NumCPU()
	m["cpu_pct"] = cpuPct()
	if model, mhz := cpuInfo(); model != "" { m["cpu_model"] = model; m["cpu_mhz"] = mhz }
	// RAM
	tot, used, free := memInfo()
	m["ram_total_mb"], m["ram_used_mb"], m["ram_free_mb"] = tot, used, free
	// disk
	dt, du, df := diskInfo("/")
	m["disk_total_gb"], m["disk_used_gb"], m["disk_free_gb"] = dt, du, df
	// net cumulative + rate
	rx, tx := netTotals()
	m["net_rx_bytes"], m["net_tx_bytes"] = rx, tx
	m["net_rx_sec"], m["net_tx_sec"] = netRate(rx, tx)
	// uptime/loadavg
	m["uptime_sec"] = uptime()
	m["loadavg1"], m["loadavg5"], m["loadavg15"] = loadAvg()
	m["ts"] = time.Now().Unix()
	writeJSON(w, m)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

var lastCPU idleTotal
var haveCPU bool
type idleTotal struct{ idle, total uint64 }

func cpuPct() float64 {
	it := procStat()
	defer func() { lastCPU = it; haveCPU = true }()
	if !haveCPU || it.total <= lastCPU.total { return 0 }
	dt := it.total - lastCPU.total
	di := it.idle - lastCPU.idle
	if dt == 0 { return 0 }
	return float64(dt-di) / float64(dt) * 100
}

func procStat() idleTotal {
	data, err := os.ReadFile("/proc/stat")
	if err != nil { return idleTotal{} }
	f := strings.Fields(strings.Split(string(data), "\n")[0])
	if len(f) < 5 || f[0] != "cpu" { return idleTotal{} }
	var it idleTotal
	var vals []uint64
	for _, x := range f[1:] { v, _ := strconv.ParseUint(x, 10, 64); vals = append(vals, v); it.total += v }
	if len(vals) >= 4 { it.idle = vals[3] }
	return it
}

func cpuInfo() (string, float64) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil { return "", 0 }
	var model string
	var mhz float64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "model name") && model == "" { model = strings.TrimSpace(strings.SplitN(line, ":", 2)[1]) }
		if strings.HasPrefix(line, "cpu MHz") && mhz == 0 { mhz, _ = strconv.ParseFloat(strings.TrimSpace(strings.SplitN(line, ":", 2)[1]), 64) }
	}
	return model, mhz
}

func memInfo() (total, used, free int) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil { return }
	var t, a int64
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 { continue }
		v, _ := strconv.ParseInt(f[1], 10, 64)
		if f[0] == "MemTotal:" { t = v }
		if f[0] == "MemAvailable:" { a = v }
	}
	total = int(t / 1024); free = int(a / 1024); used = total - free
	return
}

func diskInfo(path string) (total, used, free float64) {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil { return }
	tb := uint64(st.Blocks) * uint64(st.Bsize)
	fb := uint64(st.Bavail) * uint64(st.Bsize)
	total = float64(tb) / 1e9; free = float64(fb) / 1e9; used = total - free
	return
}

func netTotals() (rx, tx int64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil { return }
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, ":") { continue }
		parts := strings.SplitN(line, ":", 2)
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" || strings.HasPrefix(iface, "veth") || strings.HasPrefix(iface, "docker") || strings.HasPrefix(iface, "br-") { continue }
		f := strings.Fields(parts[1])
		if len(f) < 9 { continue }
		r, _ := strconv.ParseInt(f[0], 10, 64); t, _ := strconv.ParseInt(f[8], 10, 64)
		rx += r; tx += t
	}
	return
}

var lastNet struct{ rx, tx int64; ts time.Time }
var haveNet bool
func netRate(rx, tx int64) (rxSec, txSec float64) {
	now := time.Now()
	defer func() { lastNet.rx, lastNet.tx, lastNet.ts, haveNet = rx, tx, now, true }()
	if !haveNet { return 0, 0 }
	dt := now.Sub(lastNet.ts).Seconds()
	if dt <= 0 { return 0, 0 }
	if rx >= lastNet.rx { rxSec = float64(rx-lastNet.rx) / dt }
	if tx >= lastNet.tx { txSec = float64(tx-lastNet.tx) / dt }
	return
}

func uptime() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil { return 0 }
	f := strings.Fields(string(data))
	if len(f) == 0 { return 0 }
	u, _ := strconv.ParseFloat(f[0], 64)
	return int64(u)
}

func loadAvg() (a, b, c float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil { return }
	f := strings.Fields(string(data))
	if len(f) >= 3 { a, _ = strconv.ParseFloat(f[0], 64); b, _ = strconv.ParseFloat(f[1], 64); c, _ = strconv.ParseFloat(f[2], 64) }
	return
}
func handleDoctor(w http.ResponseWriter, r *http.Request) {
	type check struct {
		ID string `json:"id"`
		Name string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
		Fixable bool `json:"fixable"`
	}
	var checks []check
	add := func(id, name, status, detail string, fixable bool) {
		checks = append(checks, check{id, name, status, detail, fixable})
	}
	// xray alive
	if out, err := exec.Command("systemctl", "is-active", "xray").Output(); err == nil && strings.TrimSpace(string(out)) == "active" {
		add("xray", "Xray", "ok", "Работает", false)
	} else { add("xray", "Xray", "error", "Не работает", true) }
	// xray version
	if out, err := exec.Command("/usr/local/bin/xray", "version").Output(); err == nil {
		f := strings.Fields(string(out)); if len(f)>1 { add("xray_ver", "Версия Xray", "ok", f[1], false) }
	}
	// BBR
	if out, err := exec.Command("sysctl", "-n", "net.ipv4.tcp_congestion_control").Output(); err == nil && strings.TrimSpace(string(out)) == "bbr" {
		add("bbr", "BBR", "ok", "Включён", false)
	} else { add("bbr", "BBR", "warn", "Не включён", true) }
	// disk
	if out, err := exec.Command("df", "--output=avail", "-B1", "/").Output(); err == nil {
		f := strings.Fields(string(out)); if len(f)>1 { var a int64; fmt.Sscanf(f[1],"%d",&a); gb:=a/(1024*1024*1024)
			if gb>1 { add("disk","Диск","ok",fmt.Sprintf("%d GB свободно",gb),false) } else { add("disk","Диск","warn",fmt.Sprintf("Мало: %d GB",gb),false) } }
	}
	// UFW
	if out, err := exec.Command("ufw", "status").Output(); err == nil && strings.Contains(string(out), "Status: active") {
		add("ufw", "UFW", "ok", "Активен", false)
	} else { add("ufw", "UFW", "warn", "Не активен", true) }
	// agent version
	add("agent_ver", "Агент", "ok", agentVersion, false)
	writeJSON(w, checks)
}
