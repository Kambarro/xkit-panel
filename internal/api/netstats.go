package api

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Сетевая нагрузка мастера (дашборд): rx/tx байт/сек по /proc/net/dev.
// УРОК (владелец): в дашборде не хватает сетевой нагрузки/загрузки каналов.
// Считаем дельту счётчиков интерфейсов между вызовами (дашборд опрашивается раз в 10с).

type netSample struct {
	rx, tx uint64
	ts     time.Time
}

var (
	netMu   sync.Mutex
	lastNet *netSample
)

// netDevTotals — сумма rx/tx байт по всем не-loopback интерфейсам.
func netDevTotals() (rx, tx uint64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil { return 0, 0 }
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, ":") { continue }
		parts := strings.SplitN(line, ":", 2)
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" || strings.HasPrefix(iface, "veth") || strings.HasPrefix(iface, "docker") || strings.HasPrefix(iface, "br-") { continue }
		fields := strings.Fields(parts[1])
		if len(fields) < 9 { continue }
		r, _ := strconv.ParseUint(fields[0], 10, 64)
		t, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += r
		tx += t
	}
	return
}

// netRate — текущая скорость rx/tx байт/сек (дельта с прошлого замера).
func netRate() (rxSec, txSec float64) {
	rx, tx := netDevTotals()
	now := time.Now()
	netMu.Lock()
	defer netMu.Unlock()
	if lastNet != nil {
		dt := now.Sub(lastNet.ts).Seconds()
		if dt > 0 {
			// счётчики могли сброситься (рестарт интерфейса) — не уходим в минус
			if rx >= lastNet.rx { rxSec = float64(rx-lastNet.rx) / dt }
			if tx >= lastNet.tx { txSec = float64(tx-lastNet.tx) / dt }
		}
	}
	lastNet = &netSample{rx: rx, tx: tx, ts: now}
	return
}