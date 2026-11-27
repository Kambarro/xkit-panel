package balancer

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

// MetricSampler — функция сбора текущих метрик мастера (задаётся из api при старте).
// Возвращает cpu%, ram used/total MB, кумулятивные net rx/tx байт, онлайн клиентов.
type MetricSampler func(ctx context.Context) store.MetricSample

// StartMetrics запускает сэмплирование метрик раз в 30с + чистку старше 30 дней.
func (c *Controller) StartMetrics(ctx context.Context, sampler MetricSampler) {
	if sampler == nil { return }
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		// первый сэмпл сразу
		c.store.AddMetric(sampler(ctx))
		prune := time.NewTicker(6 * time.Hour)
		defer prune.Stop()
		for {
			select {
			case <-ctx.Done(): return
			case <-c.stopCh: return
			case <-t.C:
				c.store.AddMetric(sampler(ctx))
			case <-prune.C:
				c.store.PruneMetrics(30)
				c.store.PruneEvents(90) // журнал действий: храним 90 дней
			}
		}
	}()
}

// DefaultSampler — сбор метрик из /proc (cpu дельта, meminfo, net/dev) + онлайн из Xray.
func (c *Controller) DefaultSampler() MetricSampler {
	var lastIdle, lastTotal uint64
	var haveLast bool
	return func(ctx context.Context) store.MetricSample {
		m := store.MetricSample{Ts: time.Now().Unix()}
		// CPU дельта с прошлого сэмпла
		idle, total := procStatVals()
		if haveLast && total > lastTotal {
			dt := total - lastTotal
			di := idle - lastIdle
			if dt > 0 { m.CPUPct = float64(dt-di) / float64(dt) * 100 }
		}
		lastIdle, lastTotal, haveLast = idle, total, true
		// RAM
		if data, err := os.ReadFile("/proc/meminfo"); err == nil {
			var tot, avail int64
			for _, line := range strings.Split(string(data), "\n") {
				f := strings.Fields(line)
				if len(f) < 2 { continue }
				v, _ := strconv.ParseInt(f[1], 10, 64)
				if f[0] == "MemTotal:" { tot = v }
				if f[0] == "MemAvailable:" { avail = v }
			}
			m.RAMTotal = int(tot / 1024)
			m.RAMMB = int((tot - avail) / 1024)
		}
		// net кумулятивные
		m.NetRx, m.NetTx = netDevTotalsVals()
		// онлайн
		if c.xray != nil {
			if u, err := c.xray.OnlineUsers(ctx); err == nil { m.Online = len(u) }
		}
		return m
	}
}

func procStatVals() (idle, total uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil { return 0, 0 }
	line := strings.Split(string(data), "\n")[0]
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" { return 0, 0 }
	var vals []uint64
	for _, x := range f[1:] { v, _ := strconv.ParseUint(x, 10, 64); vals = append(vals, v); total += v }
	if len(vals) >= 4 { idle = vals[3] }
	return
}

func netDevTotalsVals() (rx, tx int64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil { return 0, 0 }
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, ":") { continue }
		parts := strings.SplitN(line, ":", 2)
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" || strings.HasPrefix(iface, "veth") || strings.HasPrefix(iface, "docker") || strings.HasPrefix(iface, "br-") { continue }
		f := strings.Fields(parts[1])
		if len(f) < 9 { continue }
		r, _ := strconv.ParseInt(f[0], 10, 64)
		t, _ := strconv.ParseInt(f[8], 10, 64)
		rx += r; tx += t
	}
	return
}