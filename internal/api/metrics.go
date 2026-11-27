package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

// GET /api/metrics?period=5m|1h|12h|24h|7d|30d — история метрик + агрегаты за период.
// Трафик = дельта кумулятивных счётчиков rx/tx за период (реальный объём ГБ).
// Нагрузка = avg/max CPU, RAM. Онлайн = avg/max.
func (s *Server) metricsHistory(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" { period = "1h" }
	sec := periodSeconds(period)
	now := time.Now().Unix()
	since := now - int64(sec)
	samples, _ := s.store.MetricsSince(since)
	// агрегаты
	var cpuSum, cpuMax float64
	var ramSum, ramMax int
	var onlineSum, onlineMax int
	var rxTotal, txTotal int64
	var last *store.MetricSample
	if len(samples) > 0 { last = &samples[len(samples)-1] }
	for i := range samples {
		m := &samples[i]
		cpuSum += m.CPUPct
		if m.CPUPct > cpuMax { cpuMax = m.CPUPct }
		ramSum += m.RAMMB
		if m.RAMMB > ramMax { ramMax = m.RAMMB }
		onlineSum += m.Online
		if m.Online > onlineMax { onlineMax = m.Online }
	}
	n := len(samples)
	if n > 0 {
		// трафик: дельта кумулятивных счётчиков (учитывает сброс при рестарте интерфейса)
		rxTotal = counterDelta(samples, func(m store.MetricSample) int64 { return m.NetRx })
		txTotal = counterDelta(samples, func(m store.MetricSample) int64 { return m.NetTx })
	}
	// даунсэмпл для графика (макс ~200 точек)
	graph := downsample(samples, 200)
	avg := func(sum float64) float64 { if n == 0 { return 0 }; return sum / float64(n) }
	writeJSON(w, map[string]any{
		"period": period, "samples": n, "since": since, "until": now,
		"traffic_rx_bytes": rxTotal, "traffic_tx_bytes": txTotal,
		"traffic_total_bytes": rxTotal + txTotal,
		"cpu_avg": avg(cpuSum), "cpu_max": cpuMax,
		"ram_avg_mb": int(avg(float64(ramSum))), "ram_max_mb": ramMax,
		"online_avg": int(avg(float64(onlineSum))), "online_max": onlineMax,
		"ram_total_mb": lastRAMTotal(last),
		"graph": graph,
	})
}

func lastRAMTotal(m *store.MetricSample) int { if m == nil { return 0 }; return m.RAMTotal }

// counterDelta — сумма положительных дельт кумулятивного счётчика (сброс → 0, не минус).
func counterDelta(samples []store.MetricSample, get func(store.MetricSample) int64) int64 {
	var total int64
	for i := 1; i < len(samples); i++ {
		d := get(samples[i]) - get(samples[i-1])
		if d > 0 { total += d }
	}
	return total
}

func downsample(samples []store.MetricSample, maxPoints int) []store.MetricSample {
	if len(samples) <= maxPoints { return samples }
	step := len(samples) / maxPoints
	if step < 1 { step = 1 }
	var out []store.MetricSample
	for i := 0; i < len(samples); i += step { out = append(out, samples[i]) }
	return out
}

func periodSeconds(p string) int {
	switch p {
	case "5m": return 300
	case "15m": return 900
	case "1h": return 3600
	case "6h": return 21600
	case "12h": return 43200
	case "24h", "1d": return 86400
	case "7d", "1w": return 604800
	case "30d": return 2592000
	default:
		if n, err := strconv.Atoi(p); err == nil && n > 0 { return n }
		return 3600
	}
}