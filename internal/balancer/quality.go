package balancer

// nodeQualityScore — интегральная оценка качества ноды 0..100 для выбора.
// Компоненты: доступность (uptime), задержка (latency), загрузка (load).
// down → 0. Чем выше score — тем лучше нода.
func nodeQualityScore(ok bool, latencyMs, uptimePct, loadPct float64) float64 {
	if !ok {
		return 0
	}
	// latency: 0мс→100, 300мс+→0 (линейно)
	latScore := 100.0 - latencyMs/3.0
	if latScore < 0 { latScore = 0 }
	if latScore > 100 { latScore = 100 }
	// load: 0%→100, 100%→0
	loadScore := 100.0 - loadPct
	if loadScore < 0 { loadScore = 0 }
	// веса: uptime 50%, latency 30%, load 20%
	score := uptimePct*0.5 + latScore*0.3 + loadScore*0.2
	if score > 100 { score = 100 }
	if score < 0 { score = 0 }
	return score
}