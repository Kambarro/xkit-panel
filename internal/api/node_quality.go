package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

// GET /api/nodes/quality?id=<nodeID>&period=1h|24h|7d|30d — история качества ноды.
// Агрегаты: uptime%, avg/max latency, avg load, online + график (downsample).
func (s *Server) nodeQuality(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id обязателен", 400)
		return
	}
	period := r.URL.Query().Get("period")
	if period == "" { period = "24h" }
	sec := periodSeconds(period)
	now := time.Now().Unix()
	since := now - int64(sec)
	samples, _ := s.store.NodeSamplesSince(id, since)
	uptime, avgLat, maxLat, avgLoad, total := s.store.NodeQualityStats(id, since)
	// текущие метрики ноды
	var curLat, curUptime, curScore float64
	var health string
	s.store.DB().QueryRow(`SELECT latency_ms,uptime_pct,quality_score,health FROM nodes WHERE id=?`, id).Scan(&curLat, &curUptime, &curScore, &health)
	graph := downsampleNode(samples, 200)
	writeJSON(w, map[string]any{
		"id": id, "period": period, "samples": total, "since": since, "until": now,
		"uptime_pct": uptime, "avg_latency_ms": avgLat, "max_latency_ms": maxLat, "avg_load_pct": avgLoad,
		"current_latency_ms": curLat, "current_uptime_pct": curUptime, "quality_score": curScore, "health": health,
		"graph": graph,
	})
}

// GET /api/nodes/quality/all — сравнение всех нод по качеству (для выбора/ранжирования).
func (s *Server) nodesQualityAll(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" { period = "24h" }
	since := time.Now().Unix() - int64(periodSeconds(period))
	all := s.allNodes()
	type nq struct {
		ID           string  `json:"id"`
		Name         string  `json:"name"`
		Country      string  `json:"country"`
		Health       string  `json:"health"`
		LatencyMs    float64 `json:"latency_ms"`
		UptimePct    float64 `json:"uptime_pct"`
		QualityScore float64 `json:"quality_score"`
		Clients      int     `json:"clients"`
	}
	var out []nq
	for _, n := range all {
		cnt := 0
		if a, err := s.store.AssignmentsByNode(n.ID); err == nil { cnt = len(a) }
		// uptime за период из истории (точнее чем текущий 24h)
		up, _, _, _, _ := s.store.NodeQualityStats(n.ID, since)
		if up == 0 { up = n.UptimePct }
		out = append(out, nq{n.ID, n.Name, n.Country, n.Health, n.LatencyMs, up, n.QualityScore, cnt})
	}
	// сортировка по quality_score DESC (лучшие сверху)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].QualityScore > out[i].QualityScore { out[i], out[j] = out[j], out[i] }
		}
	}
	if out == nil { out = []nq{} }
	writeJSON(w, map[string]any{"period": period, "nodes": out})
}

func downsampleNode(samples []store.NodeSample, maxPoints int) []store.NodeSample {
	if len(samples) <= maxPoints { return samples }
	step := len(samples) / maxPoints
	if step < 1 { step = 1 }
	var out []store.NodeSample
	for i := 0; i < len(samples); i += step { out = append(out, samples[i]) }
	return out
}
// POST /api/nodes/quality/reset {id} — сброс статистики качества ноды.
func (s *Server) nodeQualityReset(w http.ResponseWriter, r *http.Request) {
	var body struct{ ID string `json:"id"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "id обязателен", 400); return
	}
	if err := s.store.ResetNodeSamples(body.ID); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("node_quality", "ok", "статистика качества ноды сброшена", fmt.Sprintf(`{"node":%q}`, body.ID))
	writeJSON(w, map[string]any{"ok": true})
}
