package store

import "time"

// NodeSample — сэмпл качества ноды (история для графиков/выбора).
type NodeSample struct {
	Ts        int64   `json:"ts"`
	NodeID    string  `json:"node_id"`
	OK        bool    `json:"ok"`
	LatencyMs float64 `json:"latency_ms"`
	LoadPct   float64 `json:"load_pct"`
	Clients   int     `json:"clients"`
}

func (s *Store) AddNodeSample(m NodeSample) error {
	ok := 0
	if m.OK { ok = 1 }
	_, err := s.db.Exec(`INSERT INTO node_samples(ts,node_id,ok,latency_ms,load_pct,clients) VALUES(?,?,?,?,?,?)`,
		m.Ts, m.NodeID, ok, m.LatencyMs, m.LoadPct, m.Clients)
	return err
}

// NodeSamplesSince — история ноды за период.
func (s *Store) NodeSamplesSince(nodeID string, since int64) ([]NodeSample, error) {
	rows, err := s.db.Query(`SELECT ts,node_id,ok,latency_ms,load_pct,clients FROM node_samples WHERE node_id=? AND ts>=? ORDER BY ts`, nodeID, since)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []NodeSample
	for rows.Next() {
		var m NodeSample
		var ok int
		if err := rows.Scan(&m.Ts, &m.NodeID, &ok, &m.LatencyMs, &m.LoadPct, &m.Clients); err == nil {
			m.OK = ok == 1
			out = append(out, m)
		}
	}
	return out, nil
}

// SetNodeQuality — текущие метрики качества ноды (latency/uptime/score).
func (s *Store) SetNodeQuality(id string, latencyMs, uptimePct, score float64) error {
	_, err := s.db.Exec(`UPDATE nodes SET latency_ms=?,uptime_pct=?,quality_score=? WHERE id=?`, latencyMs, uptimePct, score, id)
	return err
}

// NodeQualityStats — агрегаты истории ноды за период: uptime%, avg/max latency, avg load.
// УРОК (дедлок): SetMaxOpenConns(1) → НЕЛЬЗЯ делать вложенный QueryRow пока открыт
// другой Row (conn не освобождён). Считаем всё ОДНИМ запросом.
func (s *Store) NodeQualityStats(nodeID string, since int64) (uptimePct, avgLat, maxLat, avgLoad float64, samples int) {
	var total, okCnt int
	var al, ml, aload float64
	// один запрос: total всех, okCnt успешных, avg/max latency и avg load по успешным
	err := s.db.QueryRow(`SELECT
		COUNT(*),
		SUM(CASE WHEN ok=1 THEN 1 ELSE 0 END),
		AVG(CASE WHEN ok=1 THEN latency_ms END),
		MAX(CASE WHEN ok=1 THEN latency_ms END),
		AVG(CASE WHEN ok=1 THEN load_pct END)
		FROM node_samples WHERE node_id=? AND ts>=?`, nodeID, since).
		Scan(&total, &okCnt, &al, &ml, &aload)
	if err == nil && total > 0 {
		uptimePct = float64(okCnt) / float64(total) * 100
		avgLat, maxLat, avgLoad, samples = al, ml, aload, total
	}
	return
}

// PruneNodeSamples — чистка истории нод старше days дней.
func (s *Store) PruneNodeSamples(days int) {
	cutoff := time.Now().Unix() - int64(days)*86400
	s.db.Exec(`DELETE FROM node_samples WHERE ts<?`, cutoff)
}
// ResetNodeSamples — сброс истории качества ноды (кнопка "Сбросить статистику").
// После переустановки/долгого офлайна старые down-сэмплы режут score — сбрасываем.
func (s *Store) ResetNodeSamples(nodeID string) error {
	_, err := s.db.Exec(`DELETE FROM node_samples WHERE node_id=?`, nodeID)
	if err != nil { return err }
	_, err = s.db.Exec(`UPDATE nodes SET uptime_pct=100, quality_score=0 WHERE id=?`, nodeID)
	return err
}
