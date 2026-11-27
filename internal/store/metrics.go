package store

import "time"

// MetricSample — сэмпл метрик мастера для истории дашборда.
type MetricSample struct {
	Ts       int64   `json:"ts"`
	CPUPct   float64 `json:"cpu_pct"`
	RAMMB    int     `json:"ram_mb"`
	RAMTotal int     `json:"ram_total"`
	NetRx    int64   `json:"net_rx"`
	NetTx    int64   `json:"net_tx"`
	Online   int     `json:"online"`
}

func (s *Store) AddMetric(m MetricSample) error {
	_, err := s.db.Exec(`INSERT INTO metric_samples(ts,cpu_pct,ram_mb,ram_total,net_rx,net_tx,online) VALUES(?,?,?,?,?,?,?)`,
		m.Ts, m.CPUPct, m.RAMMB, m.RAMTotal, m.NetRx, m.NetTx, m.Online)
	return err
}

// MetricsSince — сэмплы за период [since, now]. Для графиков/агрегатов дашборда.
func (s *Store) MetricsSince(since int64) ([]MetricSample, error) {
	rows, err := s.db.Query(`SELECT ts,cpu_pct,ram_mb,ram_total,net_rx,net_tx,online FROM metric_samples WHERE ts>=? ORDER BY ts`, since)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []MetricSample
	for rows.Next() {
		var m MetricSample
		if err := rows.Scan(&m.Ts, &m.CPUPct, &m.RAMMB, &m.RAMTotal, &m.NetRx, &m.NetTx, &m.Online); err == nil {
			out = append(out, m)
		}
	}
	return out, nil
}

// PruneMetrics — удалить сэмплы старше days дней (retention).
func (s *Store) PruneMetrics(days int) {
	cutoff := time.Now().Unix() - int64(days)*86400
	s.db.Exec(`DELETE FROM metric_samples WHERE ts<?`, cutoff)
}