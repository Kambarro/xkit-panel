package store

import "time"

// NodeBilling — трафик-бюджет ноды под биллинг хостера (P1 #5, Remnawave).
// УРОК (panels-research): лимит GB + день сброса + алерт 90% + consumption-multiplier.
type NodeBilling struct {
	LimitGB      int     `json:"limit_gb"`      // 0 = без лимита
	UsedBytes    int64   `json:"used_bytes"`    // накоплено за период
	ResetDay     int     `json:"reset_day"`     // день месяца сброса (1-28)
	PeriodStart  int64   `json:"period_start"`  // unix ts начала периода
	Multiplier   float64 `json:"multiplier"`    // ×0.5/×2 квоты клиента
	AlertSent    bool    `json:"alert_sent"`
}

// GetNodeBilling — бюджет ноды.
func (s *Store) GetNodeBilling(id string) NodeBilling {
	var b NodeBilling
	var alert int
	s.db.QueryRow(`SELECT traffic_limit_gb,traffic_used_bytes,billing_reset_day,billing_period_start,consumption_multiplier,billing_alert_sent FROM nodes WHERE id=?`, id).
		Scan(&b.LimitGB, &b.UsedBytes, &b.ResetDay, &b.PeriodStart, &b.Multiplier, &alert)
	b.AlertSent = alert == 1
	if b.ResetDay == 0 { b.ResetDay = 1 }
	if b.Multiplier == 0 { b.Multiplier = 1.0 }
	return b
}

// SetNodeBilling — установить лимит/день сброса/multiplier.
func (s *Store) SetNodeBilling(id string, limitGB, resetDay int, multiplier float64) error {
	if resetDay < 1 || resetDay > 28 { resetDay = 1 }
	if multiplier <= 0 { multiplier = 1.0 }
	_, err := s.db.Exec(`UPDATE nodes SET traffic_limit_gb=?, billing_reset_day=?, consumption_multiplier=?, updated_at=strftime('%s','now') WHERE id=?`,
		limitGB, resetDay, multiplier, id)
	return err
}

// AddNodeTraffic — добавить трафик ноде (дельта из outbound stats).
func (s *Store) AddNodeTraffic(id string, delta int64) error {
	if delta <= 0 { return nil }
	_, err := s.db.Exec(`UPDATE nodes SET traffic_used_bytes=traffic_used_bytes+? WHERE id=?`, delta, id)
	return err
}

// ResetNodeBillingPeriod — сбросить накопленный трафик (новый биллинг-период).
func (s *Store) ResetNodeBillingPeriod(id string, now int64) error {
	_, err := s.db.Exec(`UPDATE nodes SET traffic_used_bytes=0, billing_period_start=?, billing_alert_sent=0 WHERE id=?`, now, id)
	return err
}

// MarkNodeAlert — отметить алерт 90% отправленным.
func (s *Store) MarkNodeAlert(id string) error {
	_, err := s.db.Exec(`UPDATE nodes SET billing_alert_sent=1 WHERE id=?`, id)
	return err
}

// NodesDueForBillingReset — ноды у которых наступил день сброса биллинг-периода.
// Логика: если now перешёл через reset_day текущего месяца относительно period_start.
func (s *Store) NodesDueForBillingReset(now int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT id,billing_reset_day,billing_period_start FROM nodes WHERE traffic_limit_gb>0`)
	if err != nil { return nil, err }
	defer rows.Close()
	t := time.Unix(now, 0)
	var out []string
	for rows.Next() {
		var id string
		var resetDay int
		var periodStart int64
		if err := rows.Scan(&id, &resetDay, &periodStart); err != nil { continue }
		if resetDay < 1 || resetDay > 28 { resetDay = 1 }
		// граница периода: reset_day текущего месяца (или следующего если уже прошёл)
		y, m, _ := t.Date()
		boundary := time.Date(y, m, resetDay, 0, 0, 0, 0, t.Location())
		if t.Before(boundary) {
			// текущий день < reset_day → граница была в прошлом месяце
			boundary = boundary.AddDate(0, -1, 0)
		}
		// если period_start раньше границы → пора сбросить
		if periodStart < boundary.Unix() {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// NodeBillingPct — процент использования лимита (0 если без лимита).
func (b NodeBilling) Pct() float64 {
	if b.LimitGB <= 0 { return 0 }
	limitBytes := int64(b.LimitGB) * 1024 * 1024 * 1024
	return float64(b.UsedBytes) / float64(limitBytes) * 100
}