package store

import "time"

// AutoRenew — параметры автопродления клиента (P0 #2, panels-research).
// УРОК (3x-ui clients.mdx / Marzban): домохозяйка не продлевает вручную.
// Режимы: none/daily/weekly/monthly/days. Month-end clamp (31→28/30), DST-safe.
type AutoRenew struct {
	Mode         string `json:"mode"`          // none/daily/weekly/monthly/days
	Days         int    `json:"days"`          // для mode=days
	ResetTraffic bool   `json:"reset_traffic"` // сбрасывать used_bytes при продлении
	LastRenewAt  int64  `json:"last_renew_at"`
}

// GetAutoRenew — параметры автопродления клиента.
func (s *Store) GetAutoRenew(email string) AutoRenew {
	var a AutoRenew
	var reset int
	s.db.QueryRow(`SELECT autorenew_mode,autorenew_days,autorenew_reset_traffic,last_renew_at FROM clients WHERE email=?`, email).
		Scan(&a.Mode, &a.Days, &reset, &a.LastRenewAt)
	a.ResetTraffic = reset == 1
	if a.Mode == "" { a.Mode = "none" }
	if a.Days == 0 { a.Days = 30 }
	return a
}

// SetAutoRenew — установить параметры автопродления.
func (s *Store) SetAutoRenew(email, mode string, days int, resetTraffic bool) error {
	reset := 0
	if resetTraffic { reset = 1 }
	if days <= 0 { days = 30 }
	_, err := s.db.Exec(`UPDATE clients SET autorenew_mode=?, autorenew_days=?, autorenew_reset_traffic=?, updated_at=strftime('%s','now') WHERE email=?`,
		mode, days, reset, email)
	return err
}

// NextRenewTime — вычисляет следующее продление от last_renew_at (или expiry базы).
// УРОК 3x-ui (краевые случаи): monthly с clamp (31 jan → 28 feb), weekly=+7d, daily=+24h.
// Возвращает unix ts следующего продления; 0 если mode=none.
func NextRenewTime(mode string, days int, from int64) int64 {
	if mode == "none" || mode == "" { return 0 }
	t := time.Unix(from, 0)
	switch mode {
	case "daily":
		return t.AddDate(0, 0, 1).Unix()
	case "weekly":
		return t.AddDate(0, 0, 7).Unix()
	case "monthly":
		// clamp: AddDate нормализует (31 jan + 1 month = 3 mar), нужно clamp к концу месяца
		y, m, d := t.Date()
		// первый день следующего месяца
		firstNext := time.Date(y, m+1, 1, t.Hour(), t.Minute(), t.Second(), 0, t.Location())
		// последний день следующего месяца
		lastDay := firstNext.AddDate(0, 1, -1).Day()
		if d > lastDay { d = lastDay }
		return time.Date(y, m+1, d, t.Hour(), t.Minute(), t.Second(), 0, t.Location()).Unix()
	case "days":
		if days <= 0 { days = 30 }
		return t.AddDate(0, 0, days).Unix()
	}
	return 0
}

// ClientsDueForRenewal — клиенты у которых наступило автопродление.
// Логика: продлеваем КОГДА expiry прошёл (или близок), от last_renew_at/expiry базы.
// Для monthly/weekly/daily: если now >= nextRenew от последнего продления → продлить.
// Возвращает (email, currentExpiry, autorenew).
type RenewalDue struct {
	Email   string
	Expiry  int64
	Renew   AutoRenew
}

func (s *Store) ClientsDueForRenewal(now int64) ([]RenewalDue, error) {
	rows, err := s.db.Query(`SELECT email,expiry,autorenew_mode,autorenew_days,autorenew_reset_traffic,last_renew_at
		FROM clients WHERE enabled=1 AND autorenew_mode!='none' AND autorenew_mode!=''`)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []RenewalDue
	for rows.Next() {
		var d RenewalDue
		var reset int
		if err := rows.Scan(&d.Email, &d.Expiry, &d.Renew.Mode, &d.Renew.Days, &reset, &d.Renew.LastRenewAt); err != nil {
			return nil, err
		}
		d.Renew.ResetTraffic = reset == 1
		// база отсчёта: последнее продление, иначе expiry, иначе now
		base := d.Renew.LastRenewAt
		if base == 0 { base = d.Expiry }
		if base == 0 { base = now }
		next := NextRenewTime(d.Renew.Mode, d.Renew.Days, base)
		if next > 0 && now >= next {
			out = append(out, d)
		}
	}
	return out, rows.Err()
}

// ApplyRenewal — продлевает клиента: expiry = next от базы, last_renew_at=now,
// опционально сброс трафика. Возвращает новый expiry.
// УРОК (live-проверка): catch-up — если база далеко в прошлом (панель лежала/клиент
// был отключён), продлеваем ЦИКЛОМ пока expiry не станет > now (3x-ui catch-up).
// Иначе один шаг от старой базы даёт всё ещё истёкший expiry → клиент отключается.
func (s *Store) ApplyRenewal(email string, now int64) (int64, error) {
	a := s.GetAutoRenew(email)
	var expiry int64
	s.db.QueryRow(`SELECT expiry FROM clients WHERE email=?`, email).Scan(&expiry)
	base := a.LastRenewAt
	if base == 0 { base = expiry }
	if base == 0 { base = now }
	// catch-up: продлеваем пока не перешагнём now (защита от бесконечного цикла — 1000 итераций)
	newExpiry := base
	for i := 0; i < 1000; i++ {
		next := NextRenewTime(a.Mode, a.Days, newExpiry)
		if next == 0 || next <= newExpiry { break }
		newExpiry = next
		if newExpiry > now { break }
	}
	if newExpiry <= base { return expiry, nil }
	if a.ResetTraffic {
		_, err := s.db.Exec(`UPDATE clients SET expiry=?, last_renew_at=?, used_bytes=0, updated_at=strftime('%s','now') WHERE email=?`, newExpiry, now, email)
		return newExpiry, err
	}
	_, err := s.db.Exec(`UPDATE clients SET expiry=?, last_renew_at=?, updated_at=strftime('%s','now') WHERE email=?`, newExpiry, now, email)
	return newExpiry, err
}