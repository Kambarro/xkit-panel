package store

import (
	"database/sql"
	"time"
)

// TrafficTotal — суммарный потреблённый трафик за всё время (lifetime).
// Отдельно от clients.used_bytes (квота, сбрасывается при продлении) и
// nodes.traffic_used_bytes (биллинг-период): Xray-счётчики обнуляются при
// рестарте ядра и при QueryStats(reset=true) — lifetime живёт здесь.
type TrafficTotal struct {
	UpBytes   int64 `json:"up_bytes"`
	DownBytes int64 `json:"down_bytes"`
	LastUp    int64 `json:"-"`
	LastDown  int64 `json:"-"`
}

func (t TrafficTotal) Total() int64 { return t.UpBytes + t.DownBytes }

// hourNow — начало текущего часа UTC (unix, кратно 3600): ключ traffic_hourly.
// Границы периодов — UTC (документировано в API/UI), не локальное время сервера.
func hourNow() int64 { return time.Now().Unix() / 3600 * 3600 }

// addHourlyTx — прибавить дельту в hour-бакет (внутри транзакции lifetime+бакет:
// один источник дельты на оба учёта → задвоения нет).
func addHourlyTx(tx *sql.Tx, kind, id string, hour, up, down int64) error {
	if up <= 0 && down <= 0 { return nil }
	if up < 0 { up = 0 }
	if down < 0 { down = 0 }
	_, err := tx.Exec(`INSERT INTO traffic_hourly(kind,id,hour,up,down) VALUES(?,?,?,?,?)
		ON CONFLICT(kind,id,hour) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`,
		kind, id, hour, up, down)
	return err
}

// AccumulateClientTraffic — дельта-агрегация кумулятивных счётчиков клиента.
// cur >= last → дельта cur-last; cur < last → счётчик сброшен (рестарт xray /
// внешний reset) → весь cur считается новой дельтой. Одна транзакция пишет
// дельту и в lifetime, и в текущий hour-бакет (периоды день/неделя/месяц);
// повторный вызов с теми же значениями ничего не добавляет (не-задвоение).
// shortcut: сброс+рост выше last между двумя опросами не отличим от обычного
// роста — теряется только хвост до сброса, апгрейд — если появится event-стрим.
func (s *Store) AccumulateClientTraffic(email string, curUp, curDown int64) error {
	if curUp < 0 { curUp = 0 }
	if curDown < 0 { curDown = 0 }
	tx, err := s.db.Begin()
	if err != nil { return err }
	defer tx.Rollback()
	var lastUp, lastDown int64
	err = tx.QueryRow(`SELECT last_up,last_down FROM traffic_totals WHERE kind='client' AND id=?`, email).
		Scan(&lastUp, &lastDown)
	if err != nil && err != sql.ErrNoRows { return err }
	dUp, dDown := curUp-lastUp, curDown-lastDown
	if curUp < lastUp { dUp = curUp }   // рестарт-сброс: весь cur — новая дельта
	if curDown < lastDown { dDown = curDown }
	if _, err := tx.Exec(`INSERT INTO traffic_totals(kind,id,up_bytes,down_bytes,last_up,last_down)
		VALUES('client',?,?,?,?,?)
		ON CONFLICT(kind,id) DO UPDATE SET
		up_bytes=up_bytes+excluded.up_bytes, down_bytes=down_bytes+excluded.down_bytes,
		last_up=excluded.last_up, last_down=excluded.last_down,
		updated_at=strftime('%s','now')`,
		email, dUp, dDown, curUp, curDown); err != nil { return err }
	if err := addHourlyTx(tx, "client", email, hourNow(), dUp, dDown); err != nil { return err }
	return tx.Commit()
}

// AddTrafficDelta — прибавить готовую дельту (ноды: биллинг читает outbound
// stats с reset=true, значение уже дельта за окно — повторно не дифференцируем).
// Та же дельта идёт в lifetime и в текущий hour-бакет одной транзакцией.
func (s *Store) AddTrafficDelta(kind, id string, upDelta, downDelta int64) error {
	if upDelta <= 0 && downDelta <= 0 { return nil }
	if upDelta < 0 { upDelta = 0 }
	if downDelta < 0 { downDelta = 0 }
	tx, err := s.db.Begin()
	if err != nil { return err }
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO traffic_totals(kind,id,up_bytes,down_bytes)
		VALUES(?,?,?,?)
		ON CONFLICT(kind,id) DO UPDATE SET up_bytes=up_bytes+excluded.up_bytes,
		down_bytes=down_bytes+excluded.down_bytes, updated_at=strftime('%s','now')`,
		kind, id, upDelta, downDelta); err != nil { return err }
	if err := addHourlyTx(tx, kind, id, hourNow(), upDelta, downDelta); err != nil { return err }
	return tx.Commit()
}

// GetTrafficTotal — lifetime-трафик сущности; nil если учёт ещё не начался.
func (s *Store) GetTrafficTotal(kind, id string) *TrafficTotal {
	var t TrafficTotal
	err := s.db.QueryRow(`SELECT up_bytes,down_bytes,last_up,last_down FROM traffic_totals WHERE kind=? AND id=?`, kind, id).
		Scan(&t.UpBytes, &t.DownBytes, &t.LastUp, &t.LastDown)
	if err != nil { return nil }
	return &t
}

// AllTrafficTotals — lifetime-трафик всех сущностей вида (для списков в API).
func (s *Store) AllTrafficTotals(kind string) map[string]TrafficTotal {
	out := map[string]TrafficTotal{}
	rows, err := s.db.Query(`SELECT id,up_bytes,down_bytes FROM traffic_totals WHERE kind=?`, kind)
	if err != nil { return out }
	defer rows.Close()
	for rows.Next() {
		var id string
		var t TrafficTotal
		if rows.Scan(&id, &t.UpBytes, &t.DownBytes) == nil { out[id] = t }
	}
	return out
}

// DeleteTrafficTotal — убрать lifetime-строку и почасовые бакеты при удалении клиента/ноды.
func (s *Store) DeleteTrafficTotal(kind, id string) {
	s.db.Exec(`DELETE FROM traffic_totals WHERE kind=? AND id=?`, kind, id)
	s.db.Exec(`DELETE FROM traffic_hourly WHERE kind=? AND id=?`, kind, id)
}

// TrafficPeriods — трафик за скользящие окна из hour-бакетов (UTC).
// JSON: today/week/month = последние 24ч/7д/30д, up+down и раздельно.
type TrafficPeriods struct {
	TodayUp    int64 `json:"traffic_today_up_bytes"`
	TodayDown  int64 `json:"traffic_today_down_bytes"`
	Today      int64 `json:"traffic_today_bytes"`
	WeekUp     int64 `json:"traffic_week_up_bytes"`
	WeekDown   int64 `json:"traffic_week_down_bytes"`
	Week       int64 `json:"traffic_week_bytes"`
	MonthUp    int64 `json:"traffic_month_up_bytes"`
	MonthDown  int64 `json:"traffic_month_down_bytes"`
	Month      int64 `json:"traffic_month_bytes"`
}

// trafficPeriodCutoffs — границы окон: ровно now-24ч/-7д/-30д (скользящие).
// Бакет входит целиком, если его hour >= cutoff (точность до часа — документировано).
func trafficPeriodCutoffs(now int64) (day, week, month int64) {
	return now - 24*3600, now - 7*24*3600, now - 30*24*3600
}

// AllTrafficPeriods — периоды всех сущностей вида одним запросом (для API).
func (s *Store) AllTrafficPeriods(kind string) map[string]TrafficPeriods {
	return s.allTrafficPeriods(kind, time.Now().Unix())
}

func (s *Store) allTrafficPeriods(kind string, now int64) map[string]TrafficPeriods {
	out := map[string]TrafficPeriods{}
	day, week, month := trafficPeriodCutoffs(now)
	rows, err := s.db.Query(`SELECT id,
		SUM(CASE WHEN hour>=? THEN up ELSE 0 END), SUM(CASE WHEN hour>=? THEN down ELSE 0 END),
		SUM(CASE WHEN hour>=? THEN up ELSE 0 END), SUM(CASE WHEN hour>=? THEN down ELSE 0 END),
		SUM(up), SUM(down)
		FROM traffic_hourly WHERE kind=? AND hour>=? GROUP BY id`,
		day, day, week, week, kind, month)
	if err != nil { return out }
	defer rows.Close()
	for rows.Next() {
		var id string
		var p TrafficPeriods
		if rows.Scan(&id, &p.TodayUp, &p.TodayDown, &p.WeekUp, &p.WeekDown, &p.MonthUp, &p.MonthDown) == nil {
			p.Today, p.Week, p.Month = p.TodayUp+p.TodayDown, p.WeekUp+p.WeekDown, p.MonthUp+p.MonthDown
			out[id] = p
		}
	}
	return out
}

// PruneTrafficHourly — retention: удалить бакеты старше cutoff (unix).
// Вызывается в enforce-цикле сбора с cutoff = now-90д. Lifetime не трогает.
func (s *Store) PruneTrafficHourly(cutoff int64) error {
	_, err := s.db.Exec(`DELETE FROM traffic_hourly WHERE hour < ?`, cutoff)
	return err
}
