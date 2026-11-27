package store

import (
	"testing"
	"time"
)

// hourBucketSum — сумма всех hour-бакетов сущности (для сверки с lifetime).
func hourBucketSum(t *testing.T, s *Store, kind, id string) (up, down int64) {
	t.Helper()
	err := s.db.QueryRow(`SELECT COALESCE(SUM(up),0),COALESCE(SUM(down),0) FROM traffic_hourly WHERE kind=? AND id=?`, kind, id).Scan(&up, &down)
	if err != nil { t.Fatal(err) }
	return
}

// TestTrafficHourlyMirrorsLifetime — каждый accumulate/delta пишется и в lifetime,
// и в текущий hour-бакет: суммы совпадают, повторный опрос не задваивает ни там, ни там.
func TestTrafficHourlyMirrorsLifetime(t *testing.T) {
	s := trafficTestStore(t)
	must := func(err error) { t.Helper(); if err != nil { t.Fatal(err) } }
	must(s.AccumulateClientTraffic("a@t", 100, 200))
	must(s.AccumulateClientTraffic("a@t", 150, 260)) // +50/+60
	must(s.AccumulateClientTraffic("a@t", 150, 260)) // повтор — ноль
	must(s.AddTrafficDelta("node", "n1", 7, 8))
	must(s.AddTrafficDelta("node", "n1", 1, 2))
	cu, cd := hourBucketSum(t, s, "client", "a@t")
	if cu != 150 || cd != 260 { t.Fatalf("бакеты клиента: up=%d down=%d, want 150/260", cu, cd) }
	nu, nd := hourBucketSum(t, s, "node", "n1")
	if nu != 8 || nd != 10 { t.Fatalf("бакеты ноды: up=%d down=%d, want 8/10", nu, nd) }
	// один бакет на текущий час (UPSERT, не размножение строк)
	var cnt int
	must(s.db.QueryRow(`SELECT COUNT(*) FROM traffic_hourly`).Scan(&cnt))
	if cnt != 2 { t.Fatalf("строк бакетов: %d, want 2 (client+node, текущий час)", cnt) }
}

// TestTrafficHourlyRestartDelta — рестарт-сброс (cur<last) в бакетах обрабатывается
// как в lifetime: весь cur — новая дельта, история бакетов не теряется.
func TestTrafficHourlyRestartDelta(t *testing.T) {
	s := trafficTestStore(t)
	must := func(err error) { t.Helper(); if err != nil { t.Fatal(err) } }
	must(s.AccumulateClientTraffic("a@t", 1000, 5000))
	must(s.AccumulateClientTraffic("a@t", 30, 40)) // ядро перезапущено
	must(s.AccumulateClientTraffic("a@t", 50, 90)) // +20/+50
	cu, cd := hourBucketSum(t, s, "client", "a@t")
	if cu != 1050 || cd != 5090 { t.Fatalf("бакеты после рестарта: %d/%d, want 1050/5090", cu, cd) }
	lt := s.GetTrafficTotal("client", "a@t")
	if lt.UpBytes != cu || lt.DownBytes != cd { t.Fatalf("lifetime разошёлся с бакетами: %+v", lt) }
}

// TestTrafficPeriodsAggregation — скользящие окна 24ч/7д/30д агрегируются из
// бакетов по hour >= now-окно; старый бакет вне всех окон не попадает никуда.
func TestTrafficPeriodsAggregation(t *testing.T) {
	s := trafficTestStore(t)
	must := func(err error) { t.Helper(); if err != nil { t.Fatal(err) } }
	now := time.Now().Unix()
	h := now / 3600 * 3600
	ins := func(hour, up, down int64) {
		t.Helper()
		must(s.AddTrafficDelta("client", "a@t", 0, 0)) // no-op, таблица существует после миграции
		_, err := s.db.Exec(`INSERT INTO traffic_hourly(kind,id,hour,up,down) VALUES('client','a@t',?,?,?)
			ON CONFLICT(kind,id,hour) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, hour, up, down)
		must(err)
	}
	ins(h, 10, 20)             // текущий час — во всех окнах
	ins(h-23*3600, 1, 2)       // ~23ч назад — во всех окнах
	ins(h-2*24*3600, 100, 200) // 2 дня — week+month, не today
	ins(h-8*24*3600, 1000, 2000) // 8 дней — только month
	ins(h-40*24*3600, 9, 9)    // 40 дней — вне всех окон (retention-кандидат)
	p := s.allTrafficPeriods("client", now)["a@t"]
	if p.TodayUp != 11 || p.TodayDown != 22 || p.Today != 33 { t.Fatalf("today: %+v", p) }
	if p.WeekUp != 111 || p.WeekDown != 222 || p.Week != 333 { t.Fatalf("week: %+v", p) }
	if p.MonthUp != 1111 || p.MonthDown != 2222 || p.Month != 3333 { t.Fatalf("month: %+v", p) }
	// пустая сущность → zero, не паника
	if z := s.AllTrafficPeriods("node")["missing"]; z.Today != 0 || z.Month != 0 { t.Fatalf("zero: %+v", z) }
}

// TestTrafficHourlyRetention — Prune удаляет бакеты старше cutoff, свежие и
// lifetime не трогает; удаление сущности чистит и бакеты.
func TestTrafficHourlyRetention(t *testing.T) {
	s := trafficTestStore(t)
	must := func(err error) { t.Helper(); if err != nil { t.Fatal(err) } }
	now := time.Now().Unix()
	h := now / 3600 * 3600
	must(s.AccumulateClientTraffic("a@t", 100, 200)) // свежий бакет + lifetime
	_, err := s.db.Exec(`INSERT INTO traffic_hourly(kind,id,hour,up,down) VALUES('client','a@t',?,5,5)`, h-91*24*3600)
	must(err)
	_, err = s.db.Exec(`INSERT INTO traffic_hourly(kind,id,hour,up,down) VALUES('client','a@t',?,7,7)`, h-89*24*3600)
	must(err)
	must(s.PruneTrafficHourly(now - 90*24*3600))
	cu, cd := hourBucketSum(t, s, "client", "a@t")
	if cu != 107 || cd != 207 { t.Fatalf("после prune: %d/%d, want 107/207 (91д удалён, 89д остался)", cu, cd) }
	if lt := s.GetTrafficTotal("client", "a@t"); lt == nil || lt.Total() != 300 {
		t.Fatalf("lifetime пострадал от prune: %+v", lt)
	}
	// удаление клиента убирает и бакеты
	s.DeleteTrafficTotal("client", "a@t")
	cu, cd = hourBucketSum(t, s, "client", "a@t")
	if cu != 0 || cd != 0 { t.Fatalf("бакеты удалённого клиента: %d/%d", cu, cd) }
}
