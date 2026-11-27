package store

import (
	"path/filepath"
	"testing"
)

func trafficTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { s.Close() })
	return s
}

// TestAccumulateClientTrafficDeltas — рост кумулятивных счётчиков даёт дельты,
// повторный опрос с теми же значениями НЕ задваивает (главный инвариант).
func TestAccumulateClientTrafficDeltas(t *testing.T) {
	s := trafficTestStore(t)
	must := func(err error) { t.Helper(); if err != nil { t.Fatal(err) } }
	must(s.AccumulateClientTraffic("a@t", 100, 200))
	must(s.AccumulateClientTraffic("a@t", 150, 260)) // +50/+60
	must(s.AccumulateClientTraffic("a@t", 150, 260)) // повтор — ноль
	got := s.GetTrafficTotal("client", "a@t")
	if got == nil || got.UpBytes != 150 || got.DownBytes != 260 || got.Total() != 410 {
		t.Fatalf("дельты: %+v, want up=150 down=260", got)
	}
	if got.LastUp != 150 || got.LastDown != 260 { t.Fatalf("last: %+v", got) }
}

// TestAccumulateClientTrafficResetSurvives — счётчик упал (рестарт xray /
// QueryStats reset=true другим потребителем): новый кумулятив целиком считается
// дельтой и ДОБАВЛЯЕТСЯ к накопленному, а не заменяет его.
func TestAccumulateClientTrafficResetSurvives(t *testing.T) {
	s := trafficTestStore(t)
	must := func(err error) { t.Helper(); if err != nil { t.Fatal(err) } }
	must(s.AccumulateClientTraffic("a@t", 1000, 5000)) // до рестарта
	must(s.AccumulateClientTraffic("a@t", 30, 40))     // ядро перезапущено, счётчики с нуля
	must(s.AccumulateClientTraffic("a@t", 50, 90))     // +20/+50 после рестарта
	got := s.GetTrafficTotal("client", "a@t")
	if got == nil || got.UpBytes != 1050 || got.DownBytes != 5090 {
		t.Fatalf("после рестарта: %+v, want up=1050 down=5090 (не потеряли историю)", got)
	}
}

// TestTrafficTotalsIsolation — квота/биллинг сбрасываются, lifetime — нет;
// client и node с одинаковым id не смешиваются.
func TestTrafficTotalsIsolation(t *testing.T) {
	s := trafficTestStore(t)
	must := func(err error) { t.Helper(); if err != nil { t.Fatal(err) } }
	must(s.AccumulateClientTraffic("x", 10, 20))
	must(s.AddTrafficDelta("node", "x", 7, 8))
	must(s.AddTrafficDelta("node", "x", 1, 2))
	if got := s.GetTrafficTotal("client", "x"); got == nil || got.Total() != 30 {
		t.Fatalf("client: %+v", got)
	}
	if got := s.GetTrafficTotal("node", "x"); got == nil || got.UpBytes != 8 || got.DownBytes != 10 {
		t.Fatalf("node: %+v", got)
	}
	// сброс квоты клиента не трогает lifetime
	if err := s.UpsertClient(Client{Email: "x", UUID: "u", SubID: "s", Enabled: true}); err != nil { t.Fatal(err) }
	must(s.SetUsedBytes("x", 0))
	if got := s.GetTrafficTotal("client", "x"); got == nil || got.Total() != 30 {
		t.Fatalf("lifetime после сброса used_bytes: %+v", got)
	}
	// отрицательная/нулевая дельта — no-op
	must(s.AddTrafficDelta("node", "x", -5, 0))
	if got := s.GetTrafficTotal("node", "x"); got.Total() != 18 { t.Fatalf("no-op: %+v", got) }
	// удаление
	s.DeleteTrafficTotal("client", "x")
	if s.GetTrafficTotal("client", "x") != nil { t.Fatal("строка не удалена") }
	if s.GetTrafficTotal("node", "x") == nil { t.Fatal("удаление client задело node") }
}
