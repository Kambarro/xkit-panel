package store

import (
	"testing"
	"time"
)

func TestNextRenewTime(t *testing.T) {
	// daily: +1 день
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC).Unix()
	if got := NextRenewTime("daily", 0, base); got != time.Date(2026, 1, 16, 10, 0, 0, 0, time.UTC).Unix() {
		t.Errorf("daily: %d", got)
	}
	// weekly: +7 дней
	if got := NextRenewTime("weekly", 0, base); got != time.Date(2026, 1, 22, 10, 0, 0, 0, time.UTC).Unix() {
		t.Errorf("weekly: %d", got)
	}
	// days: +N
	if got := NextRenewTime("days", 10, base); got != time.Date(2026, 1, 25, 10, 0, 0, 0, time.UTC).Unix() {
		t.Errorf("days: %d", got)
	}
	// none: 0
	if got := NextRenewTime("none", 0, base); got != 0 {
		t.Errorf("none should be 0: %d", got)
	}
}

func TestMonthlyClamp(t *testing.T) {
	// УРОК 3x-ui: 31 jan + 1 month должно clamp к 28 feb (не 3 mar!)
	jan31 := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC).Unix()
	got := NextRenewTime("monthly", 0, jan31)
	want := time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC).Unix() // 2026 не високосный
	if got != want {
		t.Errorf("monthly clamp jan31→feb28: got %s want %s", time.Unix(got, 0).Format("2006-01-02"), time.Unix(want, 0).Format("2006-01-02"))
	}
	// 31 mar + 1 month → 30 apr (clamp)
	mar31 := time.Date(2026, 3, 31, 12, 0, 0, 0, time.UTC).Unix()
	got = NextRenewTime("monthly", 0, mar31)
	want = time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC).Unix()
	if got != want {
		t.Errorf("monthly clamp mar31→apr30: got %s want %s", time.Unix(got, 0).Format("2006-01-02"), time.Unix(want, 0).Format("2006-01-02"))
	}
	// 15 jan + 1 month → 15 feb (без clamp)
	jan15 := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC).Unix()
	got = NextRenewTime("monthly", 0, jan15)
	want = time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC).Unix()
	if got != want {
		t.Errorf("monthly jan15→feb15: got %s", time.Unix(got, 0).Format("2006-01-02"))
	}
	// високосный год: 31 jan 2028 → 29 feb 2028
	jan31leap := time.Date(2028, 1, 31, 12, 0, 0, 0, time.UTC).Unix()
	got = NextRenewTime("monthly", 0, jan31leap)
	want = time.Date(2028, 2, 29, 12, 0, 0, 0, time.UTC).Unix()
	if got != want {
		t.Errorf("leap year jan31→feb29: got %s", time.Unix(got, 0).Format("2006-01-02"))
	}
}