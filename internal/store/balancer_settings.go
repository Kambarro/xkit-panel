package store

import "strconv"

// BalancerSettings — настройки балансировщика (админ, вкладка Балансировщик).
type BalancerSettings struct {
	LoadThreshold     float64 `json:"load_threshold"`      // 0..1, загрузка выше → нода загружена
	FailsToDown       int     `json:"fails_to_down"`       // неудач подряд → down
	ProbeSec          int     `json:"probe_sec"`           // интервал health-проб
	ReevalSec         int     `json:"reeval_sec"`          // интервал переназначения
	EnforceSec        int     `json:"enforce_sec"`         // интервал expiry/quota
	ProbeTimeoutSec   int     `json:"probe_timeout_sec"`   // таймаут health-пробы ноды
	IPWindowSec       int     `json:"ip_window_sec"`       // окно свежести IP для ip-лимита
	NotifyCooldownMin int     `json:"notify_cooldown_min"` // антиспам уведомлений (мин)
	AlertPct          int     `json:"alert_pct"`           // порог % квоты/трафика для уведомления
	DefaultCapacity   int     `json:"default_capacity"`    // ёмкость ноды по умолчанию (клиентов=100%)
	SelectByQuality   bool    `json:"select_by_quality"`   // выбирать ноду по качеству (latency/uptime/load), не только priority
}

func (s *Store) BalancerSettings() BalancerSettings {
	bs := BalancerSettings{LoadThreshold: 0.80, FailsToDown: 3, ProbeSec: 15, ReevalSec: 30, EnforceSec: 60, ProbeTimeoutSec: 5, IPWindowSec: 90, NotifyCooldownMin: 5, AlertPct: 90, DefaultCapacity: 50}
	if v := s.GetSetting("bal_load_threshold", ""); v != "" { if f, e := strconv.ParseFloat(v, 64); e == nil && f > 0 && f <= 1 { bs.LoadThreshold = f } }
	if v := s.GetSetting("bal_fails_to_down", ""); v != "" { if n, e := strconv.Atoi(v); e == nil && n > 0 { bs.FailsToDown = n } }
	if v := s.GetSetting("bal_probe_sec", ""); v != "" { if n, e := strconv.Atoi(v); e == nil && n >= 5 { bs.ProbeSec = n } }
	if v := s.GetSetting("bal_reeval_sec", ""); v != "" { if n, e := strconv.Atoi(v); e == nil && n >= 5 { bs.ReevalSec = n } }
	if v := s.GetSetting("bal_enforce_sec", ""); v != "" { if n, e := strconv.Atoi(v); e == nil && n >= 10 { bs.EnforceSec = n } }
	if v := s.GetSetting("bal_probe_timeout_sec", ""); v != "" { if n, e := strconv.Atoi(v); e == nil && n >= 1 { bs.ProbeTimeoutSec = n } }
	if v := s.GetSetting("bal_ip_window_sec", ""); v != "" { if n, e := strconv.Atoi(v); e == nil && n >= 10 { bs.IPWindowSec = n } }
	if v := s.GetSetting("bal_notify_cooldown_min", ""); v != "" { if n, e := strconv.Atoi(v); e == nil && n >= 1 { bs.NotifyCooldownMin = n } }
	if v := s.GetSetting("bal_alert_pct", ""); v != "" { if n, e := strconv.Atoi(v); e == nil && n > 0 && n <= 100 { bs.AlertPct = n } }
	if v := s.GetSetting("bal_default_capacity", ""); v != "" { if n, e := strconv.Atoi(v); e == nil && n >= 1 { bs.DefaultCapacity = n } }
	bs.SelectByQuality = s.GetSetting("bal_select_by_quality", "0") == "1"
	return bs
}

func (s *Store) SetBalancerSettings(bs BalancerSettings) {
	s.SetSetting("bal_load_threshold", strconv.FormatFloat(bs.LoadThreshold, 'f', 2, 64))
	s.SetSetting("bal_fails_to_down", strconv.Itoa(bs.FailsToDown))
	s.SetSetting("bal_probe_sec", strconv.Itoa(bs.ProbeSec))
	s.SetSetting("bal_reeval_sec", strconv.Itoa(bs.ReevalSec))
	s.SetSetting("bal_enforce_sec", strconv.Itoa(bs.EnforceSec))
	s.SetSetting("bal_probe_timeout_sec", strconv.Itoa(bs.ProbeTimeoutSec))
	s.SetSetting("bal_ip_window_sec", strconv.Itoa(bs.IPWindowSec))
	s.SetSetting("bal_notify_cooldown_min", strconv.Itoa(bs.NotifyCooldownMin))
	s.SetSetting("bal_alert_pct", strconv.Itoa(bs.AlertPct))
	s.SetSetting("bal_default_capacity", strconv.Itoa(bs.DefaultCapacity))
	q := "0"; if bs.SelectByQuality { q = "1" }; s.SetSetting("bal_select_by_quality", q)
}