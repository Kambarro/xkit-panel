package store

import (
	"encoding/json"

	"github.com/kambarro/xkit-panel/internal/routing"
)

// Режим маршрутизации мастера (решение владельца 2026-11-26):
// '' = авто (solo без нод / ru-direct с нодами — текущее поведение, не ломаем),
// solo = всё direct с мастера, ru-direct = РФ direct остальное через ноды,
// antifilter = заблокированное через ноды, остальное direct.
// Хранится в settings routing_mode; antifilter недоступен в соло (нет нод).

func (s *Store) RoutingMode() string {
	return s.GetSetting("routing_mode", "")
}

// EffectiveRoutingMode — фактический режим с учётом наличия нод.
// antifilter без нод бессмысленен (туннеля нет) — деградируем в solo.
func (s *Store) EffectiveRoutingMode(hasNodes bool) string {
	switch m := s.RoutingMode(); m {
	case "solo":
		return "solo"
	case "ru-direct":
		return "ru-direct"
	case "antifilter":
		if !hasNodes {
			return "solo"
		}
		return "antifilter"
	default: // авто — текущее поведение панели
		if hasNodes {
			return "ru-direct"
		}
		return "solo"
	}
}

func (s *Store) SetRoutingMode(mode string) error {
	switch mode {
	case "", "solo", "ru-direct", "antifilter":
		return s.SetSetting("routing_mode", mode)
	}
	return errInvalidRoutingMode
}

var errInvalidRoutingMode = &invalidModeError{}

type invalidModeError struct{}

func (*invalidModeError) Error() string {
	return "неизвестный режим маршрутизации (solo|ru-direct|antifilter|пусто=авто)"
}

// AntifilterMargin — expert-флаг «с /24-запасом»: добавлять allyouneed.lst
// (суммаризация, 86.5% адресов — спекулятивные соседи). По умолчанию ВЫКЛ:
// точный состав ipresolve ∪ subnet ∪ community (решение владельца).
func (s *Store) AntifilterMargin() bool {
	return s.GetSetting("antifilter_margin", "") == "1"
}

func (s *Store) SetAntifilterMargin(on bool) error {
	v := ""
	if on {
		v = "1"
	}
	return s.SetSetting("antifilter_margin", v)
}

// AlwaysRules — правила владельца «Всегда через ноду»/«Всегда напрямую» поверх
// любого режима. Хранятся нормализованными (routing.ValidateAlwaysRules на входе API).
func (s *Store) AlwaysRules() routing.AlwaysRules {
	var ar routing.AlwaysRules
	raw := s.GetSetting("always_rules", "")
	if raw != "" {
		json.Unmarshal([]byte(raw), &ar)
	}
	return ar
}

func (s *Store) SetAlwaysRules(ar routing.AlwaysRules) error {
	raw, _ := json.Marshal(ar)
	return s.SetSetting("always_rules", string(raw))
}

// AntifilterState — статус фонового обновления blocked-списка (для UI).
// Source: live (antifilter lst) | cache (кеш lst) | fallback (runetfreedom dat) | "" (нет данных).
type AntifilterState struct {
	Source      string            `json:"source"`
	PrefixCount int               `json:"prefix_count"`
	LastFetch   int64             `json:"last_fetch"`   // unix: последняя успешная загрузка antifilter lst
	UpdatedAt   int64             `json:"updated_at"`   // unix: последняя успешная генерация/замена dat
	Stale       bool              `json:"stale"`        // кеш старше 48ч
	Error       string            `json:"error"`        // последняя ошибка (для UI)
	ETags       map[string]string `json:"etags"`        // ETag по каждому источнику
	Sources     []string          `json:"sources"`      // какие lst вошли в набор
	GeositeAt   int64             `json:"geosite_at"`   // unix: обновление geosite-ru-only.dat
	FallbackAt  int64             `json:"fallback_at"`  // unix: переход на fallback
	Domains     int               `json:"domains"`      // доменов в geosite RU-BLOCKED (информативно)
	DatFile     string            `json:"dat_file"`     // активный A/B-файл xkit-blocked (hot-reload без кеша ядра)
}

func (s *Store) AntifilterState() AntifilterState {
	var st AntifilterState
	raw := s.GetSetting("antifilter_state", "")
	if raw != "" {
		json.Unmarshal([]byte(raw), &st)
	}
	return st
}

func (s *Store) SetAntifilterState(st AntifilterState) error {
	raw, _ := json.Marshal(st)
	return s.SetSetting("antifilter_state", string(raw))
}