package store

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Единая точка смены страны клиента (решение владельца: страна = ТОЛЬКО
// clients.country, один UUID, базовое per-user правило). Пишут все пути:
// публичный API подписки, TG-бот, админка. Валидация + rate-limit + аудит здесь.

var (
	// ErrCountryRateLimit — слишком частая смена (публичный API/бот).
	ErrCountryRateLimit = errors.New("страну можно менять не чаще раза в 10 секунд")
	// ErrCountryUnavailable — страны нет среди живых (включённых) нод мастера.
	ErrCountryUnavailable = errors.New("страна недоступна на этом мастере")
)

// ChangeClientCountry — нормализация (''/any → any), валидация (канон
// country_codes + включённая нода страны), rate-limit (minIntervalSec>0 →
// не чаще раза в интервал на клиента), запись clients.country/country_code,
// аудит AddEvent. minIntervalSec=0 — админский путь без лимита.
// Горячее переназначение (PushAssignment) — обязанность вызывающего.
func (s *Store) ChangeClientCountry(email, country string, minIntervalSec int, via string) (uint32, error) {
	country = strings.TrimSpace(country)
	if country == "" || strings.EqualFold(country, "any") {
		country = "any"
	}
	var code uint32
	if country != "any" {
		// канон country_codes (QA BUG-1/7) + страна обязана иметь включённую ноду
		code, _ = s.LookupCountryCode(country)
		var nc int
		s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE country=? AND enabled=1`, country).Scan(&nc)
		if code == 0 || nc == 0 {
			return 0, ErrCountryUnavailable
		}
	}
	now := time.Now().Unix()
	if minIntervalSec > 0 {
		var last int64
		s.db.QueryRow(`SELECT country_changed_at FROM clients WHERE email=?`, email).Scan(&last)
		if last > 0 && now-last < int64(minIntervalSec) {
			return 0, ErrCountryRateLimit
		}
	}
	if _, err := s.db.Exec(`UPDATE clients SET country=?, country_code=?, country_changed_at=?, updated_at=? WHERE email=?`,
		country, code, now, now, email); err != nil {
		return 0, err
	}
	s.AddEvent("country_change", "ok", fmt.Sprintf("клиент %s сменил страну выхода → %s (%s)", email, country, via),
		fmt.Sprintf(`{"email":%q,"country":%q,"via":%q}`, email, country, via))
	return code, nil
}