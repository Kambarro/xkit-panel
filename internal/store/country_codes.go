package store

// Канонические коды стран (vlessRoute). ЕДИНЫЙ источник — таблица country_codes
// (миграция 025): код выдаётся ОДИН раз и живёт вечно. УРОК (QA BUG-1/7):
// читатели брали код из nodes.country_code — рассинхрон US-ноды (code=1=NL)
// давал cs:NL и cs:US одинаковый vlessRoute → смена страны не работала никогда.

// LookupCountryCode — код известной страны (0 если страны нет в каноне).
// Ничего не создаёт — для валидации входа и чтения.
func (s *Store) LookupCountryCode(country string) (uint32, error) {
	var code uint32
	err := s.db.QueryRow(`SELECT code FROM country_codes WHERE country=?`, country).Scan(&code)
	if err != nil {
		return 0, nil // нет в каноне — не ошибка, вызывающий решает (400/выдать)
	}
	return code, nil
}

// CountryCode — код страны из канона; для новой страны выдаёт MAX+1 и запоминает.
// Для записи ноды/смены страны ноды (provision/node_settings).
func (s *Store) CountryCode(country string) (uint32, error) {
	if code, _ := s.LookupCountryCode(country); code > 0 {
		return code, nil
	}
	var maxCode uint32
	s.db.QueryRow(`SELECT COALESCE(MAX(code),0) FROM country_codes`).Scan(&maxCode)
	code := maxCode + 1
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO country_codes(country,code) VALUES(?,?)`, country, code); err != nil {
		return 0, err
	}
	// гонка параллельной выдачи: INSERT OR IGNORE мог не вставить — читаем факт
	return s.LookupCountryCode(country)
}