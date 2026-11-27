package store

import "strconv"

// MTU-регулировка туннелей. УРОК владельца: «для каскада что для подключения
// клиентов нужна регулировка mtu иногда это очень решает». 0 = наследовать дефолт.
// Отдельные хелперы (как node_capacity) — НЕ трогаем существующие Scan-запросы
// (урок: рассинхрон SELECT/Scan ломает per-user rules).

// MTU bounds: AWG inner должен влезть с padding/trailers во внешний UDP ≤1500.
const (
	MTUMin     = 1000
	MTUMax     = 1420
	MTUDefault = 1280
)

// DefaultMTU — глобальный дефолт (settings mtu_default).
func (s *Store) DefaultMTU() int {
	if v := s.GetSetting("mtu_default", ""); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n >= MTUMin && n <= MTUMax {
			return n
		}
	}
	return MTUDefault
}

func (s *Store) SetDefaultMTU(n int) {
	if n < MTUMin { n = MTUMin }
	if n > MTUMax { n = MTUMax }
	s.SetSetting("mtu_default", strconv.Itoa(n))
}

// NodeMTU — effective MTU каскада ноды (свой или глобальный дефолт).
func (s *Store) NodeMTU(id string) int {
	var n int
	s.db.QueryRow(`SELECT mtu FROM nodes WHERE id=?`, id).Scan(&n)
	if n >= MTUMin && n <= MTUMax { return n }
	return s.DefaultMTU()
}

func (s *Store) SetNodeMTU(id string, n int) {
	if n != 0 && (n < MTUMin || n > MTUMax) { return }
	s.db.Exec(`UPDATE nodes SET mtu=? WHERE id=?`, n, id)
}

// ClientMTU — effective MTU клиента (свой или глобальный дефолт).
func (s *Store) ClientMTU(email string) int {
	var n int
	s.db.QueryRow(`SELECT mtu FROM clients WHERE email=?`, email).Scan(&n)
	if n >= MTUMin && n <= MTUMax { return n }
	return s.DefaultMTU()
}

func (s *Store) SetClientMTU(email string, n int) {
	if n != 0 && (n < MTUMin || n > MTUMax) { return }
	s.db.Exec(`UPDATE clients SET mtu=? WHERE email=?`, n, email)
}

// LastGoodCfg — последний рабочий конфиг ноды (откат при провале туннеля).
func (s *Store) NodeLastGoodCfg(id string) string {
	var c string
	s.db.QueryRow(`SELECT last_good_cfg FROM nodes WHERE id=?`, id).Scan(&c)
	return c
}

func (s *Store) SetNodeLastGoodCfg(id, cfg string) {
	s.db.Exec(`UPDATE nodes SET last_good_cfg=? WHERE id=?`, cfg, id)
}