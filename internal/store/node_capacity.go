package store

// NodeCapacity — ёмкость ноды (клиентов = 100% загрузки). 0 → дефолт из настроек.
func (s *Store) SetNodeCapacity(id string, capacity int) error {
	if capacity < 0 { capacity = 0 }
	_, err := s.db.Exec(`UPDATE nodes SET capacity=? WHERE id=?`, capacity, id)
	return err
}

func (s *Store) NodeCapacity(id string) int {
	var n int
	s.db.QueryRow(`SELECT capacity FROM nodes WHERE id=?`, id).Scan(&n)
	return n
}