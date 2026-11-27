package store

// NodeNotificationSent / MarkNodeNotification — идемпотентность уведомлений по нодам.
// Отдельная таблица node_notifications (без FK на clients — ключ "node:<id>" не клиент).

func (s *Store) NodeNotificationSent(key, kind, ref string) bool {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM node_notifications WHERE node_key=? AND kind=? AND ref=?`, key, kind, ref).Scan(&n)
	return n > 0
}

func (s *Store) MarkNodeNotification(key, kind, ref string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO node_notifications(node_key,kind,ref) VALUES(?,?,?)`, key, kind, ref)
	return err
}