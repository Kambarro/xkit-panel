package store

import (
	"fmt"
	"time"
)

// Device — устройство клиента (HWID, стандарт Happ x-hwid).
// УРОК (panels-research #1): HWID-лимит — основа тарифов «на N устройств»,
// без него подписку расшаривают бесконечно.
type Device struct {
	Email     string `json:"email"`
	HWID      string `json:"hwid"`
	Model     string `json:"model"`
	Platform  string `json:"platform"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

// ClientHWIDLimit — лимит устройств клиента (0 = без лимита).
func (s *Store) ClientHWIDLimit(email string) int {
	var lim int
	s.db.QueryRow(`SELECT hwid_limit FROM clients WHERE email=?`, email).Scan(&lim)
	return lim
}

// SetClientHWIDLimit — установить лимит устройств.
func (s *Store) SetClientHWIDLimit(email string, limit int) error {
	_, err := s.db.Exec(`UPDATE clients SET hwid_limit=?, updated_at=strftime('%s','now') WHERE email=?`, limit, email)
	return err
}

// Devices — устройства клиента.
func (s *Store) Devices(email string) ([]Device, error) {
	rows, err := s.db.Query(`SELECT email,hwid,model,platform,first_seen,last_seen FROM client_devices WHERE email=? ORDER BY last_seen DESC`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.Email, &d.HWID, &d.Model, &d.Platform, &d.FirstSeen, &d.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeviceCount — число устройств клиента.
func (s *Store) DeviceCount(email string) int {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM client_devices WHERE email=?`, email).Scan(&n)
	return n
}

// RegisterDevice — регистрирует/обновляет устройство. Возвращает (allowed, isNew).
// allowed=false если лимит достигнут и это НОВОЕ устройство (существующие всегда allowed).
func (s *Store) RegisterDevice(email, hwid, model, platform string) (bool, bool, error) {
	// SEC-08: валидация (защита от раздувания БД мусорными значениями)
	if len(hwid) > 128 || len(model) > 128 || len(platform) > 64 {
		return false, false, fmt.Errorf("device fields too long")
	}
	for _, c := range hwid {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false, false, fmt.Errorf("invalid hwid characters")
		}
	}
	if hwid == "" {
		return true, false, nil // нет HWID — не ограничиваем (старые клиенты)
	}
	now := time.Now().Unix()
	// существующее?
	var existing string
	err := s.db.QueryRow(`SELECT hwid FROM client_devices WHERE email=? AND hwid=?`, email, hwid).Scan(&existing)
	if err == nil {
		// обновим last_seen/model
		s.db.Exec(`UPDATE client_devices SET last_seen=?, model=?, platform=? WHERE email=? AND hwid=?`, now, model, platform, email, hwid)
		return true, false, nil
	}
	// новое устройство — проверим лимит
	limit := s.ClientHWIDLimit(email)
	if limit > 0 && s.DeviceCount(email) >= limit {
		return false, true, nil // лимит достигнут
	}
	_, err = s.db.Exec(`INSERT INTO client_devices(email,hwid,model,platform,first_seen,last_seen) VALUES(?,?,?,?,?,?)`,
		email, hwid, model, platform, now, now)
	if err != nil {
		return false, false, err
	}
	return true, true, nil
}

// RemoveDevice — отвязать устройство (админ/клиент).
func (s *Store) RemoveDevice(email, hwid string) error {
	_, err := s.db.Exec(`DELETE FROM client_devices WHERE email=? AND hwid=?`, email, hwid)
	return err
}

// NotificationSent — было ли уже отправлено уведомление (email,kind,ref).
func (s *Store) NotificationSent(email, kind, ref string) bool {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM client_notifications WHERE email=? AND kind=? AND ref=?`, email, kind, ref).Scan(&n)
	return n > 0
}

// MarkNotification — отметить уведомление отправленным (идемпотентно).
func (s *Store) MarkNotification(email, kind, ref string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO client_notifications(email,kind,ref) VALUES(?,?,?)`, email, kind, ref)
	return err
}