package store

import (
 "crypto/rand"
 "encoding/hex"
)

// SubPrefix — случайный префикс пути подписки (УРОК владельца: все пути рандом,
// никаких предсказуемых /sub/). Генерится один раз, хранится в settings.
// Подписка: https://domain/<sub_prefix>/<subId>. Префикс не угадать/не перебрать.
func (s *Store) SubPrefix() string {
 p := s.GetSetting("sub_prefix", "")
 if p == "" {
  b := make([]byte, 6)
  rand.Read(b)
  p = "s" + hex.EncodeToString(b) // s + 12 hex = 13 chars
  s.SetSetting("sub_prefix", p)
 }
 return p
}
