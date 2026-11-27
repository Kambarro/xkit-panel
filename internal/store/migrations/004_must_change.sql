-- XKIT Panel — миграция 004: блокирующий first-run (одноразовый пароль + случайный логин).
-- must_change=1 → пароль одноразовый, вход только на страницу смены (блокирующий шаг).
-- Сброс через SSH (xkit-panel reset-password) → новый одноразовый + must_change=1.
ALTER TABLE admins ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0;