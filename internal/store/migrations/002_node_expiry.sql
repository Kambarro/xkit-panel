-- XKIT Panel — миграция 002: дата аренды ноды (опционально).
-- УРОК XKIT: нода арендована до даты → по истечении отключается (не удаляется),
-- клиенты failover'ятся на другие ноды страны. expiry=0 = бессрочно (свой сервер).
ALTER TABLE nodes ADD COLUMN expiry INTEGER NOT NULL DEFAULT 0; -- unix ts, 0 = бессрочно
CREATE INDEX IF NOT EXISTS idx_nodes_expiry ON nodes(expiry);