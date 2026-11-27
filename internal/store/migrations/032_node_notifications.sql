-- 025_node_notifications.sql — лог уведомлений по нодам (аренда/отключение).
-- Отдельно от client_notifications: там FK на clients(email), а ключ ноды "node:<id>"
-- не клиент → INSERT падал бы по FK. Своя таблица без FK.
CREATE TABLE IF NOT EXISTS node_notifications (
    node_key TEXT NOT NULL,
    kind     TEXT NOT NULL,
    ref      TEXT NOT NULL DEFAULT '',
    sent_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (node_key, kind, ref)
);