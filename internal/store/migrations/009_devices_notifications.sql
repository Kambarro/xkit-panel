-- 009_devices_notifications.sql — устройства (HWID) + лог уведомлений.
-- Отдельная миграция (CREATE TABLE IF NOT EXISTS) — применяется независимо от ALTER-файла.
CREATE TABLE IF NOT EXISTS client_devices (
    email      TEXT NOT NULL REFERENCES clients(email) ON DELETE CASCADE,
    hwid       TEXT NOT NULL,
    model      TEXT NOT NULL DEFAULT '',
    platform   TEXT NOT NULL DEFAULT '',
    first_seen INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    last_seen  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (email, hwid)
);
CREATE INDEX IF NOT EXISTS idx_devices_email ON client_devices(email);

CREATE TABLE IF NOT EXISTS client_notifications (
    email      TEXT NOT NULL REFERENCES clients(email) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    ref        TEXT NOT NULL DEFAULT '',
    sent_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (email, kind, ref)
);