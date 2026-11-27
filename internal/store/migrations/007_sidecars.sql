-- 007_sidecars.sql — сайдкар-протоколы (нативные демоны, панель=оркестратор).
-- УРОК (владелец): не запихивать всё в Xray — для каждого протокола лучшая реализация
-- отдельным процессом (hysteria→apernet, tuic→tuic-server, naive→sing-box и т.д.).
-- Панель управляет lifecycle через systemd, SQLite=источник правды.
CREATE TABLE IF NOT EXISTS sidecars (
    id TEXT PRIMARY KEY,              -- hysteria-main, tuic-main, ...
    kind TEXT NOT NULL,               -- hysteria2/tuic/naive/ss2022/mtproto/mieru
    enabled INTEGER NOT NULL DEFAULT 0,
    binary TEXT NOT NULL DEFAULT '',  -- путь к бинарю (/usr/local/bin/hysteria)
    version TEXT NOT NULL DEFAULT '',
    config_path TEXT NOT NULL DEFAULT '', -- /etc/xkit-sidecars/<id>.yaml
    unit TEXT NOT NULL DEFAULT '',    -- systemd unit name (xkit-<id>)
    port INTEGER NOT NULL DEFAULT 0,
    config TEXT NOT NULL DEFAULT '{}',   -- полный конфиг JSON (источник правды)
    status TEXT NOT NULL DEFAULT 'stopped', -- running/stopped/error
    last_error TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);