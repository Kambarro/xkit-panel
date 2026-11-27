-- XKIT Panel — схема SQLite (control plane балансировщика).
-- Клиенты, ноды (страна/приоритет/цена), sticky-карта assignment, настройки.
-- modernc.org/sqlite (pure Go, CGO off). WAL для конкурентного чтения.

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Ноды: зарубежные exit-ноды каскада. Страна = группа для country-select.
CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,            -- node-de-1 (= outboundTag в Xray)
    name        TEXT NOT NULL,               -- Frankfurt-1
    country     TEXT NOT NULL,               -- DE/NL/US (ISO)
    country_code INTEGER NOT NULL DEFAULT 0, -- vlessRoute 0..65535 (страна в подписке)
    priority    INTEGER NOT NULL DEFAULT 100,-- меньше = выше приоритет
    price       REAL NOT NULL DEFAULT 1.0,   -- вес цены (для assignment)
    host        TEXT NOT NULL,               -- de1.example.net
    port        INTEGER NOT NULL DEFAULT 443,
    tunnel      TEXT NOT NULL DEFAULT 'reality', -- reality/xhttp/ws/hy2
    tunnel_cfg  TEXT NOT NULL DEFAULT '{}',  -- JSON параметры туннеля (uuid/pbk/sid/sni...)
    health      TEXT NOT NULL DEFAULT 'unknown', -- alive/degraded/down/unknown
    health_fails INTEGER NOT NULL DEFAULT 0, -- счётчик неудач подряд (failsToDown=3)
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_nodes_country ON nodes(country, priority);

-- Клиенты: уникальн email = идентичность в Xray routing (user:[email]).
CREATE TABLE IF NOT EXISTS clients (
    email       TEXT PRIMARY KEY,            -- ivan@mail.ru (Xray user email)
    uuid        TEXT NOT NULL,               -- базовый UUID (байты 6-7 = vlessRoute страны)
    sub_id      TEXT NOT NULL,               -- subscription id
    name        TEXT NOT NULL DEFAULT '',
    country     TEXT NOT NULL DEFAULT '',    -- выбранная страна выхода (DE/NL/US)
    country_code INTEGER NOT NULL DEFAULT 0, -- vlessRoute код страны
    expiry      INTEGER NOT NULL DEFAULT 0,  -- unix timestamp, 0 = бессрочно
    quota_bytes INTEGER NOT NULL DEFAULT 0,  -- 0 = безлимит
    used_bytes  INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_clients_country ON clients(country);
CREATE INDEX IF NOT EXISTS idx_clients_expiry ON clients(expiry);

-- Sticky-карта: assignment (email,country) → нода. Детерминированный пин клиента.
-- rule_tag = ключ per-user routing rule в Xray (c:<email>:<country>).
CREATE TABLE IF NOT EXISTS assignments (
    email       TEXT NOT NULL REFERENCES clients(email) ON DELETE CASCADE,
    country     TEXT NOT NULL,               -- страна выхода (может отличаться от clients.country при failover)
    node_id     TEXT NOT NULL REFERENCES nodes(id),
    rule_tag    TEXT NOT NULL,               -- c:ivan@mail.ru:de
    status      TEXT NOT NULL DEFAULT 'sticky', -- sticky/failover
    failover_from TEXT NOT NULL DEFAULT '',  -- исходная страна если failover
    assigned_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (email, country)
);
CREATE INDEX IF NOT EXISTS idx_assign_node ON assignments(node_id);

-- События: failover/отвал ноды/expiry/бэкап — лента для UI/аудита.
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    kind        TEXT NOT NULL,               -- node_down/node_up/failover/expiry/backup/assign
    severity    TEXT NOT NULL DEFAULT 'info',-- info/warn/error/ok
    message     TEXT NOT NULL,
    meta        TEXT NOT NULL DEFAULT '{}'   -- JSON детали (node/email/country)
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);

-- Настройки панели (key-value).
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

-- Админы панели (веб-логин, argon2 hash).
CREATE TABLE IF NOT EXISTS admins (
    username    TEXT PRIMARY KEY,
    pass_hash   TEXT NOT NULL,               -- argon2id
    locale      TEXT NOT NULL DEFAULT 'ru',
    theme       TEXT NOT NULL DEFAULT 'dark',
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);