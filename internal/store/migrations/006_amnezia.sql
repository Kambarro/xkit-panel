-- 006_amnezia.sql — AmneziaWG сервер и пиры (источник правды = SQLite).
-- Сервер один на мастер (id=1). Пиры привязаны к клиентам панели по email.
CREATE TABLE IF NOT EXISTS awg_server (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    port INTEGER NOT NULL DEFAULT 443,
    iface TEXT NOT NULL DEFAULT 'awg0',
    subnet TEXT NOT NULL DEFAULT '10.8.1.0/24',
    private_key TEXT NOT NULL DEFAULT '',
    public_key TEXT NOT NULL DEFAULT '',
    params TEXT NOT NULL DEFAULT '{}',   -- AWGParams JSON (Jc/Jmin/Jmax/S1..S4/H1..H4/MTU...)
    dns TEXT NOT NULL DEFAULT '1.1.1.1',
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
INSERT OR IGNORE INTO awg_server(id) VALUES(1);

CREATE TABLE IF NOT EXISTS awg_peers (
    email TEXT PRIMARY KEY,             -- клиент панели
    name TEXT NOT NULL DEFAULT '',
    private_key TEXT NOT NULL,          -- клиентский priv (для conf/vpn://)
    public_key TEXT NOT NULL,
    preshared_key TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL,              -- 10.8.1.x/32
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);