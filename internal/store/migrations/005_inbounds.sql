-- XKIT Panel — миграция 005: inbounds (протоколы) в SQLite = источник правды.
-- УРОК (владелец): не ограничены 3X-UI — любые протоколы/транспорты Xray 26.x.
-- config мастера генерируется из базы; gRPC AlterInbound горячо.
CREATE TABLE IF NOT EXISTS inbounds (
    tag         TEXT PRIMARY KEY,            -- vless-reality (= tag в Xray)
    protocol    TEXT NOT NULL,               -- vless/vmess/trojan/shadowsocks/hysteria2/...
    port        INTEGER NOT NULL,
    listen      TEXT NOT NULL DEFAULT '0.0.0.0',
    network     TEXT NOT NULL DEFAULT 'tcp', -- tcp/ws/grpc/httpupgrade/xhttp/splithttp
    security    TEXT NOT NULL DEFAULT 'reality', -- reality/tls/none
    settings    TEXT NOT NULL DEFAULT '{}',  -- JSON: clients/decryption/...
    stream      TEXT NOT NULL DEFAULT '{}',  -- JSON: realitySettings/tlsSettings/wsSettings/...
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);