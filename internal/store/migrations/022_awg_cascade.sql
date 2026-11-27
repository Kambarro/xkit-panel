-- Персист AWG-каскада мастер→нода (переживает рестарт панели).
-- УРОК: мастер-клиент in-memory → после restart xkit-panel каскад running=False.
-- Нода-сервер персистентен (агент restoreAWGTunnel), мастер-клиент — нет. Чиним.
CREATE TABLE IF NOT EXISTS awg_cascades (
    node_id     TEXT PRIMARY KEY,
    port        INTEGER NOT NULL DEFAULT 51821,
    master_priv TEXT NOT NULL,
    master_pub  TEXT NOT NULL,
    node_pub    TEXT NOT NULL,
    params      TEXT NOT NULL DEFAULT '{}',
    master_ip   TEXT NOT NULL DEFAULT '10.9.0.2',
    subnet      TEXT NOT NULL DEFAULT '10.9.0.0/24',
    enabled     INTEGER NOT NULL DEFAULT 1
);