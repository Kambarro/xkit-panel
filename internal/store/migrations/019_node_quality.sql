-- История качества нод + текущие метрики качества для выбора по качеству.
CREATE TABLE IF NOT EXISTS node_samples (
    ts         INTEGER NOT NULL,
    node_id    TEXT NOT NULL,
    ok         INTEGER NOT NULL DEFAULT 0,   -- проба успешна (1/0)
    latency_ms REAL NOT NULL DEFAULT 0,      -- время TCP+TLS handshake (мс)
    load_pct   REAL NOT NULL DEFAULT 0,      -- загрузка ноды %
    clients    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_node_samples ON node_samples(node_id, ts);
-- текущие метрики качества ноды (обновляются каждой пробой)
ALTER TABLE nodes ADD COLUMN latency_ms REAL NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN uptime_pct REAL NOT NULL DEFAULT 100;
ALTER TABLE nodes ADD COLUMN quality_score REAL NOT NULL DEFAULT 0;