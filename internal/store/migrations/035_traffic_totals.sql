-- 035_traffic_totals.sql — суммарный потреблённый трафик за всё время (клиенты и ноды).
-- Xray-счётчики сбрасываются при рестарте ядра и при QueryStats(reset=true) (биллинг нод),
-- поэтому lifetime-учёт живёт отдельно: дельта-агрегация при каждом сборе метрик.
-- last_up/last_down — последний сырой счётчик клиента (для дельты и детекта сброса);
-- для нод не используются (биллинг читает outbound с reset=true → дельта напрямую).
CREATE TABLE IF NOT EXISTS traffic_totals (
    kind       TEXT NOT NULL,              -- 'client' | 'node'
    id         TEXT NOT NULL,              -- email клиента | id ноды
    up_bytes   INTEGER NOT NULL DEFAULT 0, -- накоплено за всё время
    down_bytes INTEGER NOT NULL DEFAULT 0,
    last_up    INTEGER NOT NULL DEFAULT 0,
    last_down  INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (kind, id)
);
