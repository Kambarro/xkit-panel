-- 036_traffic_hourly.sql — почасовые бакеты трафика (клиенты и ноды) для периодов.
-- Дельта collectTraffic (та же, что идёт в traffic_totals/lifetime) пишется и сюда.
-- Периоды агрегируются из бакетов: скользящие 24ч/7д/30д, границы — UTC-часы.
-- hour = unix-секунды начала часа (UTC, кратно 3600). Retention ~90 дней (чистка в enforce).
CREATE TABLE IF NOT EXISTS traffic_hourly (
    kind TEXT NOT NULL,              -- 'client' | 'node'
    id   TEXT NOT NULL,              -- email клиента | id ноды
    hour INTEGER NOT NULL,           -- начало часа UTC (unix, кратно 3600)
    up   INTEGER NOT NULL DEFAULT 0,
    down INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (kind, id, hour)
);
CREATE INDEX IF NOT EXISTS idx_traffic_hourly_hour ON traffic_hourly(hour);
