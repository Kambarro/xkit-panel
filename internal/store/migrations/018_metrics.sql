-- История метрик мастера для дашборда (трафик/нагрузка за произвольный период).
-- Сэмпл раз в ~30с (контроллер). Хранение 30 дней, старые чистятся.
CREATE TABLE IF NOT EXISTS metric_samples (
    ts        INTEGER NOT NULL,          -- unix timestamp
    cpu_pct   REAL NOT NULL DEFAULT 0,   -- загрузка CPU %
    ram_mb    INTEGER NOT NULL DEFAULT 0,-- RAM использовано МБ (система)
    ram_total INTEGER NOT NULL DEFAULT 0,-- RAM всего МБ
    net_rx    INTEGER NOT NULL DEFAULT 0,-- кумулятивные rx байт (счётчик интерфейсов)
    net_tx    INTEGER NOT NULL DEFAULT 0,-- кумулятивные tx байт
    online    INTEGER NOT NULL DEFAULT 0 -- клиентов онлайн
);
CREATE INDEX IF NOT EXISTS idx_metric_ts ON metric_samples(ts);