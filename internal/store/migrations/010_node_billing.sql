-- 010_node_billing.sql — трафик-бюджет ноды под биллинг хостера (P1 #5, Remnawave nodes.md).
-- УРОК (panels-research): NL-ноды с лимитом 20TB — спасает от счетов-сюрпризов.
-- multiplier ×0.5/×2: «дорогая» нода ест квоту клиента быстрее.
ALTER TABLE nodes ADD COLUMN traffic_limit_gb INTEGER NOT NULL DEFAULT 0; -- 0 = без лимита
ALTER TABLE nodes ADD COLUMN traffic_used_bytes INTEGER NOT NULL DEFAULT 0; -- накоплено за период
ALTER TABLE nodes ADD COLUMN billing_reset_day INTEGER NOT NULL DEFAULT 1; -- день месяца сброса (1-28)
ALTER TABLE nodes ADD COLUMN billing_period_start INTEGER NOT NULL DEFAULT 0; -- unix ts начала периода
ALTER TABLE nodes ADD COLUMN consumption_multiplier REAL NOT NULL DEFAULT 1.0; -- ×0.5/×2 квоты клиента
ALTER TABLE nodes ADD COLUMN billing_alert_sent INTEGER NOT NULL DEFAULT 0; -- алерт 90% отправлен