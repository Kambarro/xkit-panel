-- 037_client_country_ts.sql — время последней смены страны клиентом (rate-limit).
-- Страна выхода = clients.country (единственный флаг, cs/vlessRoute-слой удалён).
-- Смена через публичный API подписки и TG-бот ограничена: 1 смена / 10 сек.
ALTER TABLE clients ADD COLUMN country_changed_at INTEGER NOT NULL DEFAULT 0;