-- 008_hwid_autorenew.sql — новые колонки клиентов (HWID/автопродление/TG-привязка).
-- P0 заимствование (panels-research): HWID (Remnawave, стандарт Happ x-hwid) — основа
-- тарифов «на N устройств»; автопродление (3x-ui/Marzban) — домохозяйка не продлевает вручную.
-- ТОЛЬКО ALTER (duplicate column guard в store.go пропустит если уже применено).
ALTER TABLE clients ADD COLUMN hwid_limit INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN autorenew_mode TEXT NOT NULL DEFAULT 'none';
ALTER TABLE clients ADD COLUMN autorenew_days INTEGER NOT NULL DEFAULT 30;
ALTER TABLE clients ADD COLUMN autorenew_reset_traffic INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN last_renew_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN tg_chat_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN tg_claim_token TEXT NOT NULL DEFAULT '';