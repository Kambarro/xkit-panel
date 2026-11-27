-- 011_squads.sql — группы доступа/тарифы (P1 #8, Remnawave internal squads / Kitsune).
-- УРОК (panels-research): группа = набор inbounds (протоколов), фундамент тарифов
-- «семья/друзья/премиум». Ложится на динамические подписки из enabled inbounds.
CREATE TABLE IF NOT EXISTS squads (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    inbounds TEXT NOT NULL DEFAULT '[]',   -- JSON массив tag'ов протоколов группы
    country TEXT NOT NULL DEFAULT '',      -- страна выхода по умолчанию ('' = любая)
    hwid_limit INTEGER NOT NULL DEFAULT 0, -- лимит устройств для группы
    quota_gb INTEGER NOT NULL DEFAULT 0,   -- квота ГБ (0=безлимит)
    expiry_days INTEGER NOT NULL DEFAULT 0,-- срок дней (0=бессрочно)
    autorenew_mode TEXT NOT NULL DEFAULT 'none',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
ALTER TABLE clients ADD COLUMN squad_id TEXT NOT NULL DEFAULT '';
