-- 014_ip_limit.sql — IP-лимит per-client (P1 #11, 3x-ui ipLimit gRPC GetStatsOnlineIpList).
-- УРОК: HWID не спасает от шаринга с одним UA — IP-лимит считает уникальные source IP.
ALTER TABLE clients ADD COLUMN ip_limit INTEGER NOT NULL DEFAULT 0;
