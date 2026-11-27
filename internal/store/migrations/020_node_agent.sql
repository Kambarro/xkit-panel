-- Агент ноды: токен + флаг установки (метрики изнутри ноды через SSH).
ALTER TABLE nodes ADD COLUMN agent_token TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN agent_installed INTEGER NOT NULL DEFAULT 0;