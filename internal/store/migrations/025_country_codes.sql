-- 025_country_codes.sql — стабильные коды стран (vlessRoute).
-- УРОК (QA): код страны выводился из нод → смена страны ноды туда-обратно давала НОВЫЙ код,
-- старые UUID клиентов (с прежним кодом) переставали маршрутизироваться.
-- Код страны выдаётся ОДИН раз и живёт вечно в этой таблице.
CREATE TABLE IF NOT EXISTS country_codes (
 country TEXT PRIMARY KEY,
 code INTEGER NOT NULL UNIQUE
);
-- миграция существующих кодов из нод
INSERT OR IGNORE INTO country_codes(country,code) SELECT country,country_code FROM nodes WHERE country_code>0;