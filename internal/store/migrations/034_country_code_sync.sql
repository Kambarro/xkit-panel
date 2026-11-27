-- 034_country_code_sync.sql — BUG-1a/BUG-7 (QA 2026-11-26): nodes.country_code
-- рассинхронизирован с канонической таблицей country_codes (US-нода имела код 1=NL
-- → cs:NL и cs:US строились с одинаковым vlessRoute, страна не менялась никогда).
-- Канон — country_codes (код выдаётся один раз и живёт вечно). Чиним данные:
UPDATE nodes SET country_code=(SELECT code FROM country_codes cc WHERE cc.country=nodes.country)
 WHERE country IN (SELECT country FROM country_codes)
   AND country_code IS NOT (SELECT code FROM country_codes cc WHERE cc.country=nodes.country);
UPDATE clients SET country_code=(SELECT code FROM country_codes cc WHERE cc.country=clients.country)
 WHERE country IN (SELECT country FROM country_codes)
   AND country_code IS NOT (SELECT code FROM country_codes cc WHERE cc.country=clients.country);
-- клиенты с country='any'/'' — код 0 (без vlessRoute)
UPDATE clients SET country_code=0 WHERE country IN ('', 'any');