-- 023_client_protocols.sql — per-client набор протоколов (вариант B: группы + override).
-- УРОК владельца: «как в 3xui выбрать доступные протоколы каждому клиенту; новый клиент — все;
-- группы семья/роутеры/прочие; новый протокол — auto_add + спросить».
-- clients.protocols: '' = наследовать группу/все; JSON массив tag'ов = свой набор (override).
ALTER TABLE clients ADD COLUMN protocols TEXT NOT NULL DEFAULT '';
-- inbounds.auto_add: 1 = новый протокол добавляется всем по умолчанию (в дефолтный набор).
ALTER TABLE inbounds ADD COLUMN auto_add INTEGER NOT NULL DEFAULT 1;
-- squads.auto_add: 1 = новые auto_add-протоколы автоматически добавляются в набор группы.
ALTER TABLE squads ADD COLUMN auto_add INTEGER NOT NULL DEFAULT 1;