-- 016_client_routing.sql — per-client роутинг (дефолт владельца + кастом поверх).
-- УРОК (владелец): клиентский роутинг НЕ обходит серверные правила — он лишь direct/proxy/block.
-- Серверный слой владельца неприкосновенен. Клиент дополняет наш дефолт, не удаляет его.
-- allow_custom_routing — тумблер владельца (по умолчанию 1=разрешено, можно запретить конкретному).
ALTER TABLE clients ADD COLUMN routing_mode TEXT NOT NULL DEFAULT 'default';
ALTER TABLE clients ADD COLUMN custom_rules TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN allow_custom_routing INTEGER NOT NULL DEFAULT 1;
