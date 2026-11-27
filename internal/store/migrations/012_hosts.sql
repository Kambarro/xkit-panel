-- 012_hosts.sql — точки входа/hosts (P1 #10, 3x-ui managed hosts / Remnawave hosts).
-- УРОК: домен вместо IP + несколько рекламных адресов (CDN-фронтинг). Смена IP ноды =
-- правка DNS, клиенты не замечают (усиливает переезд); реальный IP скрыт за CDN.
CREATE TABLE IF NOT EXISTS master_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,          -- рекламный адрес (домен/CDN-фронт)
    port INTEGER NOT NULL DEFAULT 443,
    sni TEXT NOT NULL DEFAULT '',   -- per-host SNI (пусто = address)
    label TEXT NOT NULL DEFAULT '', -- название («CDN фронт», «прямой»)
    priority INTEGER NOT NULL DEFAULT 0, -- меньше = выше (первым в подписке)
    enabled INTEGER NOT NULL DEFAULT 1
);
