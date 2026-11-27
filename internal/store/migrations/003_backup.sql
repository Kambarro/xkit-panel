-- XKIT Panel — миграция 003: настройки бэкапов (как в XKIT, настраиваемые).
-- Бэкап = SQLite (источник правды) + TLS + REALITY ключи + tunnel.env → tar.gz.
-- Отправка в Telegram-бот (файл), retention: интервал/дни/минимум копий.
INSERT OR IGNORE INTO settings(key,value) VALUES
 ('backup_enabled','1'),
 ('backup_interval_h','24'),
 ('backup_keep_days','14'),
 ('backup_keep_min','3'),
 ('backup_tg_send','1'),
 ('backup_last','0');