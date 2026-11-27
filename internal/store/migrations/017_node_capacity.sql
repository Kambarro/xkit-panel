-- Ёмкость ноды (клиентов = 100% загрузки). Было захардкожено 50 в контроллере.
ALTER TABLE nodes ADD COLUMN capacity INTEGER NOT NULL DEFAULT 50;