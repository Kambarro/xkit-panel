-- MTU-регулировка туннелей (каскад мастер→нода + клиент→мастер).
-- УРОК владельца: «для каскада что для подключения клиентов нужна регулировка mtu
-- иногда это очень решает» — РФ-мобилки/PPPoE/ТСПУ режут фрагменты, AWG padding
-- добавляется сверху inner MTU. 0 = наследовать глобальный дефолт (settings mtu_default).
ALTER TABLE nodes ADD COLUMN mtu INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN mtu INTEGER NOT NULL DEFAULT 0;
-- последний рабочий конфиг ноды (откат при провале применения туннеля)
ALTER TABLE nodes ADD COLUMN last_good_cfg TEXT NOT NULL DEFAULT '';