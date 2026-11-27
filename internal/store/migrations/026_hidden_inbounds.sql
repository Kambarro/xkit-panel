-- 026_hidden_inbounds.sql — маскировка по умолчанию: TCP-протоколы за 443.
-- hidden=1: inbound слушает 127.0.0.1 (внутренний порт = косметика), клиентский порт
-- всегда 443 через REALITY→TLS-dispatcher fallback-цепочку. Порт менять нельзя.
-- public_port: порт в клиентской ссылке (443 для hidden).
-- УРОК (владелец): максимум маскировки, минимум открытых портов, по умолчанию,
-- без редактирования; что нельзя спрятать (trojan/ss/UDP) — честно предупреждаем.
ALTER TABLE inbounds ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0;
ALTER TABLE inbounds ADD COLUMN public_port INTEGER NOT NULL DEFAULT 0;