-- 027_default_ports.sql — маскировка по умолчанию: минимум открытых портов.
-- AWG → 443/udp (вместо 51820), Hysteria2 preset → 8443/udp (вместо 8446).
-- Существующие установки: меняем дефолтные порты ТОЛЬКО если они ещё дефолтные
-- (пользовательский выбор не трогаем). TCP-протоколы прячутся за 443 кодом (026).
UPDATE awg_server SET port=443 WHERE id=1 AND port=51820;
UPDATE inbounds SET port=8443 WHERE protocol='hysteria2' AND port=8446 AND hidden=0;