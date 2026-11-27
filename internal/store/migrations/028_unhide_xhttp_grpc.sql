-- 028_unhide_xhttp_grpc.sql — xhttp/grpc через VLESS-fallback не работают (проверено живьём).
-- Возвращаем на свои порты (честный бейдж "нельзя спрятать за 443"). ws/vmess за 443.
UPDATE inbounds SET hidden=0, public_port=0, listen='0.0.0.0' WHERE network IN ('xhttp','grpc') AND hidden=1;
