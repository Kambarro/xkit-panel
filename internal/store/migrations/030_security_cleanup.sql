-- 030: security cleanup per REALITY compatibility research
-- SS2022 has its own AEAD encryption, not 'none'
UPDATE inbounds SET security='ss2022' WHERE protocol='shadowsocks' AND security='none';
-- WS cannot use REALITY (Xray code rejects it) — fix any ws with reality back to tls
UPDATE inbounds SET security='tls', stream=json_set(stream,'$.security','tls') WHERE network='ws' AND security='reality';
