-- 029: security field sync from stream (fix presets created with security=none but stream=reality/tls)
UPDATE inbounds SET security=json_extract(stream,'$.security') WHERE security IN ('none','') AND json_extract(stream,'$.security') IN ('reality','tls');
