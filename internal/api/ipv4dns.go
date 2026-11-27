package api

// IPv4-only резолв (аудит #8 мастер / #10 ноды). УРОК (фикс-паттерн v9.1.6):
// на серверах нет глобального IPv6, а системный DNS отдаёт AAAA первым →
// freedom пытается IPv6 → таймауты, geo-правила не срабатывают. Фикс:
// dns.queryStrategy=UseIPv4 + публичные резолверы + freedom.domainStrategy=UseIPv4.

import (
	"encoding/json"
	"os"
)

// ipv4OnlyDNS — dns-секция xray: только A-записи, резолверы 1.1.1.1/8.8.8.8.
func ipv4OnlyDNS() map[string]any {
	return map[string]any{
		"servers":       []any{"1.1.1.1", "8.8.8.8"},
		"queryStrategy": "UseIPv4",
	}
}

// freedomIPv4 — freedom-outbound с IPv4-only резолвом доменов.
func freedomIPv4(tag string) map[string]any {
	return map[string]any{"tag": tag, "protocol": "freedom",
		"settings": map[string]any{"domainStrategy": "UseIPv4"}}
}

// masterConfigPath — путь config.json мастера (var для подмены в тестах).
var masterConfigPath = "/usr/local/etc/xray/config.json"

// ensureMasterIPv4DNS — доставляет фикс #8 на СУЩЕСТВУЮЩИЙ мастер (install.sh
// чинит только новые установки; self-update/рестарт панели лечит старые).
// Идемпотентно: трогает только dns-секцию и freedom-outbounds, остальные поля
// (включая неизвестные) сохраняет. Возвращает true если файл изменён.
// Персист в config.json — применяется при следующем рестарте xray (dns/freedom
// не имеют горячего gRPC-API); вызывается при старте панели и в RestoreInbounds.
func ensureMasterIPv4DNS(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false, err
	}
	changed := false
	if _, ok := cfg["dns"].(map[string]any); !ok {
		cfg["dns"] = ipv4OnlyDNS()
		changed = true
	}
	if obs, ok := cfg["outbounds"].([]any); ok {
		for _, o := range obs {
			om, ok := o.(map[string]any)
			if !ok || om["protocol"] != "freedom" {
				continue
			}
			st, _ := om["settings"].(map[string]any)
			if st == nil {
				st = map[string]any{}
			}
			if st["domainStrategy"] != "UseIPv4" {
				st["domainStrategy"] = "UseIPv4"
				om["settings"] = st
				changed = true
			}
		}
	}
	if !changed {
		return false, nil
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(path, out, 0644); err != nil {
		return false, err
	}
	return true, nil
}
