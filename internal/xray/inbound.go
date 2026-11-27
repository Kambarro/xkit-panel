package xray

import (
	"encoding/json"
	"fmt"

	router "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// loadInboundConfig конвертирует JSON inbound'а (как в config.json) в protobuf
// core.InboundHandlerConfig через штатный парсер Xray (infra/conf).
// УРОК: не изобретаем свой парсер — Xray уже умеет JSON→protobuf для всех протоколов.
func loadInboundConfig(inboundJSON string) (*core.InboundHandlerConfig, error) {
	var ib conf.InboundDetourConfig
	if err := json.Unmarshal([]byte(inboundJSON), &ib); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	cfg, err := ib.Build()
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	return cfg, nil
}

// LoadInboundConfigForTest — экспорт loadInboundConfig для тестов других пакетов
// (проверка что JSON inbound'а парсится штатным парсером Xray).
func LoadInboundConfigForTest(inboundJSON string) (*core.InboundHandlerConfig, error) {
	return loadInboundConfig(inboundJSON)
}

// ParseRoutingConfig конвертирует JSON routing-секции (как в config.json) в protobuf
// router.Config через штатный парсер Xray (infra/conf). Используется survey транспортов:
// чтобы вставить временное правило ПЕРЕД catch-all (append кладёт в конец → catch-all
// перехватит трафик раньше), нужен полный снапшот правил в protobuf для ReplaceRules.
// geoip:/geosite: внутри правил резолвятся штатным парсером (geo-файлы Xray).
func ParseRoutingConfig(routingJSON string) (*router.Config, error) {
	var rc conf.RouterConfig
	if err := json.Unmarshal([]byte(routingJSON), &rc); err != nil {
		return nil, fmt.Errorf("routing json: %w", err)
	}
	cfg, err := rc.Build()
	if err != nil {
		return nil, fmt.Errorf("routing build: %w", err)
	}
	return cfg, nil
}
