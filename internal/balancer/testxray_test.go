package balancer

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/xray"

	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// startXrayAPI — in-process Xray с gRPC API (RoutingService/HandlerService/StatsService)
// на случайном loopback-порту. routingJSON — снапшот routing-секции как в config.json
// мастера (geo-правила не используем: geoip.dat/geosite.dat в тест-окружении нет).
// Возвращает подключённый xray.Client; инстанс закрывается через t.Cleanup.
func startXrayAPI(t *testing.T, routingJSON string) *xray.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	cfgJSON := fmt.Sprintf(`{
		"log": {"loglevel": "error"},
		"api": {"tag": "api", "listen": %q, "services": ["HandlerService", "RoutingService", "StatsService"]},
		"inbounds": [{"tag": "api-in", "listen": "127.0.0.1", "port": 0, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}}],
		"outbounds": [
			{"tag": "direct", "protocol": "freedom"},
			{"tag": "api", "protocol": "freedom"},
			{"tag": "node-nl-1", "protocol": "freedom"},
			{"tag": "node-de-1", "protocol": "freedom"},
			{"tag": "node-us-1", "protocol": "freedom"}
		],
		"routing": %s
	}`, addr, routingJSON)
	return startXrayAPIWithConfig(t, cfgJSON)
}

// startXrayAPIWithConfig — общий запуск in-process Xray по готовому JSON-конфигу.
func startXrayAPIWithConfig(t *testing.T, cfgJSON string) *xray.Client {
	t.Helper()
	var top struct {
		API struct{ Listen string } `json:"api"`
	}
	if err := json.Unmarshal([]byte(cfgJSON), &top); err != nil {
		t.Fatalf("api listen: %v", err)
	}
	addr := top.API.Listen
	pbCfg, err := serial.LoadJSONConfig(strings.NewReader(cfgJSON))
	if err != nil {
		t.Fatalf("xray config: %v", err)
	}
	inst, err := core.New(pbCfg)
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("xray start: %v", err)
	}
	t.Cleanup(func() { inst.Close() })
	// ждём готовности API (commander поднимается в Start, но dial — с таймаутом)
	var xc *xray.Client
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		xc, err = xray.Dial(addr)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("xray dial: %v", err)
	}
	t.Cleanup(func() { xc.Close() })
	return xc
}

// testClient — включённый клиент панели (uuid детерминированный от email).
func testClient(email, country string, code uint32) store.Client {
	return store.Client{Email: email, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		SubID: "sub-" + email, Name: email, Country: country, CountryCode: code, Enabled: true}
}

// storeAssignment — назначение клиента на ноду (ruleTag как в Balancer.Assign).
func storeAssignment(email, country, nodeID string) store.Assignment {
	return store.Assignment{Email: email, Country: country, NodeID: nodeID,
		RuleTag: fmt.Sprintf("c:%s:%s", email, country), Status: "sticky"}
}

var _ = context.Background
var _ = grpc.NewServer
var _ = insecure.NewCredentials
