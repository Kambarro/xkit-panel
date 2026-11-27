package api

// E2E остатка Ops b737b05: hy2 в xray-json подписке был битый — auth лежал в
// settings.auth (HysteriaClientConfig ядра 26.11.9 его дропает), obfs salamander
// не транслировался в finalmask → клиент из ?format=xray получал auth 404.
// Здесь ПОЛНЫЙ цикл: inbound → LinkForInbound (raw-ссылка) → XrayJSON (подписка)
// → реальный xray-клиент из сгенерированного JSON → auth 233 + трафик через туннель.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/xtls/xray-core/common/geodata"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"google.golang.org/protobuf/proto"

	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/subscription"
	"github.com/kambarro/xkit-panel/internal/xray"
)

// writeClientGeoFiles — минимальные geoip/geosite для загрузки КЛИЕНТСКОГО конфига
// подписки (routing geoip:ru/private + geosite:category-ru, dns geosite:category-ru).
func writeClientGeoFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	geoIP := &geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "RU", Cidr: []*geodata.CIDR{{Ip: []byte{10, 77, 0, 0}, Prefix: 16}}},
		{Code: "PRIVATE", Cidr: []*geodata.CIDR{{Ip: []byte{127, 0, 0, 0}, Prefix: 8}}},
	}}
	geoSite := &geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{Code: "CATEGORY-RU", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "example-ru.test"}}},
	}}
	for name, msg := range map[string]proto.Message{"geoip.dat": geoIP, "geosite.dat": geoSite} {
		b, err := proto.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	t.Setenv("xray.location.asset", dir)
}

// startClientFromJSON — реальный xray-клиент из JSON подписки (serial.LoadJSONConfig
// — тот же парсер, что у клиента incy/Xray). Возвращает socks-адрес.
func startClientFromJSON(t *testing.T, cfgJSON string) string {
	t.Helper()
	pbCfg, err := serial.LoadJSONConfig(strings.NewReader(cfgJSON))
	if err != nil {
		t.Fatalf("client config load: %v", err)
	}
	inst, err := core.New(pbCfg)
	if err != nil {
		t.Fatalf("client core.New: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("client start: %v", err)
	}
	t.Cleanup(func() { inst.Close() })
	var cfg map[string]any
	json.Unmarshal([]byte(cfgJSON), &cfg)
	ib := cfg["inbounds"].([]any)[0].(map[string]any)
	return fmt.Sprintf("127.0.0.1:%v", ib["port"])
}

// socksGET — HTTP GET через socks5 клиента (реальный трафик через туннель).
func socksGET(socksAddr, url string, timeout time.Duration) (int, string, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return 0, "", err
	}
	cl := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: dialer.(proxy.ContextDialer).DialContext,
		},
	}
	resp, err := cl.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(body), nil
}

// startHy2SubServerXray — тестовый сервер-xray как startTestXray, но freedom
// разрешает loopback-таргеты: ядро 26.11.9 для hysteria-inbound по умолчанию
// блокирует private-адреса (defaultBlockPrivateRule), а E2E-таргет — httptest
// на 127.0.0.1. В проде таргеты публичные — правило не нужно.
func startHy2SubServerXray(t *testing.T) *xray.Client {
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
		"outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}, {"tag": "api", "protocol": "freedom"}],
		"routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"}]}
	}`, addr)
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
	xc, err := xray.Dial(addr)
	if err != nil {
		t.Fatalf("xray dial: %v", err)
	}
	t.Cleanup(func() { xc.Close() })
	return xc
}

func TestXrayJSONHy2SubscriptionE2E(t *testing.T) {
	writeClientGeoFiles(t)
	s := testStoreAPI(t)
	xc := startHy2SubServerXray(t)
	cert, key := testCertPEM(t)
	certJSON, _ := json.Marshal([]string{cert})
	keyJSON, _ := json.Marshal([]string{key})
	const authUUID = "a1b2c3d4-0000-4000-8000-subscriptionhy2"
	ib := store.Inbound{
		Tag: "preset-hysteria2", Protocol: "hysteria2", Port: 18447, Listen: "127.0.0.1",
		Network: "hysteria", Security: "tls", Enabled: true,
		Settings: fmt.Sprintf(`{"version":2,"clients":[{"auth":%q,"email":"client@example.com","level":0}]}`, authUUID),
		Stream: fmt.Sprintf(`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2},"tlsSettings":{"serverName":"test.local","alpn":["h3"],"certificates":[{"certificate":%s,"key":%s}]},"finalmask":{"udp":[{"type":"salamander","settings":{"password":"obfspass"}}]}}`, certJSON, keyJSON),
	}
	if err := s.UpsertInbound(ib); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertClient(store.Client{Email: "client@example.com", UUID: authUUID, SubID: "sub1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := xc.AddInbound(ctx, buildInboundJSONProto(ib, "hysteria")); err != nil {
		t.Fatalf("AddInbound: %v", err)
	}

	// raw-ссылка тем же кодом, что отдаёт подписка
	spec := subscription.ParseInboundSpec(ib.Tag, ib.Protocol, ib.Port, ib.Network, ib.Security, ib.Settings, ib.Stream)
	link := subscription.LinkForInbound(spec, authUUID, "client@example.com", "hy2sub", "127.0.0.1")
	if !strings.HasPrefix(link, "hysteria2://") {
		t.Fatalf("not hy2 link: %s", link)
	}
	p := subscription.ParseLink(link)
	if p == nil || p.Password != authUUID || p.Obfs != "salamander" || p.ObfsPass != "obfspass" {
		t.Fatalf("link roundtrip: %+v", p)
	}

	// xray-json подписка: кастомное правило (штатный P2-механизм) шлёт loopback-таргет
	// через прокси — иначе дефолтный geoip:private→direct увёл бы пробу мимо туннеля.
	proxyTag := p.Name
	gen := subscription.XrayJSONRouting([]string{link}, []map[string]any{
		{"type": "field", "ip": []string{"127.0.0.1/32"}, "outboundTag": proxyTag},
	})
	var cfg map[string]any
	if err := json.Unmarshal([]byte(gen), &cfg); err != nil {
		t.Fatalf("subscription JSON invalid: %v", err)
	}
	ob := cfg["outbounds"].([]any)[0].(map[string]any)
	settings := ob["settings"].(map[string]any)
	stream := ob["streamSettings"].(map[string]any)
	hy := stream["hysteriaSettings"].(map[string]any)
	// структура по коду ядра 26.11.9: auth ТОЛЬКО в stream.hysteriaSettings (settings.auth дропается)
	if _, bad := settings["auth"]; bad {
		t.Error("auth в settings — ядро 26.11.9 его дропает (баг Ops)")
	}
	if hy["auth"] != authUUID {
		t.Fatalf("stream.hysteriaSettings.auth=%v want %s", hy["auth"], authUUID)
	}
	fm, ok := stream["finalmask"].(map[string]any)
	if !ok {
		t.Fatal("finalmask отсутствует — salamander не транслирован (таймаут под маской)")
	}
	udp0 := fm["udp"].([]any)[0].(map[string]any)
	if udp0["type"] != "salamander" || udp0["settings"].(map[string]any)["password"] != "obfspass" {
		t.Fatalf("finalmask.udp[0]=%v", udp0)
	}

	// auth-проба значениями ИЗ сгенерированного конфига (паттерн TestHy2AuthProbeE2E): 233
	pctx, pcancel := context.WithTimeout(context.Background(), 12*time.Second)
	code, err := hy2AuthProbe(pctx, "127.0.0.1", ib.Port, "test.local", hy["auth"].(string), "obfspass")
	pcancel()
	if err != nil || code != 233 {
		t.Fatalf("auth probe из подписки: code=%d err=%v want 233", code, err)
	}

	// test-only адаптация сгенерированного JSON (auth/маска НЕ трогаются):
	// socks-порт → свободный; доверие self-signed серту через pinnedPeerCertSha256
	// (allowInsecure удалён в 26.x; пин влияет только на TLS-доверие, не на auth).
	block, _ := pem.Decode([]byte(cert))
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(crt.Raw)
	pin := hex.EncodeToString(h[:])
	stream["tlsSettings"].(map[string]any)["pinnedPeerCertSha256"] = pin
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg["inbounds"].([]any)[0].(map[string]any)["port"] = socksPort
	adapted, _ := json.Marshal(cfg)

	// реальный клиент из подписки → трафик через туннель (auth 233 обязателен для успеха)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunnel-ok")
	}))
	defer target.Close()
	socksAddr := startClientFromJSON(t, string(adapted))
	var lastErr error
	for i := 0; i < 3; i++ {
		var code int
		var body string
		code, body, lastErr = socksGET(socksAddr, target.URL, 15*time.Second)
		if lastErr == nil && code == 200 && body == "tunnel-ok" {
			lastErr = nil
			break
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("code=%d body=%q", code, body)
		}
	}
	if lastErr != nil {
		t.Fatalf("трафик через hy2 из xray-json подписки не прошёл: %v", lastErr)
	}

	// контроль (репро бага Ops): auth убран из hysteriaSettings (как дропало ядро
	// из settings.auth) → пустой auth → сервер отвечает 404. Детерминированно:
	// auth-проба тем же пустым auth, что ушёл бы у broken-клиента.
	delete(hy, "auth")
	if broken, _ := json.Marshal(cfg); strings.Contains(string(broken), authUUID) {
		t.Fatal("broken-конфиг всё ещё содержит auth")
	}
	pctx, pcancel = context.WithTimeout(context.Background(), 12*time.Second)
	code, err = hy2AuthProbe(pctx, "127.0.0.1", ib.Port, "test.local", "", "obfspass")
	pcancel()
	if err != nil || code != 404 {
		t.Fatalf("КОНТРОЛЬ: пустой auth обязан давать 404 (баг Ops), code=%d err=%v", code, err)
	}
}
