package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/xray"

	proxycmd "github.com/xtls/xray-core/app/proxyman/command"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// startTestXray — in-process Xray с gRPC API на случайном loopback-порту.
func startTestXray(t *testing.T) *xray.Client {
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
		"outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "api", "protocol": "freedom"}],
		"routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"}]}
	}`, addr)
	pbCfg, err := serial.LoadJSONConfig(stringReader(cfgJSON))
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

// testCertPEM — самоподписанный серт для hy2-inbound (tlsSettings certificate/key строками).
func testCertPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.local"},
		DNSNames:     []string{"test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return
}

func testStoreAPI(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestSyncHysteria2AccessE2E — аудит #2: доступ hy2 пересозданием inbound с
// clients[]; version=2/hysteriaSettings восстановлены; clients персистятся в БД;
// запрет клиента реально убирает его из inbound (GetInboundUsersCount).
func TestSyncHysteria2AccessE2E(t *testing.T) {
	s := testStoreAPI(t)
	xc := startTestXray(t)
	srv := NewServer(s, xc, "test", "test.local")
	cert, key := testCertPEM(t)
	certJSON, _ := json.Marshal([]string{cert})
	keyJSON, _ := json.Marshal([]string{key})
	// «живое» состояние из аудита: version и hysteriaSettings ПОТЕРЯНЫ
	ib := store.Inbound{
		Tag: "preset-hysteria2", Protocol: "hysteria2", Port: 18443, Listen: "127.0.0.1",
		Network: "hysteria", Security: "tls", Enabled: true,
		Settings: `{"clients":[]}`,
		Stream: fmt.Sprintf(`{"network":"hysteria","security":"tls","tlsSettings":{"certificates":[{"certificate":%s,"key":%s}]},"finalmask":{"udp":[{"type":"salamander","settings":{"password":"obfspass"}}]}}`, certJSON, keyJSON),
	}
	if err := s.UpsertInbound(ib); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertClient(store.Client{Email: "client@example.com", UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", SubID: "sub1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertClient(store.Client{Email: "petra@test.ru", UUID: "c942492e-7435-5e64-be50-9deb59c41922", SubID: "sub2", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// petra: hy2 запрещён (override без preset-hysteria2)
	s.SetClientProtocols("petra@test.ru", []string{"vless-reality"})

	added, removed, err := srv.syncHysteria2Access(context.Background(), &ib)
	if err != nil {
		t.Fatalf("syncHysteria2Access: %v", err)
	}
	if added != 1 || removed != 0 {
		t.Errorf("added=%d removed=%d want 1/0", added, removed)
	}
	// живой inbound: 1 user (client), не 0 (мёртвый inbound из аудита)
	resp, err := xc.Handler.GetInboundUsersCount(context.Background(), &proxycmd.GetInboundUserRequest{Tag: "preset-hysteria2"})
	if err != nil {
		t.Fatalf("GetInboundUsersCount: %v", err)
	}
	if resp.Count != 1 {
		t.Fatalf("live hy2 users=%d want 1 (auth 404 bug)", resp.Count)
	}
	// БД: version=2 + hysteriaSettings + clients[client] персистятся
	got, _ := s.GetInbound("preset-hysteria2")
	var settings, stream map[string]any
	json.Unmarshal([]byte(got.Settings), &settings)
	json.Unmarshal([]byte(got.Stream), &stream)
	if settings["version"] != float64(2) {
		t.Errorf("БД settings.version=%v want 2", settings["version"])
	}
	if hy, ok := stream["hysteriaSettings"].(map[string]any); !ok || hy["version"] != float64(2) {
		t.Errorf("БД hysteriaSettings=%v", stream["hysteriaSettings"])
	}
	cls, _ := settings["clients"].([]any)
	if len(cls) != 1 {
		t.Fatalf("БД clients=%d want 1", len(cls))
	}
	c0 := cls[0].(map[string]any)
	if c0["email"] != "client@example.com" || c0["auth"] != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Errorf("БД client=%v", c0)
	}
	// serverName восстановлен (аудит #7): из cert-пути нет — fallback домен
	ts, _ := stream["tlsSettings"].(map[string]any)
	if ts["serverName"] != "test.local" {
		t.Errorf("serverName=%v want test.local", ts["serverName"])
	}

	// запрет client → пересоздание без него: 0 users в живом inbound
	s.SetClientProtocols("client@example.com", []string{"vless-reality"})
	added, removed, err = srv.syncHysteria2Access(context.Background(), got)
	if err != nil {
		t.Fatalf("sync2: %v", err)
	}
	if added != 0 || removed != 1 {
		t.Errorf("added=%d removed=%d want 0/1", added, removed)
	}
	resp, err = xc.Handler.GetInboundUsersCount(context.Background(), &proxycmd.GetInboundUserRequest{Tag: "preset-hysteria2"})
	if err != nil {
		t.Fatalf("count2: %v", err)
	}
	if resp.Count != 0 {
		t.Fatalf("после запрета users=%d want 0", resp.Count)
	}
}
