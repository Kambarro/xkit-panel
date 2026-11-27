package api

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

// TestHy2AuthProbeE2E — смоук аудита #2c: реальная auth-проба против живого
// in-process xray hy2-inbound. 233 с валидным auth, 404 с неверным (и 404 на
// любой auth когда users нет — мёртвый inbound из аудита).
func TestHy2AuthProbeE2E(t *testing.T) {
	s := testStoreAPI(t)
	xc := startTestXray(t)
	srv := NewServer(s, xc, "test", "test.local")
	cert, key := testCertPEM(t)
	certJSON, _ := json.Marshal([]string{cert})
	keyJSON, _ := json.Marshal([]string{key})
	ib := store.Inbound{
		Tag: "preset-hysteria2", Protocol: "hysteria2", Port: 18444, Listen: "127.0.0.1",
		Network: "hysteria", Security: "tls", Enabled: true,
		Settings: `{"version":2,"clients":[{"auth":"valid-auth-uuid","email":"client@example.com","level":0}]}`,
		Stream: fmt.Sprintf(`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2},"tlsSettings":{"serverName":"test.local","certificates":[{"certificate":%s,"key":%s}]},"finalmask":{"udp":[{"type":"salamander","settings":{"password":"obfspass"}}]}}`, certJSON, keyJSON),
	}
	if err := s.UpsertInbound(ib); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertClient(store.Client{Email: "client@example.com", UUID: "valid-auth-uuid", SubID: "sub1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := xc.AddInbound(ctx, buildInboundJSONProto(ib, "hysteria")); err != nil {
		t.Fatalf("AddInbound: %v", err)
	}
	// валидный auth + правильный obfs → 233
	pctx, pcancel := context.WithTimeout(context.Background(), 12*time.Second)
	code, err := hy2AuthProbe(pctx, "127.0.0.1", ib.Port, "test.local", "valid-auth-uuid", "obfspass")
	pcancel()
	if err != nil {
		t.Fatalf("probe valid: %v", err)
	}
	if code != 233 {
		t.Fatalf("valid auth: code=%d want 233", code)
	}
	// неверный auth → 404 (masquerade)
	pctx, pcancel = context.WithTimeout(context.Background(), 12*time.Second)
	code, err = hy2AuthProbe(pctx, "127.0.0.1", ib.Port, "test.local", "wrong-auth", "obfspass")
	pcancel()
	if err != nil {
		t.Fatalf("probe wrong: %v", err)
	}
	if code != 404 {
		t.Fatalf("wrong auth: code=%d want 404", code)
	}
	// doctorHy2Smoke на этом состоянии → ok
	checks := srv.doctorHy2Smoke()
	if len(checks) != 1 {
		t.Fatalf("checks=%d want 1", len(checks))
	}
	if checks[0].Status != "ok" {
		t.Fatalf("doctor hy2 smoke: %s (%s)", checks[0].Status, checks[0].Detail)
	}

	// мёртвый inbound (users нет — состояние аудита): ЛЮБОЙ auth → 404
	dead := ib
	dead.Tag = "preset-hy2-dead"
	dead.Port = 18445
	dead.Settings = `{"version":2,"clients":[]}`
	if err := xc.AddInbound(ctx, buildInboundJSONProto(dead, "hysteria")); err != nil {
		t.Fatalf("AddInbound dead: %v", err)
	}
	pctx, pcancel = context.WithTimeout(context.Background(), 12*time.Second)
	code, err = hy2AuthProbe(pctx, "127.0.0.1", dead.Port, "test.local", "valid-auth-uuid", "obfspass")
	pcancel()
	if err != nil {
		t.Fatalf("probe dead: %v", err)
	}
	if code != 404 {
		t.Fatalf("dead inbound: code=%d want 404 (auth 404 bug reproduced)", code)
	}
}
