package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	proxycmd "github.com/xtls/xray-core/app/proxyman/command"

	"github.com/kambarro/xkit-panel/internal/store"
)

// TestToggleOffOnPreservesAuth — BUG-3 (QA 2026-11-26): toggle OFF→ON убивал
// auth hy2/ws: gRPC-восстановление шло ДО SetInboundEnabled → EffectiveProtocols
// («все включённые») не включал сам inbound → ProtocolAllowed=false для всех →
// clients=[] пересоздавался пустым и персистился. Детерминированно 4 репро.
// Здесь: OFF→ON для hy2 и hidden-ws → живой inbound с полным набором клиентов,
// БД clients[] не затёрт.
func TestToggleOffOnPreservesAuth(t *testing.T) {
	s := testStoreAPI(t)
	xc := startTestXray(t)
	srv := NewServer(s, xc, "test", "test.local")
	cert, key := testCertPEM(t)
	certJSON, _ := json.Marshal([]string{cert})
	keyJSON, _ := json.Marshal([]string{key})

	hy2 := store.Inbound{
		Tag: "preset-hysteria2", Protocol: "hysteria2", Port: 18453, Listen: "127.0.0.1",
		Network: "hysteria", Security: "tls", Enabled: true,
		Settings: `{"version":2,"clients":[]}`,
		Stream: fmt.Sprintf(`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2},"tlsSettings":{"serverName":"test.local","alpn":["h3"],"certificates":[{"certificate":%s,"key":%s}]}}`, certJSON, keyJSON),
	}
	ws := store.Inbound{
		Tag: "preset-ws-tls", Protocol: "vless", Port: 18454, Listen: "127.0.0.1",
		Network: "ws", Security: "tls", Enabled: true,
		Settings: `{"clients":[],"decryption":"none"}`,
		Stream: fmt.Sprintf(`{"network":"ws","security":"tls","wsSettings":{"path":"/ws"},"tlsSettings":{"serverName":"test.local","certificates":[{"certificate":%s,"key":%s}]}}`, certJSON, keyJSON),
	}
	for _, ib := range []store.Inbound{hy2, ws} {
		if err := s.UpsertInbound(ib); err != nil {
			t.Fatal(err)
		}
	}
	for i, email := range []string{"client@example.com", "petra@test.ru"} {
		if err := s.UpsertClient(store.Client{Email: email, UUID: fmt.Sprintf("b831381d-6324-4d53-ad4f-8cda48b308%02d", i+11), SubID: "sub" + email, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	// первичное создание inbound + полный доступ (как create/restore)
	if _, _, err := srv.syncHysteria2Access(context.Background(), &hy2); err != nil {
		t.Fatalf("hy2 initial sync: %v", err)
	}
	if err := xc.AddInbound(context.Background(), buildInboundJSON(ws)); err != nil {
		t.Fatalf("ws AddInbound: %v", err)
	}
	srv.addClientsToInbound(httptest.NewRequest(http.MethodPost, "/api/inbounds/toggle", nil), ws)

	toggle := func(tag string, enabled bool) {
		t.Helper()
		body := fmt.Sprintf(`{"tag":%q,"enabled":%v}`, tag, enabled)
		req := httptest.NewRequest(http.MethodPost, "/api/inbounds/toggle", strings.NewReader(body))
		w := httptest.NewRecorder()
		srv.toggleInbound(w, req)
		if w.Code != 200 {
			t.Fatalf("toggle %s=%v: %d %s", tag, enabled, w.Code, w.Body.String())
		}
	}
	users := func(tag string) int64 {
		t.Helper()
		resp, err := xc.Handler.GetInboundUsersCount(context.Background(), &proxycmd.GetInboundUserRequest{Tag: tag})
		if err != nil {
			t.Fatalf("GetInboundUsersCount %s: %v", tag, err)
		}
		return resp.Count
	}

	for _, tag := range []string{"preset-hysteria2", "preset-ws-tls"} {
		if got := users(tag); got != 2 {
			t.Fatalf("%s: до toggle users=%d want 2", tag, got)
		}
		toggle(tag, false)
		toggle(tag, true)
		if got := users(tag); got != 2 {
			t.Errorf("%s: после OFF→ON users=%d want 2 (BUG-3: auth убит)", tag, got)
		}
	}
	// БД hy2: clients[] не затёрт пустым
	got, _ := s.GetInbound("preset-hysteria2")
	var settings map[string]any
	json.Unmarshal([]byte(got.Settings), &settings)
	cls, _ := settings["clients"].([]any)
	if len(cls) != 2 {
		t.Errorf("БД hy2 clients=%d want 2 (затёрт пустым — BUG-3)", len(cls))
	}
	// повторный цикл тоже не должен ломать (QA: детерминированно)
	toggle("preset-hysteria2", false)
	toggle("preset-hysteria2", true)
	if got := users("preset-hysteria2"); got != 2 {
		t.Errorf("hy2 после второго OFF→ON users=%d want 2", got)
	}
}