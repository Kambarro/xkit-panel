package api

// B-1/B-2 (Ops-деплой 147be19, 2026-11-26): toggle hy2 ON отвечает ok, но
// syncHysteria2Access→UpsertInbound(УСТАРЕВШИЙ ib) перезаписывает enabled=0
// (ib прочитан ДО SetInboundEnabled(true)) → hy2 исчезает из подписок,
// повторный toggle не лечит; syncFirewall вслед за enabled=0 закрывает udp-порт.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/subscription"
)

// subLinkForTag — ссылка подписки для tag штатным путём main.go:
// SQL enabled=1 AND in_sub=1 → ParseInboundSpec → LinkForInbound. "" = протокола нет.
func subLinkForTag(t *testing.T, s *store.Store, tag, uuid, email string) string {
	t.Helper()
	var protocol, network, security, settingsJ, streamJ string
	var port int
	err := s.DB().QueryRow(`SELECT protocol,port,network,security,settings,stream FROM inbounds WHERE tag=? AND enabled=1 AND in_sub=1`, tag).
		Scan(&protocol, &port, &network, &security, &settingsJ, &streamJ)
	if err != nil {
		return ""
	}
	sp := subscription.ParseInboundSpec(tag, protocol, port, network, security, settingsJ, streamJ)
	return subscription.LinkForInbound(sp, uuid, email, "e2e", "127.0.0.1")
}

func toggleReq(t *testing.T, srv *Server, tag string, enabled bool) {
	t.Helper()
	body := fmt.Sprintf(`{"tag":%q,"enabled":%v}`, tag, enabled)
	w := httptest.NewRecorder()
	srv.toggleInbound(w, httptest.NewRequest(http.MethodPost, "/api/inbounds/toggle", strings.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("toggle %s=%v: %d %s", tag, enabled, w.Code, w.Body.String())
	}
}

// TestToggleHy2EnabledPersistE2E — B-1: OFF→ON → БД enabled=1 И подписка содержит
// hy2 И реальный auth 233. Повторный цикл тоже держит enabled=1.
func TestToggleHy2EnabledPersistE2E(t *testing.T) {
	s := testStoreAPI(t)
	xc := startHy2SubServerXray(t)
	srv := NewServer(s, xc, "test", "test.local")
	cert, key := testCertPEM(t)
	certJSON, _ := json.Marshal([]string{cert})
	keyJSON, _ := json.Marshal([]string{key})
	const authUUID = "a1b2c3d4-0000-4000-8000-toggleenabled1"
	const port = 18456
	ib := store.Inbound{
		Tag: "preset-hysteria2", Protocol: "hysteria2", Port: port, Listen: "127.0.0.1",
		Network: "hysteria", Security: "tls", Enabled: true, InSub: true,
		Settings: fmt.Sprintf(`{"version":2,"clients":[{"auth":%q,"email":"client@example.com","level":0}]}`, authUUID),
		Stream:   fmt.Sprintf(`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2},"tlsSettings":{"serverName":"test.local","alpn":["h3"],"certificates":[{"certificate":%s,"key":%s}]}}`, certJSON, keyJSON),
	}
	if err := s.UpsertInbound(ib); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertClient(store.Client{Email: "client@example.com", UUID: authUUID, SubID: "sub1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// первичное создание (как create/restore)
	if _, _, err := srv.syncHysteria2Access(context.Background(), &ib); err != nil {
		t.Fatalf("initial sync: %v", err)
	}

	dbEnabled := func() bool {
		t.Helper()
		got, _ := s.GetInbound("preset-hysteria2")
		if got == nil {
			t.Fatal("inbound пропал из БД")
		}
		return got.Enabled
	}

	toggleReq(t, srv, "preset-hysteria2", false)
	if dbEnabled() {
		t.Fatal("после OFF enabled=1")
	}
	if l := subLinkForTag(t, s, "preset-hysteria2", authUUID, "client@example.com"); l != "" {
		t.Fatalf("после OFF подписка всё ещё отдаёт hy2: %s", l)
	}
	if _, ok := srv.neededPorts()[port]; ok {
		t.Error("после OFF neededPorts содержит udp-порт (B-2: firewall должен закрыть)")
	}

	toggleReq(t, srv, "preset-hysteria2", true)
	if !dbEnabled() {
		t.Error("B-1: после ON БД enabled=0 (UpsertInbound со старым ib откатил)")
	}
	link := subLinkForTag(t, s, "preset-hysteria2", authUUID, "client@example.com")
	if !strings.HasPrefix(link, "hysteria2://") {
		t.Errorf("B-1: после ON подписка без hy2 (link=%q)", link)
	}
	if pr, ok := srv.neededPorts()[port]; !ok || pr != "udp" {
		t.Errorf("B-2: после ON neededPorts[%d]=%q,%v want udp,true", port, pr, ok)
	}
	// реальный auth: 233 = клиенты на месте и inbound жив
	pctx, pcancel := context.WithTimeout(context.Background(), 12*time.Second)
	code, err := hy2AuthProbe(pctx, "127.0.0.1", port, "test.local", authUUID, "")
	pcancel()
	if err != nil || code != 233 {
		t.Errorf("auth после ON: code=%d err=%v want 233", code, err)
	}

	// повторный OFF→ON (Ops: «повторный toggle не лечит» — фикс обязан держать)
	toggleReq(t, srv, "preset-hysteria2", false)
	toggleReq(t, srv, "preset-hysteria2", true)
	if !dbEnabled() {
		t.Error("B-1: после второго ON БД enabled=0")
	}
	if l := subLinkForTag(t, s, "preset-hysteria2", authUUID, "client@example.com"); !strings.HasPrefix(l, "hysteria2://") {
		t.Errorf("B-1: после второго ON подписка без hy2 (link=%q)", l)
	}
}

// ufwStub — фейковый ufw (реальный требует root): правила в файле $UFW_STUB_RULES.
// Понимает ровно те вызовы, что делает internal/firewall.
const ufwStub = `#!/bin/bash
RULES="${UFW_STUB_RULES:?}"
touch "$RULES"
case "$1" in
status)
  echo "Status: active"
  if [ "$2" = "numbered" ]; then
    n=0; while IFS= read -r line; do n=$((n+1)); echo "[ $n] $line"; done < "$RULES"
  else
    cat "$RULES"
  fi ;;
allow)
  rule="$2"; shift 2
  line="$rule                   ALLOW IN    Anywhere"
  if [ "$1" = "comment" ]; then line="$line # $2"; fi
  grep -q "^$rule " "$RULES" || echo "$line" >> "$RULES" ;;
delete)
  if [ "$2" = "allow" ]; then sed -i "\|^$3 |d" "$RULES"; fi ;;
esac
exit 0
`

// TestToggleFirewallFollowsEnabled — B-2: UFW (стаб) следует за РЕАЛЬНЫМ enabled:
// ON → правило <port>/udp ALLOW XKIT:auto есть, OFF → удалено. RED при B-1:
// enabled откатывался в 0 → syncFirewall закрывал порт живого inbound.
func TestToggleFirewallFollowsEnabled(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "ufw")
	if err := os.WriteFile(stub, []byte(ufwStub), 0755); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(dir, "rules.txt")
	t.Setenv("UFW_STUB_RULES", rules)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	s := testStoreAPI(t)
	xc := startTestXray(t)
	srv := NewServer(s, xc, "test", "test.local")
	cert, key := testCertPEM(t)
	certJSON, _ := json.Marshal([]string{cert})
	keyJSON, _ := json.Marshal([]string{key})
	const port = 18457
	ib := store.Inbound{
		Tag: "preset-hysteria2", Protocol: "hysteria2", Port: port, Listen: "127.0.0.1",
		Network: "hysteria", Security: "tls", Enabled: true, InSub: true,
		Settings: `{"version":2,"clients":[]}`,
		Stream:   fmt.Sprintf(`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2},"tlsSettings":{"serverName":"test.local","alpn":["h3"],"certificates":[{"certificate":%s,"key":%s}]}}`, certJSON, keyJSON),
	}
	if err := s.UpsertInbound(ib); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertClient(store.Client{Email: "client@example.com", UUID: "a1b2c3d4-0000-4000-8000-togglefirewall", SubID: "sub1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.syncHysteria2Access(context.Background(), &ib); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	rule := fmt.Sprintf("%d/udp", port)
	hasRule := func() bool {
		t.Helper()
		b, _ := os.ReadFile(rules)
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, rule+" ") && strings.Contains(l, "XKIT:auto") {
				return true
			}
		}
		return false
	}

	srv.syncFirewall()
	if !hasRule() {
		t.Fatalf("enabled=1, но правила %s нет (стартовое состояние)", rule)
	}
	toggleReq(t, srv, "preset-hysteria2", false)
	if hasRule() {
		t.Error("после OFF правило udp осталось (firewall не следует за enabled)")
	}
	toggleReq(t, srv, "preset-hysteria2", true)
	if !hasRule() {
		t.Error("B-2: после ON правило udp не вернулось (enabled откатился — B-1)")
	}
}
