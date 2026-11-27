package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kambarro/xkit-panel/internal/store"
)

// Аудит #2: hy2 inbound мёртв — settings.version=2 и stream.hysteriaSettings
// терялись при пересоздании/миграциях; xray registry protocol "hysteria"
// требует version=2 в ОБОИХ местах, иначе inbound без users/auth (404).

// TestNormalizeHysteria2 — потерянные version/hysteriaSettings/serverName
// восстанавливаются, существующие значения не трогаются.
func TestNormalizeHysteria2(t *testing.T) {
	cases := []struct {
		name     string
		settings string
		stream   string
		wantVer  float64
		wantHy2  bool
		wantSNI  string
	}{
		{
			name:     "lost version and hysteriaSettings (live DB state)",
			settings: `{"clients":[]}`,
			stream:   `{"network":"hysteria","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/etc/letsencrypt/live/x.ru/fullchain.pem","keyFile":"/etc/letsencrypt/live/x.ru/privkey.pem"}]},"finalmask":{"udp":[{"type":"salamander","settings":{"password":"obfs"}}]}}`,
			wantVer:  2, wantHy2: true, wantSNI: "x.ru",
		},
		{
			name:     "intact — untouched",
			settings: `{"version":2,"clients":[{"auth":"u1","email":"a@b.c"}]}`,
			stream:   `{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2},"tlsSettings":{"serverName":"keep.ru","alpn":["h3"],"certificates":[]}}`,
			wantVer:  2, wantHy2: true, wantSNI: "keep.ru",
		},
	}
	for _, c := range cases {
		ib := store.Inbound{Tag: "preset-hysteria2", Protocol: "hysteria2", Port: 8443,
			Network: "hysteria", Security: "tls", Settings: c.settings, Stream: c.stream, Enabled: true}
		changed := normalizeHysteria2(&ib, "fallback.ru")
		var settings, stream map[string]any
		json.Unmarshal([]byte(ib.Settings), &settings)
		json.Unmarshal([]byte(ib.Stream), &stream)
		if settings["version"] != c.wantVer {
			t.Errorf("%s: settings.version=%v want %v", c.name, settings["version"], c.wantVer)
		}
		hy, ok := stream["hysteriaSettings"].(map[string]any)
		if ok != c.wantHy2 || (ok && hy["version"] != float64(2)) {
			t.Errorf("%s: hysteriaSettings=%v want version 2", c.name, stream["hysteriaSettings"])
		}
		ts, _ := stream["tlsSettings"].(map[string]any)
		if ts == nil || ts["serverName"] != c.wantSNI {
			t.Errorf("%s: serverName=%v want %q", c.name, ts["serverName"], c.wantSNI)
		}
		if c.name == "intact — untouched" && changed {
			t.Errorf("%s: changed=true, want false", c.name)
		}
		if c.name != "intact — untouched" && !changed {
			t.Errorf("%s: changed=false, want true", c.name)
		}
		// network hysteria обязателен (registry transport)
		if stream["network"] != "hysteria" {
			t.Errorf("%s: network=%v want hysteria", c.name, stream["network"])
		}
	}
}

// TestHysteria2ClientsJSON — clients[] для пересоздания inbound: auth=uuid,
// email, level; пустой список = [] (не null).
func TestHysteria2ClientsJSON(t *testing.T) {
	cls := hysteria2Clients([]hy2User{{Email: "a@b.c", UUID: "uuid-1"}, {Email: "d@e.f", UUID: "uuid-2"}})
	if len(cls) != 2 {
		t.Fatalf("clients=%d want 2", len(cls))
	}
	c0 := cls[0].(map[string]any)
	if c0["auth"] != "uuid-1" || c0["email"] != "a@b.c" {
		t.Errorf("client[0]=%v", c0)
	}
	empty := hysteria2Clients(nil)
	b, _ := json.Marshal(empty)
	if string(b) != "[]" {
		t.Errorf("empty clients must marshal to [], got %s", b)
	}
}

// TestBuildInboundJSONHysteria2 — JSON для gRPC: protocol=hysteria (registry),
// version=2 в settings И stream.hysteriaSettings, subSni/subTls не утекают в settings.
func TestBuildInboundJSONHysteria2(t *testing.T) {
	ib := store.Inbound{Tag: "preset-hysteria2", Protocol: "hysteria2", Port: 8443, Listen: "0.0.0.0",
		Network: "hysteria", Security: "tls",
		Settings: `{"clients":[],"subSni":"x.ru","subTls":true}`,
		Stream:   `{"network":"udp","security":"tls","tlsSettings":{"certificates":[]}}`,
		Enabled: true}
	normalizeHysteria2(&ib, "x.ru")
	out := buildInboundJSON(ib)
	var full map[string]any
	if err := json.Unmarshal([]byte(out), &full); err != nil {
		t.Fatalf("json: %v", err)
	}
	if full["protocol"] != "hysteria" {
		t.Errorf("protocol=%v want hysteria", full["protocol"])
	}
	settings := full["settings"].(map[string]any)
	if settings["version"] != float64(2) {
		t.Errorf("settings.version=%v", settings["version"])
	}
	if _, ok := settings["subSni"]; ok {
		t.Error("subSni leaked into xray settings")
	}
	stream := full["streamSettings"].(map[string]any)
	if stream["network"] != "hysteria" {
		t.Errorf("stream.network=%v want hysteria", stream["network"])
	}
	if hy, ok := stream["hysteriaSettings"].(map[string]any); !ok || hy["version"] != float64(2) {
		t.Errorf("hysteriaSettings=%v", stream["hysteriaSettings"])
	}
	// конфиг должен парситься штатным парсером xray (infra/conf) — без cert-файлов
	// Build упадёт на certificates, поэтому проверяем только структуру JSON выше.
	if !strings.Contains(out, `"version":2`) {
		t.Error("version:2 missing in JSON")
	}
}
