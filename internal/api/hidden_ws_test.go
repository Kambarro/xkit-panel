package api

import (
	"encoding/json"
	"testing"

	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/xray"
)

// TestSanitizeHiddenStream — аудит #6: hidden ws-inbound с TLS и пустым доменом
// → plaintext-stream за dispatcher (cert-путь live//fullchain больше не строится).
func TestSanitizeHiddenStream(t *testing.T) {
	ib := store.Inbound{
		Tag: "preset-ws-tls", Protocol: "vless", Port: 8445, Listen: "127.0.0.1",
		Network: "ws", Security: "tls", Enabled: true, Hidden: true, PublicPort: 443,
		Settings: `{"clients":[],"decryption":"none"}`,
		Stream:   `{"network":"ws","security":"tls","tlsSettings":{"serverName":"","certificates":[{"certificateFile":"/etc/letsencrypt/live//fullchain.pem","keyFile":"/etc/letsencrypt/live//privkey.pem"}]},"wsSettings":{"path":"/abc123"}}`,
	}
	if !sanitizeHiddenStream(&ib) {
		t.Fatal("sanitizeHiddenStream: no change")
	}
	var stream map[string]any
	json.Unmarshal([]byte(ib.Stream), &stream)
	if _, ok := stream["tlsSettings"]; ok {
		t.Error("tlsSettings остался в hidden-stream (cert live//fullchain)")
	}
	if sec, _ := stream["security"].(string); sec == "tls" {
		t.Error("security=tls в hidden-stream")
	}
	ws, _ := stream["wsSettings"].(map[string]any)
	if ws == nil || ws["path"] != "/abc123" {
		t.Errorf("wsSettings потерян: %v", stream["wsSettings"])
	}
	// идемпотентно
	if sanitizeHiddenStream(&ib) {
		t.Error("повторный sanitize не должен менять")
	}
	// JSON для AddInbound парсится штатным парсером xray (без cert-файлов)
	if _, err := xray.LoadInboundConfigForTest(buildInboundJSON(ib)); err != nil {
		t.Errorf("hidden inbound не парсится: %v", err)
	}
	// sni из tlsSettings сохраняется в subSni для подписки
	ib2 := store.Inbound{Tag: "x", Protocol: "vless", Network: "ws", Hidden: true,
		Settings: `{"clients":[]}`,
		Stream:   `{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example.ru"},"wsSettings":{"path":"/p"}}`}
	sanitizeHiddenStream(&ib2)
	var settings map[string]any
	json.Unmarshal([]byte(ib2.Settings), &settings)
	if settings["subSni"] != "sni.example.ru" {
		t.Errorf("subSni=%v want sni.example.ru", settings["subSni"])
	}
}
