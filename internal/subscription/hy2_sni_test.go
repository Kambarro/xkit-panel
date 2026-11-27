package subscription

import (
	"strings"
	"testing"
)

// Аудит #7: hy2-ссылка с пустым sni — клиент Xray 26.x не может валидировать
// TLS (allowInsecure удалён). serverName терялся при пересоздании inbound —
// LinkForInbound обязан подставлять address (сертификат выдан на домен мастера).
func TestHy2LinkSNIFallback(t *testing.T) {
	spec := InboundSpec{
		Tag: "preset-hysteria2", Protocol: "hysteria2", Port: 8443,
		Network: "hysteria", Security: "tls",
		Settings: map[string]any{"version": float64(2), "clients": []any{}},
		Stream: map[string]any{
			"network": "hysteria", "security": "tls",
			"tlsSettings": map[string]any{"certificates": []any{}}, // serverName ПОТЕРЯН
		},
	}
	link := LinkForInbound(spec, "auth-uuid", "client@example.com", "Hy2", "vpn.example.com")
	if !strings.HasPrefix(link, "hysteria2://") {
		t.Fatalf("not hy2 link: %s", link)
	}
	if !strings.Contains(link, "sni=vpn.example.com") {
		t.Errorf("пустой sni должен fallback на address: %s", link)
	}
	if strings.Contains(link, "sni=&") || strings.HasSuffix(link, "sni=") {
		t.Errorf("sni пустой: %s", link)
	}
	// существующий serverName не трогается
	spec.Stream["tlsSettings"] = map[string]any{"serverName": "keep.example.com"}
	link = LinkForInbound(spec, "auth-uuid", "client@example.com", "Hy2", "vpn.example.com")
	if !strings.Contains(link, "sni=keep.example.com") {
		t.Errorf("существующий sni затёрт: %s", link)
	}
}
