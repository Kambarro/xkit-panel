package subscription

import (
	"strings"
	"testing"
)

func TestVlessLink(t *testing.T) {
	m := MasterParams{Address: "example.com", Port: 443, SNI: "example.com", PublicKey: "pubkey123", ShortID: "sid123", Fingerprint: "chrome", Flow: "xtls-rprx-vision"}
	link := VlessLink("b831381d-6324-4d53-ad4f-8cda48b30811", "ivan@test.ru", "Ivan", m)
	if !strings.HasPrefix(link, "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?") {
		t.Errorf("bad link prefix: %s", link)
	}
	if !strings.Contains(link, "security=reality") || !strings.Contains(link, "pbk=pubkey123") || !strings.Contains(link, "flow=xtls-rprx-vision") {
		t.Errorf("missing params: %s", link)
	}
	if !strings.Contains(link, "#Ivan") {
		t.Errorf("missing remark: %s", link)
	}
}

// TestNoCountryProfiles — упрощение: страновых профилей НЕТ, ссылка всегда
// с базовым UUID (страна = clients.country, меняется через API подписки/бот).
func TestNoCountryProfiles(t *testing.T) {
	m := MasterParams{Address: "example.com", Port: 443, SNI: "example.com", PublicKey: "pk", ShortID: "sid", Fingerprint: "chrome", Flow: "xtls-rprx-vision"}
	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	link := VlessLink(uuid, "ivan@test.ru", "Ivan", m)
	if !strings.Contains(link, "vless://"+uuid+"@example.com:443") {
		t.Errorf("ссылка не с базовым UUID: %s", link)
	}
	if strings.Contains(link, "[NL]") || strings.Contains(link, "-0001-") {
		t.Errorf("страновой профиль в ссылке (слой удалён): %s", link)
	}
}

func TestSubscription(t *testing.T) {
	links := []string{"vless://a@host:443#A", "vless://b@host:443#B"}
	sub := Subscription(links)
	if sub == "" {
		t.Error("empty subscription")
	}
	// base64 decode проверяем
	if !strings.Contains(sub, "=") && len(sub) < 10 {
		t.Errorf("bad base64: %s", sub)
	}
}

func TestClientLinks(t *testing.T) {
	m := MasterParams{Address: "example.com", Port: 443, SNI: "example.com", PublicKey: "pk", ShortID: "sid", Fingerprint: "chrome", Flow: "xtls-rprx-vision"}
	links := ClientLinks("b831381d-6324-4d53-ad4f-8cda48b30811", "ivan@test.ru", "Ivan", m)
	// одна базовая ссылка (страновые профили удалены)
	if len(links) != 1 {
		t.Errorf("ожидал 1 базовую ссылку, got %d", len(links))
	}
	// все с одним адресом мастера
	for _, l := range links {
		if !strings.Contains(l, "@example.com:443") {
			t.Errorf("ссылка не на мастер: %s", l)
		}
	}
}