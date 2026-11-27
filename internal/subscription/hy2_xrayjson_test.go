package subscription

// Остаток Ops b737b05: hy2 в xray-json подписке — auth 404 у клиента.
// HysteriaClientConfig ядра 26.11.9 = {version,address,port}: settings.auth
// молча дропается, транспорт читает ТОЛЬКО stream.hysteriaSettings.auth;
// obfs=salamander обязан транслироваться в finalmask.udp[].
// E2E с реальным клиентом: internal/api TestXrayJSONHy2SubscriptionE2E.

import (
	"encoding/json"
	"testing"
)

func TestXrayJSONHy2AuthAndFinalmask(t *testing.T) {
	l := "hysteria2://authpass@vpn.example.com:8443?sni=vpn.example.com&obfs=salamander&obfs-password=obfspass#Hy2"
	for name, gen := range map[string]func([]string) string{
		"default":  XrayJSON,
		"profiles": func(ls []string) string { return XrayJSONProfiles(ls, nil) },
	} {
		var cfg map[string]any
		if err := json.Unmarshal([]byte(gen([]string{l})), &cfg); err != nil {
			t.Fatalf("%s: invalid JSON: %v", name, err)
		}
		ob := cfg["outbounds"].([]any)[0].(map[string]any)
		if ob["protocol"] != "hysteria" {
			t.Errorf("%s: protocol=%v want hysteria", name, ob["protocol"])
		}
		settings := ob["settings"].(map[string]any)
		if _, bad := settings["auth"]; bad {
			t.Errorf("%s: auth в settings — ядро его дропает (auth 404)", name)
		}
		stream := ob["streamSettings"].(map[string]any)
		hy, ok := stream["hysteriaSettings"].(map[string]any)
		if !ok || hy["auth"] != "authpass" || hy["version"] != float64(2) {
			t.Errorf("%s: hysteriaSettings=%v want {version:2,auth:authpass}", name, stream["hysteriaSettings"])
		}
		fm, ok := stream["finalmask"].(map[string]any)
		if !ok {
			t.Fatalf("%s: finalmask отсутствует — salamander не транслирован", name)
		}
		m0 := fm["udp"].([]any)[0].(map[string]any)
		if m0["type"] != "salamander" || m0["settings"].(map[string]any)["password"] != "obfspass" {
			t.Errorf("%s: finalmask.udp[0]=%v", name, m0)
		}
	}
	// без obfs в ссылке — finalmask не навязываем
	var cfg map[string]any
	json.Unmarshal([]byte(XrayJSON([]string{"hysteria2://authpass@vpn.example.com:8443?sni=vpn.example.com#Hy2"})), &cfg)
	stream := cfg["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	if _, has := stream["finalmask"]; has {
		t.Error("finalmask без obfs в ссылке")
	}
}
