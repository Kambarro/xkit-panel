package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kambarro/xkit-panel/internal/tunnel"
)

// Аудит #8: мастер без dns-секции и freedom domainStrategy=None → системный
// DNS отдаёт AAAA первым, IPv6 мёртв → таймауты. ensureMasterIPv4DNS лечит
// существующий config.json идемпотентно, не теряя чужие поля.
func TestEnsureMasterIPv4DNS(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	// живое состояние аудита: dns отсутствует, freedom без settings, чужие поля
	orig := `{"log":{"loglevel":"warning"},"inbounds":[{"tag":"vless-reality","port":443}],
	 "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"blackhole","protocol":"blackhole"},{"tag":"api","protocol":"freedom"},{"tag":"node-1","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":40581}]}}],
	 "routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","port":"0-65535","outboundTag":"direct"}]},
	 "customField":{"keep":true}}`
	if err := os.WriteFile(p, []byte(orig), 0644); err != nil {
		t.Fatal(err)
	}
	changed, err := ensureMasterIPv4DNS(p)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	data, _ := os.ReadFile(p)
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("файл не парсится: %v", err)
	}
	dns, _ := cfg["dns"].(map[string]any)
	if dns == nil || dns["queryStrategy"] != "UseIPv4" {
		t.Fatalf("dns=%v", cfg["dns"])
	}
	srv, _ := dns["servers"].([]any)
	if len(srv) != 2 || srv[0] != "1.1.1.1" || srv[1] != "8.8.8.8" {
		t.Errorf("servers=%v", dns["servers"])
	}
	for _, o := range cfg["outbounds"].([]any) {
		om := o.(map[string]any)
		st, _ := om["settings"].(map[string]any)
		if om["protocol"] == "freedom" && (st == nil || st["domainStrategy"] != "UseIPv4") {
			t.Errorf("freedom %v без UseIPv4: %v", om["tag"], om)
		}
		// socks-outbound каскада не тронут
		if om["tag"] == "node-1" {
			servers := st["servers"].([]any)
			s0 := servers[0].(map[string]any)
			if s0["address"] != "127.0.0.1" || s0["port"] != float64(40581) {
				t.Errorf("socks-outbound изменён: %v", om)
			}
		}
	}
	// чужие секции сохранены
	if cfg["customField"] == nil || cfg["routing"] == nil || cfg["inbounds"] == nil {
		t.Error("потеряны секции конфига")
	}
	// идемпотентно
	changed, err = ensureMasterIPv4DNS(p)
	if err != nil || changed {
		t.Errorf("повторный вызов: changed=%v err=%v", changed, err)
	}
	// существующий dns пользователя не затирается
	custom := `{"dns":{"servers":["9.9.9.9"],"queryStrategy":"UseIP"},"outbounds":[{"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}]}`
	os.WriteFile(p, []byte(custom), 0644)
	changed, _ = ensureMasterIPv4DNS(p)
	if changed {
		t.Error("существующий dns/freedom затёрт")
	}
}

// Аудит #10: шаблоны нод (provision/node_transport/mtu) обязаны нести
// dns UseIPv4 + freedom UseIPv4 — IPv6 на нодах тоже мёртв.
func TestNodeTemplatesIPv4(t *testing.T) {
	s := &Server{}
	cfg := s.buildNodeConfig(tunnel.Params{Transport: tunnel.TCPReality, Host: "node.example.com", Port: 443,
		UUID: "uuid-1", PublicKey: "pub", PrivateKey: "priv", ShortID: "ab12", SNI: "node.example.com"})
	var m map[string]any
	if err := json.Unmarshal([]byte(cfg), &m); err != nil {
		t.Fatalf("node cfg: %v", err)
	}
	assertIPv4Config(t, m)
}

func assertIPv4Config(t *testing.T, m map[string]any) {
	t.Helper()
	dns, _ := m["dns"].(map[string]any)
	if dns == nil || dns["queryStrategy"] != "UseIPv4" {
		t.Errorf("dns=%v want UseIPv4", m["dns"])
	}
	obs, _ := m["outbounds"].([]any)
	found := false
	for _, o := range obs {
		om := o.(map[string]any)
		if om["protocol"] == "freedom" {
			found = true
			st, _ := om["settings"].(map[string]any)
			if st == nil || st["domainStrategy"] != "UseIPv4" {
				t.Errorf("freedom без UseIPv4: %v", om)
			}
		}
	}
	if !found {
		t.Error("freedom outbound отсутствует")
	}
}
