package balancer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestStripLegacyCountryRules — миграция упрощения: cs:/cspd:/cspi: правила и
// per-user vlessRoute вырезаются из config.json при старте; базовые c:, afp,
// api/survey/catch-all и порядок сохраняются; идемпотентно.
func TestStripLegacyCountryRules(t *testing.T) {
	cfg := `{"routing":{"domainStrategy":"IPIfNonMatch","rules":[
		{"type":"field","inboundTag":["api-in"],"outboundTag":"api","ruleTag":"api"},
		{"type":"field","user":["a@b.c"],"vlessRoute":"1","outboundTag":"node-nl-1","ruleTag":"cs:a@b.c:NL"},
		{"type":"field","user":["a@b.c"],"vlessRoute":"3","domain":["ext:geosite-ru-only.dat:ru-blocked"],"outboundTag":"node-us-1","ruleTag":"cspd:a@b.c:US"},
		{"type":"field","user":["a@b.c"],"vlessRoute":"3","ip":["ext:xkit-blocked.dat:xkit-blocked"],"outboundTag":"node-us-1","ruleTag":"cspi:a@b.c:US"},
		{"type":"field","user":["a@b.c"],"outboundTag":"node-nl-1","ruleTag":"c:a@b.c:NL"},
		{"type":"field","user":["a@b.c"],"domain":["ext:geosite-ru-only.dat:ru-blocked"],"outboundTag":"node-nl-1","ruleTag":"afpd:a@b.c"},
		{"type":"field","inboundTag":["survey-x"],"outboundTag":"node-nl-1","ruleTag":"survey:survey-x"},
		{"type":"field","port":"0-65535","outboundTag":"direct"}
	]}}`
	p := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(p, []byte(cfg), 0644)
	old := masterConfigPath
	masterConfigPath = p
	t.Cleanup(func() { masterConfigPath = old })

	if n := StripLegacyCountryRules(); n != 3 {
		t.Fatalf("снято %d, want 3 (cs/cspd/cspi)", n)
	}
	data, _ := os.ReadFile(p)
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	rules := parsed["routing"].(map[string]any)["rules"].([]any)
	var tags []string
	for _, r := range rules {
		rm := r.(map[string]any)
		tag, _ := rm["ruleTag"].(string)
		tags = append(tags, tag)
		if _, has := rm["vlessRoute"]; has {
			t.Fatalf("vlessRoute пережил миграцию: %v", rm)
		}
	}
	want := []string{"api", "c:a@b.c:NL", "afpd:a@b.c", "survey:survey-x", ""}
	if len(tags) != len(want) {
		t.Fatalf("tags=%v, want %v", tags, want)
	}
	for i := range want {
		if tags[i] != want[i] {
			t.Fatalf("порядок нарушен: %v, want %v", tags, want)
		}
	}
	// идемпотентно: повторный вызов ничего не снимает и не переписывает файл
	before, _ := os.ReadFile(p)
	if n := StripLegacyCountryRules(); n != 0 {
		t.Fatalf("повторный strip снял %d, want 0", n)
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Fatal("повторный strip переписал файл")
	}
}