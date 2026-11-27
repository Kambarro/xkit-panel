package api

// Баг expert-флага (2026-11-26): GET settings отдавал value не строкой '1' →
// строгое ==='1' на фронте сбрасывало expertMode. Фикс двусторонний:
// POST нормализует любое truthy-значение в канон '1'/'' (truthySetting),
// GET возвращает канон. Плюс версии компонентов hysteria/AWG (display only).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTruthySetting(t *testing.T) {
	truthy := []any{"1", "true", "TRUE", "on", "yes", " 1 ", true, float64(1)}
	for _, v := range truthy {
		if !truthySetting(v) {
			t.Errorf("truthySetting(%v) = false, want true", v)
		}
	}
	falsy := []any{"", "0", "false", "off", "no", "2", false, float64(0), nil}
	for _, v := range falsy {
		if truthySetting(v) {
			t.Errorf("truthySetting(%v) = true, want false", v)
		}
	}
}

// TestExpertModeSettingsNormalize — POST expert_mode строкой/числом/bool
// персистит канон '1'; GET отдаёт '1'. Выключение любым falsy → ''.
func TestExpertModeSettingsNormalize(t *testing.T) {
	s := testStoreAPI(t)
	srv := NewServer(s, nil, "test", "test.local")
	for _, body := range []string{
		`{"key":"expert_mode","value":"1"}`,
		`{"key":"expert_mode","value":1}`,
		`{"key":"expert_mode","value":true}`,
		`{"key":"expert_mode","value":"true"}`,
		`{"key":"expert_mode","value":"on"}`,
	} {
		w := httptest.NewRecorder()
		srv.setSettings(w, httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(body)))
		if w.Code != 200 {
			t.Fatalf("POST %s: code %d", body, w.Code)
		}
		if got := s.GetSetting("expert_mode", ""); got != "1" {
			t.Errorf("POST %s: stored %q, want \"1\"", body, got)
		}
		w = httptest.NewRecorder()
		srv.getSettings(w, httptest.NewRequest(http.MethodGet, "/api/settings?key=expert_mode", nil))
		var d map[string]string
		json.Unmarshal(w.Body.Bytes(), &d)
		if d["value"] != "1" {
			t.Errorf("GET after %s: value %q, want \"1\"", body, d["value"])
		}
	}
	for _, body := range []string{
		`{"key":"expert_mode","value":""}`,
		`{"key":"expert_mode","value":0}`,
		`{"key":"expert_mode","value":false}`,
		`{"key":"expert_mode","value":"0"}`,
	} {
		w := httptest.NewRecorder()
		srv.setSettings(w, httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(body)))
		if w.Code != 200 {
			t.Fatalf("POST %s: code %d", body, w.Code)
		}
		if got := s.GetSetting("expert_mode", "x"); got != "" {
			t.Errorf("POST %s: stored %q, want \"\"", body, got)
		}
	}
	// locale/theme по-прежнему строками; нестроковое значение игнорируется (не 400)
	w := httptest.NewRecorder()
	srv.setSettings(w, httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(`{"locale":"en","theme":5}`)))
	if w.Code != 200 {
		t.Fatalf("mixed POST: code %d", w.Code)
	}
	if s.GetSetting("locale", "") != "en" {
		t.Error("locale not stored")
	}
	if s.GetSetting("theme", "") != "" {
		t.Error("non-string theme must be ignored")
	}
}

// TestHysteriaComponentViaXray — без standalone hysteria-server компонент
// называется «hysteria2 (via xray)», current/latest = версии xray, без Update.
func TestHysteriaComponentViaXray(t *testing.T) {
	c := hysteriaComponent("26.11.9", "26.11.9")
	if c.Name == "hysteria" {
		t.Skip("standalone hysteria-server установлен — via-xray ветка не проверяется")
	}
	if c.Name != "hysteria2 (via xray)" {
		t.Errorf("name = %q", c.Name)
	}
	if c.Current != "26.11.9" || c.Latest != "26.11.9" {
		t.Errorf("versions must follow xray: %+v", c)
	}
	if c.Update {
		t.Error("via-xray компонент не должен предлагать отдельное обновление")
	}
}

// TestAwgComponentFromBuildInfo — current берётся из go.mod (BuildInfo),
// совпадает с реальным тегом v3.x. Сетевой latest не проверяем (офлайн-CI).
func TestAwgComponentFromBuildInfo(t *testing.T) {
	c := awgComponent()
	if c.Name != "AmneziaWG (встроена)" {
		t.Errorf("name = %q", c.Name)
	}
	if !strings.HasPrefix(c.Current, "3.") {
		t.Errorf("current из BuildInfo = %q, want 3.x (go.mod amneziawg-go/v3)", c.Current)
	}
}