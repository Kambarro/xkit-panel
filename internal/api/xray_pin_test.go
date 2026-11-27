package api

// Страж ИНВАРИАНТА деплоя: XRAY_PIN в install.sh == xrayPinnedVersion в Go.
// Разъезд = панель и бинарь xray на разных protobuf-схемах → ReplaceRules
// «invalid wire-format» (живой баг 2026-11-26). Соответствие go.mod проверяется
// при подъёме версии вручную (pseudo-version тега v<XRAY_PIN>).

import (
	"os"
	"regexp"
	"testing"
)

func TestXrayPinInvariant(t *testing.T) {
	data, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatalf("install.sh: %v", err)
	}
	m := regexp.MustCompile(`XRAY_PIN="([0-9]+\.[0-9]+\.[0-9]+)"`).FindSubmatch(data)
	if m == nil {
		t.Fatal("install.sh: XRAY_PIN не найден (latest запрещён — инвариант go.mod ↔ бинарь)")
	}
	if string(m[1]) != xrayPinnedVersion {
		t.Fatalf("install.sh XRAY_PIN=%s != xrayPinnedVersion=%s — синхронизируй ОБА + go.mod xray-core", m[1], xrayPinnedVersion)
	}
}
