package subscription

import (
	"strings"
	"testing"
)

// TestPageHappButtonWithoutCustom — BUG-12 (LOW, QA): при allow_custom_routing=0
// кнопка «Применить в Happ» не отдавалась, хотя deeplink полезен и без кастома
// (наши дефолтные правила). Кнопка обязана быть при непустом deeplink; редактор
// своих правил — только при RoutingAllowed.
func TestPageHappButtonWithoutCustom(t *testing.T) {
	d := PageData{Name: "client", SubURL: "https://m.com/s/x", Links: []string{testVlessWS},
		Locale: "ru", Domain: "m.com", RoutingAllowed: false, RoutingMode: "default",
		RoutingDeeplink: "happ://routing/onadd/abc"}
	page := RenderPage(d)
	if !strings.Contains(page, `href="happ://routing/onadd/abc"`) {
		t.Error("Happ-кнопка не отдана при allow_custom_routing=0 (deeplink полезен и без кастома)")
	}
	if strings.Contains(page, `id="routing-editor"`) {
		t.Error("редактор кастомных правил показан при запрете владельца")
	}
	// с разрешением — редактор есть
	d.RoutingAllowed = true
	page = RenderPage(d)
	if !strings.Contains(page, `id="routing-editor"`) || !strings.Contains(page, `href="happ://routing/onadd/abc"`) {
		t.Error("при RoutingAllowed должны быть и редактор, и Happ-кнопка")
	}
}

// TestDetectFormatUnknownQuery — BUG-12: ?format=bogus молча отдавал raw.
// Неизвестный явный format → "invalid" (handler отдаст 400).
func TestDetectFormatUnknownQuery(t *testing.T) {
	if f, _ := DetectFormat("SomeApp/1.0", "*/*", "bogus"); f != "invalid" {
		t.Errorf("format=bogus → %q, want invalid (400)", f)
	}
	// пустой format — обычная UA-логика
	if f, _ := DetectFormat("SomeApp/1.0", "*/*", ""); f != "raw" {
		t.Errorf("пустой format → %q, want raw", f)
	}
}