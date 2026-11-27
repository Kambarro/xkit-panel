package subscription

import (
	"fmt"
	"strings"
)

// Userinfo — реальные данные клиента для заголовка Subscription-Userinfo.
// УРОК (исследование): в панели было захардкожено upload=0;download=0;total=0;expire=0 —
// клиенты не видели квоту/срок. Теперь из БД (used_bytes/quota_bytes/expiry).
type Userinfo struct {
	Upload   int64
	Download int64
	Total    int64 // quota_bytes, 0 = безлимит
	Expire   int64 // unix ts, 0 = бессрочно
}

// Header формирует значение Subscription-Userinfo (формат клиентов v2rayNG/Hiddify/etc).
func (u Userinfo) Header() string {
	return fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", u.Upload, u.Download, u.Total, u.Expire)
}

// DetectFormat — UA-детект формата подписки (паттерн Kitsune internal/sub).
// УРОК: hiddify→raw (Hiddify 4.x ЛОМАЕТСЯ на Clash-YAML!), incy→xray-json,
// sing-box→singbox, clash/mihomo→clash; ?format= приоритетнее UA.
// wantsPage: браузер (Accept:text/html + Mozilla) → HTML-страница вместо base64.
func DetectFormat(userAgent, accept, queryFormat string) (format string, wantsPage bool) {
	// явный ?format= приоритетнее всего; неизвестный → invalid (handler отдаст 400,
	// QA BUG-12: format=bogus молча отдавал raw)
	switch strings.ToLower(queryFormat) {
	case "":
		// нет явного формата — UA-логика ниже
	case "raw", "base64":
		return "raw", false
	case "clash", "yaml":
		return "clash", false
	case "singbox", "sing-box", "json":
		return "singbox", false
	case "xray", "xray-json":
		return "xray", false
	case "page", "html":
		return "raw", true
	default:
		return "invalid", false
	}
	ua := strings.ToLower(userAgent)
	// браузерная страница: Accept содержит text/html И UA похож на браузер
	if strings.Contains(strings.ToLower(accept), "text/html") &&
		(strings.Contains(ua, "mozilla") || strings.Contains(ua, "chrome") || strings.Contains(ua, "safari")) &&
		!isClientUA(ua) {
		return "raw", true
	}
	// клиентские приложения (порядок важен: hiddify раньше clash!)
	switch {
	case strings.Contains(ua, "hiddify"):
		return "raw", false // Hiddify 4.x ломается на Clash-YAML
	case strings.Contains(ua, "incy"):
		return "raw", false // incy xray-json parser не поддерживает multi-outbound; raw base64 = все ссылки
	case strings.Contains(ua, "sing-box"), strings.Contains(ua, "singbox"),
		strings.Contains(ua, "sfa"), strings.Contains(ua, "sfi"), strings.Contains(ua, "sfm"), strings.Contains(ua, "sft"):
		return "singbox", false
	case strings.Contains(ua, "clash"), strings.Contains(ua, "mihomo"), strings.Contains(ua, "flclash"),
		strings.Contains(ua, "stash"), strings.Contains(ua, "nyanpasu"), strings.Contains(ua, "verge"), strings.Contains(ua, "meta"):
		return "clash", false
	case strings.Contains(ua, "v2ray"), strings.Contains(ua, "v2rayng"), strings.Contains(ua, "nekobox"),
		strings.Contains(ua, "nekoray"), strings.Contains(ua, "streisand"), strings.Contains(ua, "karing"),
		strings.Contains(ua, "shadowrocket"), strings.Contains(ua, "quantumult"), strings.Contains(ua, "loon"),
		strings.Contains(ua, "surfboard"), strings.Contains(ua, "happ"):
		return "raw", false
	}
	return "raw", false
}

func isClientUA(ua string) bool {
	for _, k := range []string{"hiddify", "clash", "mihomo", "sing-box", "singbox", "v2ray", "nekobox",
		"nekoray", "streisand", "karing", "shadowrocket", "quantumult", "loon", "surfboard", "happ", "incy", "sfa", "sfi"} {
		if strings.Contains(ua, k) {
			return true
		}
	}
	return false
}

// PlatformByUA — платформа для инструкций подключения (паттерн Kitsune connect.go).
func PlatformByUA(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "iphone"), strings.Contains(ua, "ipad"), strings.Contains(ua, "ios"):
		return "ios"
	case strings.Contains(ua, "android"):
		return "android"
	case strings.Contains(ua, "windows"):
		return "windows"
	case strings.Contains(ua, "mac os"), strings.Contains(ua, "macintosh"):
		return "mac"
	case strings.Contains(ua, "linux"):
		return "linux"
	}
	return "unknown"
}