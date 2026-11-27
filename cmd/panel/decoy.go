package main

import (
	"fmt"
	"net/http"
	"strings"
)

// DECOY / АНТИ-ПРОБИНГ (P1 #6, panels-research Remnawave Response Rules / Marzban HOME_PAGE_TEMPLATE).
// УРОК: корень и несуществующие пути НЕ должны выдавать VPN-панель (404 панели = палево).
// Отдаём правдоподобную заглушку обычного сайта. ТСПУ/сканеры видят «сайт», не панель.
// Реальная панель только по секретному пути (XKIT_SECRET_PATH), подписка по валидному subId.

// validSubID — формат subId: hex-токен (новые = 16 hex от randBytes(8)).
// УРОК (live-проверка): старые тест-клиенты могут иметь короткие subId (sub1/sub2) —
// НЕ ломаем их. Принимаем hex 4-32 символа; мусор/слова (admin, test, ../) отсекаем.
// Реальная защита — случайный токен (не угадать) + decoy на несуществующие в БД.
func validSubID(id string) bool {
	if len(id) < 4 || len(id) > 32 {
		return false
	}
	// BUG-07: legacy subId (sub1, sub2) — допускаем
	if strings.HasPrefix(id, "sub") && len(id) <= 6 {
		for _, c := range id[3:] {
			if c < '0' || c > '9' { return false }
		}
		return len(id) > 3
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// decoyResponse — правдоподобная заглушка обычного сайта (не VPN-панель).
// Для браузеров — HTML «сайт на обслуживании/обычный лендинг», для прочих — generic 200/404.
// Не раскрывает ни панель, ни подписку, ни Xray.
func decoyResponse(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")
	ua := strings.ToLower(r.UserAgent())
	isBrowser := strings.Contains(accept, "text/html") && (strings.Contains(ua, "mozilla") || strings.Contains(ua, "chrome") || strings.Contains(ua, "safari"))
	if isBrowser {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, decoyHTML)
		return
	}
	// не-браузер (сканер/зонд/бот): generic 404 как обычный сервер, без деталей
	w.Header().Set("Server", "nginx")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, "404 Not Found")
}

// decoyHTML — нейтральный лендинг (никаких намёков на VPN/панель/Xray).
const decoyHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Welcome</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;background:#f5f6f8;color:#222;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{max-width:520px;padding:2.5rem;text-align:center}
h1{font-size:1.6rem;font-weight:600;margin-bottom:.75rem;color:#1a1a2e}
p{color:#555;line-height:1.6;font-size:.95rem}
.dot{width:10px;height:10px;border-radius:50%;background:#3fb950;display:inline-block;margin-right:.4rem}
.footer{margin-top:2rem;font-size:.75rem;color:#999}
</style></head><body><div class="box">
<h1><span class="dot"></span>Service Online</h1>
<p>This server is operating normally. If you are looking for a specific resource, please check the address or contact the administrator.</p>
<div class="footer">Powered by nginx</div>
</div></body></html>`