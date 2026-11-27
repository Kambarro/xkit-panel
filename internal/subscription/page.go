package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"strings"
	"time"
)

// PageData — данные для браузерной страницы подписки.
type PageData struct {
	Name       string
	SubURL     string
	Links      []string
	QRDataURL  string // data:image/png;base64 (go-qrcode в процесс, внешний API запрещён)
	UsedBytes  int64
	QuotaBytes int64
	Expiry     int64
	Platform   string
	Locale     string
	Domain     string
	// P2 роутинг: наш дефолт + кастом клиента.
	RoutingMode    string // default | custom
	RoutingAllowed bool   // тумблер владельца
	RoutingDeeplink string // happ://routing/onadd/… (кнопка «Применить в Happ»)
	SubID          string // для публичного API роутинга
}

// RenderPage — HTML-страница подписки (УРОК: голый base64 в браузере бесполезен).
// Тёмная/светлая тема, QR, трафик/срок, кнопки приложений, инструкции по платформе.
// Образец UX — Kitsune internal/sub/page.go + connect.go.
func RenderPage(d PageData) string {
	en := d.Locale == "en"
	t := func(ru, enStr string) string {
		if en {
			return enStr
		}
		return ru
	}
	// трафик
	used := humanBytes(d.UsedBytes)
	quota := t("безлимит", "unlimited")
	pct := 0
	if d.QuotaBytes > 0 {
		quota = humanBytes(d.QuotaBytes)
		pct = int(float64(d.UsedBytes) / float64(d.QuotaBytes) * 100)
		if pct > 100 {
			pct = 100
		}
	}
	// срок
	expiry := t("бессрочно", "forever")
	if d.Expiry > 0 {
		days := int(time.Until(time.Unix(d.Expiry, 0)).Hours() / 24)
		if days > 1 {
			expiry = fmt.Sprintf(t("осталось %d дн.", "%d days left"), days)
		} else if days >= 0 {
			hours := int(time.Until(time.Unix(d.Expiry, 0)).Hours())
			expiry = fmt.Sprintf(t("осталось %d ч.", "%d hours left"), hours)
		} else {
			expiry = t("истёк", "expired")
		}
	}
	// ссылки с копированием: имя из remark (протокол + страна), не «Профиль N».
	linksHTML := ""
	for i, l := range d.Links {
		label := linkLabel(l, i, en)
		linksHTML += fmt.Sprintf(`<div class="link-card"><div class="link-label">%s</div><div class="link-row"><code class="link-url">%s</code><button class="copy-btn" onclick="copyText('%s')">%s</button></div></div>`,
			html.EscapeString(label), html.EscapeString(l), strings.ReplaceAll(l, "'", "\\'"), t("копировать", "copy"))
	}
	// инструкции по платформе
	apps := platformApps(d.Platform, en)
	appsHTML := ""
	for _, a := range apps {
		appsHTML += fmt.Sprintf(`<a class="app-btn" href="%s" target="_blank" rel="noopener">%s</a>`, a.URL, a.Name)
	}
	qrBlock := ""
	if d.QRDataURL != "" {
		qrBlock = fmt.Sprintf(`<div class="qr-wrap"><img src="%s" alt="QR" width="200" height="200"><div class="qr-hint">%s</div></div>`,
			d.QRDataURL, t("Сканируйте в приложении", "Scan in the app"))
	}
	trafficBar := ""
	if d.QuotaBytes > 0 {
		trafficBar = fmt.Sprintf(`<div class="progress"><div class="progress-fill" style="width:%d%%"></div></div>`, pct)
	}
	// P2 роутинг-блок: наш дефолт + кастом клиента (если разрешено владельцем).
	// УРОК (QA BUG-12): Happ-кнопка полезна и БЕЗ кастома (применяет наши правила) —
	// отдаём при непустом deeplink; редактор своих правил — только при разрешении.
	routingBlock := ""
	happBtn := ""
	if d.RoutingDeeplink != "" {
		happBtn = fmt.Sprintf(`<a class="app-btn" href="%s">📲 %s</a>`, html.EscapeString(d.RoutingDeeplink), t("Применить в Happ", "Apply in Happ"))
	}
	if d.RoutingAllowed || happBtn != "" {
		modeLabel := t("Наша (рекомендуется)", "Ours (recommended)")
		if d.RoutingMode == "custom" {
			modeLabel = t("Моя (кастомная)", "Mine (custom)")
		}
		editor := ""
		if d.RoutingAllowed {
		// редактор своих правил (клиент управляет сам, поверх нашего дефолта)
		editor = fmt.Sprintf(`<div style="margin-top:.75rem">
<button class="copy-btn" style="background:var(--cell);color:var(--acc);border:1px solid var(--border)" onclick="toggleRoutingEditor()">✎ %s</button>
<div id="routing-editor" style="display:none;margin-top:.75rem">
<div class="muted" style="font-size:.75rem;margin-bottom:.5rem">%s</div>
<div style="margin-bottom:.5rem"><label style="font-size:.8rem">%s</label><textarea id="rt-direct" rows="2" style="width:100%%;font-size:.75rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.5rem;color:var(--text)" placeholder="domain:mybank.ru"></textarea></div>
<div style="margin-bottom:.5rem"><label style="font-size:.8rem">%s</label><textarea id="rt-block" rows="2" style="width:100%%;font-size:.75rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.5rem;color:var(--text)" placeholder="domain:ads.example.com"></textarea></div>
<div style="margin-bottom:.5rem"><label style="font-size:.8rem">%s</label><textarea id="rt-proxy" rows="2" style="width:100%%;font-size:.75rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.5rem;color:var(--text)" placeholder="domain:youtube.com"></textarea></div>
<div style="display:flex;gap:.5rem"><button class="copy-btn" onclick="saveRouting('custom')">%s</button><button class="copy-btn" style="background:var(--cell);color:var(--muted);border:1px solid var(--border)" onclick="saveRouting('default')">%s</button></div>
<div id="rt-msg" style="font-size:.75rem;margin-top:.5rem"></div>
</div></div>`,
			t("Редактировать мои правила", "Edit my rules"),
			t("По одному правилу в строке. Наши правила работают всегда, ваши добавляются поверх.", "One rule per line. Our rules always apply, yours are added on top."),
			t("Напрямую (мимо VPN):", "Direct (bypass VPN):"),
			t("Блокировать:", "Block:"),
			t("Через VPN:", "Through VPN:"),
			t("Сохранить мои", "Save mine"),
			t("Вернуть ваши", "Reset to yours"))
		}
		routingBlock = fmt.Sprintf(`<div class="card"><div class="section-title">🧭 %s</div>
<div class="muted" style="margin-bottom:.5rem">%s</div>
<div class="stat-row"><span>%s</span><b id="rt-mode">%s</b></div>
<div style="margin:.5rem 0">%s</div>
%s
<div class="muted" style="font-size:.75rem;margin-top:.5rem">%s</div></div>`,
			t("Маршрутизация", "Routing"),
			t("Какие сайты идут через VPN, какие напрямую. Наша настройка работает по умолчанию.", "Which sites go through VPN and which direct. Our setup works by default."),
			t("Режим", "Mode"), modeLabel, happBtn, editor,
			t("Правила владельца на сервере всегда приоритетны и не изменяются.", "Owner's server-side rules always take priority and cannot be changed."))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>%s — XKIT</title>
<style>
:root{--bg:#0a0e1a;--card:#11162a;--border:#1e2745;--text:#f2fbff;--muted:#8b94ad;--acc:#00E5FF;--acc2:#B026FF;--ok:#00ffa3;--warn:#ffb020;--bad:#ff3b6b}
@media(prefers-color-scheme:light){:root{--bg:#f6f8fa;--card:#fff;--border:#d0d7de;--text:#1f2328;--muted:#656d76;--acc:#0aa8cc;--acc2:#8B2FD9}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:1rem;background-image:radial-gradient(circle at 12%% 0%%,rgba(0,229,255,.05),transparent 42%%),radial-gradient(circle at 88%% 100%%,rgba(176,38,255,.05),transparent 42%%);background-attachment:fixed}
@media(prefers-color-scheme:light){body{background-image:none}}
.wrap{max-width:560px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.25rem;margin-bottom:1rem;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--acc),var(--acc2));opacity:.5}
h1{font-size:1.25rem;margin-bottom:.25rem}.muted{color:var(--muted);font-size:.85rem}
.stat-row{display:flex;justify-content:space-between;margin:.5rem 0;font-size:.9rem}
.progress{height:8px;background:var(--border);border-radius:4px;overflow:hidden;margin:.5rem 0}
.progress-fill{height:100%%;background:var(--acc);border-radius:4px}
.qr-wrap{text-align:center;padding:1rem 0}.qr-wrap img{border-radius:10px;background:#fff;padding:8px}
.qr-hint{color:var(--muted);font-size:.8rem;margin-top:.5rem}
.link-card{margin:.75rem 0}.link-label{font-size:.8rem;color:var(--muted);margin-bottom:.25rem}
.link-row{display:flex;gap:.5rem;align-items:center}
.link-url{flex:1;font-size:.7rem;word-break:break-all;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.5rem;max-height:4.5em;overflow:hidden}
.copy-btn{background:var(--acc);color:#fff;border:none;border-radius:8px;padding:.5rem .75rem;font-size:.8rem;cursor:pointer;white-space:nowrap}
.app-btn{display:inline-block;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.5rem .9rem;margin:.25rem;font-size:.85rem;color:var(--acc);text-decoration:none}
.section-title{font-size:.95rem;font-weight:600;margin:1rem 0 .5rem}
.sub-url{font-size:.75rem;word-break:break-all;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.6rem;margin:.5rem 0}
.toast{position:fixed;bottom:1.5rem;left:50%%;transform:translateX(-50%%);background:var(--ok);color:#fff;padding:.5rem 1rem;border-radius:8px;font-size:.85rem;opacity:0;transition:opacity .3s;pointer-events:none}
.toast.show{opacity:1}
</style></head><body><div class="wrap">
<div class="card"><h1><svg viewBox="0 0 100 100" width="30" height="30" style="vertical-align:middle;margin-right:8px;filter:drop-shadow(0 0 5px rgba(0,229,255,.35))"><rect x="28" y="56" width="20" height="11" rx="3" fill="#B026FF"/><rect x="52" y="56" width="20" height="11" rx="3" fill="#B026FF"/><rect x="22" y="70" width="16" height="11" rx="3" fill="#B026FF"/><rect x="42" y="70" width="20" height="11" rx="3" fill="#B026FF"/><rect x="66" y="70" width="12" height="11" rx="3" fill="#B026FF"/><polyline points="8,70 22,40 50,26 74,38" fill="none" stroke="#00E5FF" stroke-width="8.5" stroke-linecap="round" stroke-linejoin="round"/><circle cx="8" cy="70" r="5.5" fill="#00E5FF"/><polygon points="93,62 76.5,49.5 84,40" fill="#00E5FF"/></svg><span style="background:linear-gradient(90deg,var(--acc),var(--acc2));-webkit-background-clip:text;background-clip:text;color:transparent">%s</span></h1><div class="muted">%s · %s</div></div>
<div class="card">
<div class="stat-row"><span>%s</span><b>%s / %s</b></div>%s
<div class="stat-row"><span>%s</span><b>%s</b></div>
</div>
%s
<div class="card"><div class="section-title">🌍 %s</div><div class="muted" style="margin-bottom:.5rem">%s</div>
<select id="country-sel" onchange="saveCountry(this.value)" style="width:100%%;padding:.5rem;border-radius:8px;background:var(--bg);color:var(--text);border:1px solid var(--border);font-size:.9rem"><option>…</option></select>
<div id="country-msg" class="muted" style="margin-top:.4rem;font-size:.8rem"></div></div>
<div class="card"><div class="section-title">%s</div>%s</div>
%s
<div class="card"><div class="section-title">%s</div><div class="muted" style="margin-bottom:.5rem">%s</div>%s</div>
<div class="card"><div class="section-title">%s</div><div class="sub-url">%s</div><button class="copy-btn" onclick="copyText('%s')">%s</button></div>
<div class="muted" style="text-align:center;padding:1rem">XKIT Panel · %s</div>
</div>
<div class="toast" id="toast">%s</div>
<script>
function copyText(t){
  var done=function(){const e=document.getElementById('toast');if(e){e.classList.add('show');setTimeout(()=>e.classList.remove('show'),1500);}};
  var fallback=function(){try{const ta=document.createElement('textarea');ta.value=t;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);done();}catch(e){}};
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done).catch(fallback);}else{fallback();}
}
var SUB_ROUTING_URL=location.pathname.replace(/\/$/,'')+'/routing';
var SUB_COUNTRY_URL=location.pathname.replace(/\/$/,'')+'/country';
function loadCountry(){
  fetch(SUB_COUNTRY_URL).then(r=>r.json()).then(d=>{
    var sel=document.getElementById('country-sel');
    var opts='<option value="any">Any — '+(document.documentElement.lang==='en'?'best node':'лучшая нода')+'</option>';
    (d.available||[]).forEach(c=>{opts+='<option value="'+c.country+'">'+c.country+'</option>';});
    sel.innerHTML=opts;sel.value=d.country||'any';
  }).catch(()=>{});
}
function saveCountry(c){
  var msg=document.getElementById('country-msg');
  fetch(SUB_COUNTRY_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({country:c})}).then(r=>{
    if(r.ok){msg.style.color='var(--ok)';msg.textContent=document.documentElement.lang==='en'?'✓ Applied. Refresh subscription in your app.':'✓ Применено. Обновите подписку в приложении.';setTimeout(()=>location.reload(),1200);}
    else{r.text().then(t=>{msg.style.color='#f85149';msg.textContent=t;});}
  });
}
loadCountry();
function parseLines(id){return (document.getElementById(id).value||'').split('\n').map(s=>s.trim()).filter(Boolean);}
function toggleRoutingEditor(){
  var ed=document.getElementById('routing-editor');
  if(ed.style.display==='none'){
    fetch(SUB_ROUTING_URL).then(r=>r.json()).then(d=>{
      var ru=d.rules||{};
      document.getElementById('rt-direct').value=(ru.direct_sites||[]).join('\n');
      document.getElementById('rt-block').value=(ru.block_sites||[]).join('\n');
      document.getElementById('rt-proxy').value=(ru.proxy_sites||[]).join('\n');
      ed.style.display='block';
    });
  } else { ed.style.display='none'; }
}
function saveRouting(mode){
  var body={mode:mode,rules:{direct_sites:parseLines('rt-direct'),block_sites:parseLines('rt-block'),proxy_sites:parseLines('rt-proxy')}};
  fetch(SUB_ROUTING_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>{
    var msg=document.getElementById('rt-msg');
    if(r.ok){msg.style.color='var(--ok)';msg.textContent=mode==='custom'?'✓ Сохранено. Обновите подписку в приложении.':'✓ Возвращены наши правила.';document.getElementById('rt-mode').textContent=mode==='custom'?'Моя (кастомная)':'Наша (рекомендуется)';}
    else{r.text().then(t=>{msg.style.color='var(--bad)';msg.textContent='Ошибка: '+t;});}
  });
}
</script></body></html>`,
		d.Locale, html.EscapeString(d.Name),
		html.EscapeString(d.Name), t("Подписка", "Subscription"), html.EscapeString(d.Domain),
		t("Трафик", "Traffic"), used, quota, trafficBar,
		t("Срок", "Expires"), expiry,
		qrBlock,
		t("Страна выхода", "Exit country"), t("Any — лучшая нода автоматически. Смена страны применяется сразу; обновите подписку в приложении.", "Any — best node automatically. Country change applies instantly; refresh the subscription in your app."),
		t("Ссылки для импорта", "Import links"), linksHTML,
		routingBlock,
		t("Приложения", "Apps"), t("Установите приложение и импортируйте ссылку или сканируйте QR:", "Install an app and import the link or scan the QR:"), appsHTML,
		t("URL подписки (автообновление)", "Subscription URL (auto-update)"), html.EscapeString(d.SubURL), d.SubURL, t("копировать URL", "copy URL"),
		html.EscapeString(d.Domain),
		t("Скопировано", "Copied"))
}

// linkLabel — человекочитаемое имя ссылки из remark (#фрагмент) или протокола.
// УРОК (владелец): «просто подписи Профиль 2/3/4» — непонятно. Показываем протокол+страну.
func linkLabel(link string, idx int, en bool) string {
	// remark после # (URL-encoded): "ProtoTest [NL] (vless-xhttp)"
	if i := strings.Index(link, "#"); i >= 0 && i+1 < len(link) {
		if rem, err := url.PathUnescape(link[i+1:]); err == nil && rem != "" {
			// уберём имя клиента (до первого " [") — оставим страну+протокол
			if j := strings.Index(rem, " ["); j > 0 {
				rem = rem[j+1:] // "[NL] (vless-xhttp)"
			}
			rem = strings.TrimSpace(rem)
			if rem != "" {
				return rem
			}
		}
	}
	// fallback: протокол из схемы
	scheme := link
	if i := strings.Index(link, "://"); i > 0 {
		scheme = link[:i]
	}
	if scheme == "vmess" {
		// vmess: base64 JSON → ps (remark со страной) или net
		if b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://")); err == nil {
			var obj map[string]any
			if json.Unmarshal(b, &obj) == nil {
				if ps, _ := obj["ps"].(string); ps != "" {
					if j := strings.Index(ps, " ["); j > 0 {
						return strings.TrimSpace(ps[j+1:])
					}
					return ps
				}
				net, _ := obj["net"].(string)
				if net != "" && net != "tcp" {
					return "vmess-" + net
				}
			}
		}
	}
	if scheme != "" && scheme != link {
		return scheme
	}
	if en {
		return fmt.Sprintf("Server %d", idx+1)
	}
	return fmt.Sprintf("Сервер %d", idx+1)
}

type appLink struct{ Name, URL string }

func platformApps(platform string, en bool) []appLink {
	switch platform {
	case "ios":
		return []appLink{
			{"Streisand", "https://apps.apple.com/app/streisand/id6450534064"},
			{"Shadowrocket", "https://apps.apple.com/app/shadowrocket/id932747118"},
			{"Hiddify", "https://apps.apple.com/app/hiddify-proxy-vpn/id6596777532"},
			{"V2Box", "https://apps.apple.com/app/v2box-v2ray-client/id6446814690"},
		}
	case "android":
		return []appLink{
			{"v2rayNG", "https://play.google.com/store/apps/details?id=com.v2ray.ang"},
			{"Hiddify", "https://play.google.com/store/apps/details?id=app.hiddify.com"},
			{"NekoBox", "https://github.com/MatsuriDayo/NekoBoxForAndroid/releases"},
			{"Clash Meta", "https://github.com/MetaCubeX/ClashMetaForAndroid/releases"},
		}
	case "windows":
		return []appLink{
			{"v2rayN", "https://github.com/2dust/v2rayN/releases"},
			{"Hiddify", "https://github.com/hiddify/hiddify-app/releases"},
			{"Clash Verge", "https://github.com/clash-verge-rev/clash-verge-rev/releases"},
			{"NekoRay", "https://github.com/MatsuriDayo/nekoray/releases"},
		}
	case "mac":
		return []appLink{
			{"Hiddify", "https://github.com/hiddify/hiddify-app/releases"},
			{"Clash Verge", "https://github.com/clash-verge-rev/clash-verge-rev/releases"},
			{"V2Box", "https://apps.apple.com/app/v2box-v2ray-client/id6446814690"},
		}
	}
	// unknown — все платформы
	return []appLink{
		{"v2rayNG (Android)", "https://play.google.com/store/apps/details?id=com.v2ray.ang"},
		{"Streisand (iOS)", "https://apps.apple.com/app/streisand/id6450534064"},
		{"v2rayN (Windows)", "https://github.com/2dust/v2rayN/releases"},
		{"Hiddify", "https://github.com/hiddify/hiddify-app/releases"},
	}
}

func humanBytes(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}