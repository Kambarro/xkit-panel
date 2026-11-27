package main

import (
	"encoding/base64"
	"fmt"
	"html"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// amneziaSubPage — HTML страница AmneziaWG подписки: vpn:// кнопка + conf +
// ПРАВИЛЬНЫЙ multi-frame QR (Amnezia containers → Qt zlib → чанки '>hBBI').
// УРОК XKIT main (src/28): приложение Amnezia сканирует АНИМИРОВАННЫЙ multi-frame
// QR (каждый чанк = отдельный кадр, цикл 700мс). Простой vpn:// QR Amnezia НЕ
// распознаёт сканером — поэтому рендерим все чанки как кадры анимации.
// QR генерится в процессе (go-qrcode), внешний API запрещён.
func amneziaSubPage(conf, vpnLink string, chunks []string) string {
	// multi-frame QR: каждый чанк → PNG data URL, JS циклит кадры (700мс).
	var frames []string
	for _, c := range chunks {
		if png, err := qrcode.Encode(c, qrcode.Medium, 256); err == nil {
			frames = append(frames, "data:image/png;base64,"+base64.StdEncoding.EncodeToString(png))
		}
	}
	// fallback: если чанков нет — простой vpn:// QR (клик по кнопке всё равно импортирует)
	if len(frames) == 0 {
		if png, err := qrcode.Encode(vpnLink, qrcode.Medium, 256); err == nil {
			frames = append(frames, "data:image/png;base64,"+base64.StdEncoding.EncodeToString(png))
		}
	}
	var quoted []string
	for _, f := range frames {
		quoted = append(quoted, `"`+f+`"`)
	}
	framesJSON := "[" + strings.Join(quoted, ",") + "]"
	frameCount := len(frames)
	animNote := "Анимированный QR — держите камеру пока приложение не считает все кадры"
	if frameCount <= 1 {
		animNote = "Сканируйте QR в приложении Amnezia"
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>AmneziaWG — XKIT</title>
<style>
:root{--bg:#0a0e17;--card:#111726;--border:#1e2a45;--text:#e8f6ff;--muted:#7d8db0;--acc:#00f0ff;--acc2:#ff2ec4}
@media(prefers-color-scheme:light){:root{--bg:#f4f7fc;--card:#fff;--border:#d4deee;--text:#101828;--muted:#5b6b8c;--acc:#0aa8cc;--acc2:#8b2fd9}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);padding:1rem;min-height:100vh}
.wrap{max-width:560px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.25rem;margin-bottom:1rem}
h1{font-size:1.2rem;margin-bottom:.5rem}.muted{color:var(--muted);font-size:.85rem}
.btn{display:block;text-align:center;background:linear-gradient(90deg,var(--acc),var(--acc2));color:#04121a;border:none;border-radius:10px;padding:.8rem;font-size:.95rem;text-decoration:none;margin:.5rem 0;cursor:pointer;font-weight:600}
.btn-sec{background:var(--bg);border:1px solid var(--border);color:var(--acc)}
pre{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.75rem;font-size:.65rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto}
.qr{text-align:center;padding:.5rem 0}.qr img{background:#fff;padding:8px;border-radius:10px}
.qr-count{color:var(--muted);font-size:.75rem;margin-top:.4rem}
</style></head><body><div class="wrap">
<div class="card"><h1>🛡 AmneziaWG</h1><div class="muted">XKIT Panel · обфусцированный WireGuard</div></div>
<div class="card">
<a class="btn" href="%s">📲 Открыть в Amnezia (vpn://)</a>
<a class="btn btn-sec" href="?format=conf">⬇ Скачать .conf</a>
<div class="muted" style="margin:.5rem 0">%s:</div>
<div class="qr"><img id="awg-qr" src="" width="220" height="220" alt="QR"><div class="qr-count" id="awg-qr-count"></div></div>
</div>
<div class="card"><div class="muted" style="margin-bottom:.5rem">Конфиг (для ручного импорта):</div><pre>%s</pre></div>
<div class="muted" style="text-align:center;padding:1rem">XKIT Panel</div>
</div>
<script>
(function(){
  var frames=%s;
  var img=document.getElementById('awg-qr');
  var cnt=document.getElementById('awg-qr-count');
  if(!frames.length){return;}
  var i=0;
  function show(){
    img.src=frames[i];
    if(frames.length>1){cnt.textContent='кадр '+(i+1)+' / '+frames.length;}
    i=(i+1)%%frames.length;
  }
  show();
  if(frames.length>1){setInterval(show,700);}
})();
</script>
</body></html>`,
		html.EscapeString(vpnLink), html.EscapeString(animNote), html.EscapeString(conf), framesJSON)
}