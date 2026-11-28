// Command panel — XKIT Panel: Go-панель VPN с own sticky-балансировщиком поверх Xray gRPC.
// Один статический бинарь (CGO off), embed UI, SQLite store, chi API.
// Маскировка: nginx+camo фронт, панель только по секретному пути (XKIT_SECRET_PATH).
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/kambarro/xkit-panel/internal/api"
	"github.com/kambarro/xkit-panel/internal/antifilter"
	"github.com/kambarro/xkit-panel/internal/auth"
	"github.com/kambarro/xkit-panel/internal/backup"
	"github.com/kambarro/xkit-panel/internal/balancer"
	"github.com/kambarro/xkit-panel/internal/notify"
	"github.com/kambarro/xkit-panel/internal/routing"
	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/amnezia"
	"github.com/kambarro/xkit-panel/internal/subscription"
	"github.com/kambarro/xkit-panel/internal/xray"
)

//go:embed web/*
var webFS embed.FS

const Version = "1.0.4"

func main() {
	// RESCUE-CLI (P1 #7, panels-research Remnawave rescue-cli / Hiddify CLI / 3x-ui меню).
	// УРОК (владелец): «забыла пароль / панель не открывается» — без паники и SSH-экспедиций.
	// Подкоманды: reset-password, admin-url, status, restore. Только через SSH на сервер.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "reset-password", "admin-url", "status", "restore", "help", "--help", "-h":
			runRescueCLI(os.Args[1])
			return
		}
	}
	var (
		listen   = flag.String("listen", env("XKIT_LISTEN", "127.0.0.1:8080"), "HTTP listen addr")
		dbPath   = flag.String("db", env("XKIT_DB", "/var/lib/xkit-panel/panel.db"), "SQLite path")
		xrayAddr = flag.String("xray", env("XKIT_XRAY_API", "127.0.0.1:62789"), "Xray gRPC API addr")
		secret   = flag.String("secret", env("XKIT_SECRET_PATH", ""), "secret URL path prefix (camo)")
		domain   = flag.String("domain", env("XKIT_DOMAIN", "localhost"), "public domain")
		seed     = flag.Bool("seed", false, "seed demo data (nodes/clients)")
	)
	flag.Parse()

	if err := os.MkdirAll(parentDir(*dbPath), 0750); err != nil {
		log.Fatalf("db dir: %v", err)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	// SEC-03: tunnel_uuid каскада — из tunnel.env (install.sh), иначе crypto/rand.
	// Никаких хардкод-дефолтов: общий предсказуемый UUID = доступ к каскаду.
	initTunnelUUID(st, parentDir(*dbPath))

	// Xray gRPC (может быть недоступен при первом старте — не фатально)
	var xc *xray.Client
	if c, err := xray.Dial(*xrayAddr); err != nil {
		log.Printf("WARN xray gRPC %s недоступен: %v (панель работает, балансировщик ждёт Xray)", *xrayAddr, err)
	} else {
		xc = c
		defer xc.Close()
		log.Printf("Xray gRPC подключен: %s", *xrayAddr)
	}

	if *seed {
		seedDemo(st)
	}

	srv := api.NewServer(st, xc, Version, *domain)
	// REALITY параметры мастера для подписок (из env)
	srv.SetMaster(subscription.MasterParams{
		Address: *domain, Port: 443, SNI: *domain,
		PublicKey: env("XKIT_REALITY_PUB", ""), ShortID: env("XKIT_REALITY_SID", ""),
		Fingerprint: "chrome", Flow: "xtls-rprx-vision",
	})
	mux := http.NewServeMux()

	// BALANCER CONTROLLER: панель сама управляет Xray routing через gRPC.
	var ctrl *balancer.Controller
	if xc != nil {
		ctrl = balancer.NewController(st, xc)
		ctrl.InboundTag = env("XKIT_INBOUND_TAG", "vless-reality")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctrl.Start(ctx)
		ctrl.StartMetrics(ctx, ctrl.DefaultSampler())
		defer ctrl.Stop()
		srv.SetController(ctrl)
	}
	// ANTIFILTER: фоновое обновление blocked-списков (ETag 30м, кеш/fallback §5.2).
	// AssetDir — каталог geo-файлов Xray (install.sh кладёт geoip/geosite сюда же).
	afMgr := antifilter.NewManager(st, env("XKIT_AF_CACHE", parentDir(*dbPath)+"/antifilter"), env("XKIT_ASSET_DIR", "/usr/local/share/xray"))
	srv.SetAntifilterManager(afMgr)
	afCtx, afCancel := context.WithCancel(context.Background())
	defer afCancel()
	afMgr.StartLoop(afCtx, func() {
		// горячая пересборка af-правил (A/B-файл сменился — ядро перечитает набор)
		if ctrl != nil {
			ctrl.SyncRulesNow(context.Background())
		}
	})
	// FIREWALL АВТОМАТИКА (директива: домохозяйка не трогает ufw вручную).
	// Базовая политика deny incoming + ssh/http/https, сверка портов с активными протоколами.
	srv.InitFirewall()
	go srv.InitFail2ban()
	srv.SetContext(context.Background())
	go srv.InitTGProxy()

	// TELEGRAM БОТ (опционален): альтернативный пульт без терминала.
	// УРОКИ main XKIT перенесены: recover от panic кнопок, пошаговый мастер создания,
	// подписка одним сообщением, ошибки не глушатся. Меню добавления бота в UI (настройки).
	// BotManager: токен из settings (форма в UI) или env при первом старте, перезапуск без рестарта панели.
	botMgr := api.NewBotManager(st, *domain)
	srv.SetBotManager(botMgr)
	botCtx, botCancel := context.WithCancel(context.Background())
	defer botCancel()
	botMgr.Start(botCtx, env("XKIT_TG_TOKEN", ""), env("XKIT_TG_ADMIN", "0"))

	// Уведомления клиентам (P0 #3): контроллер шлёт через бота (истечение/квота).
	// nil-safe: если бот не настроен — SendText вернёт ошибку, уведомления не отправятся.
	if ctrl != nil {
		ctrl.NotifyClient = botMgr.SendText
		ctrl.NotifyAdmin = botMgr.SendAdmin
		// 🌍 Страна в клиентском меню бота: смена clients.country → горячий PushAssignment
		botMgr.SetCountryChange(func(ctx context.Context, email, country string) error {
			_, err := ctrl.PushAssignment(ctx, email, country)
			return err
		})
	}

	// WEBHOOK-уведомления (P1 #14): события панели → внешний URL с HMAC-подписью.
	// Интеграции: бот магазина, Uptime-Kuma, биллинг. Настройка в UI (Настройки → Webhook).
	wh := notify.NewWebhook(st)
	wh.Start()
	st.EventHook = wh.Emit
	srv.SetWebhook(wh)

	// БЭКАПЫ (настраиваемые как в XKIT main): SQLite+TLS+REALITY → tar.gz,
	// retention (интервал/дни/минимум), отправка в TG-бот. Основа аварийного переезда.
	backupDir := env("XKIT_BACKUP_DIR", parentDir(*dbPath)+"/backups")
	bkMgr := backup.NewManager(st, backupDir, *dbPath)
	bkMgr.SetTGSend(botMgr.SendFile)
	bkMgr.Start(botCtx)
	srv.SetBackupManager(bkMgr, backupDir)

	// AMNEZIAWG сервер в процессе (amneziawg-go библиотека): восстановление из БД.
	// SQLite = источник правды: если enabled — поднимаем TUN+NAT+пиры при старте.
	srv.SetAWGManager()
	// УРОК (QA): все restore в горутинах — HTTP должен слушать СРАЗУ (nginx 502 при блокировке).
	go srv.RestoreAWG()
	// AWG-каскады мастер→нода: восстановление из БД (мастер-клиент переживает рестарт панели).
	go srv.RestoreAWGCascades()
	// Восстановление inbound'ов из БД (preset-протоколы переживают рестарт xray).
	// Restore сам ждёт готовности gRPC xray.
	go srv.RestoreInbounds()
	// внешний рестарт xray (systemctl мимо панели) — детект и restore (Ops 2026-11-26)
	go srv.WatchXrayRestart(context.Background())
	// R-1: known_hosts каталог для SSH accept-new
	os.MkdirAll("/var/lib/xkit-panel", 0700)
	// SEC-12: прореживание истёкших сессий (раз в час)
	go func() {
		for range time.Tick(time.Hour) {
			st.DB().Exec(`DELETE FROM sessions WHERE expires < ?`, time.Now().Unix())
		}
	}()

	// секретный путь (маскировка): если задан — всё под /<secret>/
	prefix := ""
	secretPath := *secret
	if secretPath == "" {
		secretPath = st.GetSetting("secret_path", "")
	}
	if secretPath == "" {
		secretPath = randHex(8)
		st.SetSetting("secret_path", secretPath)
	}
	prefix = "/" + strings.Trim(secretPath, "/")

	// AUTH: логин/пароль (argon2). УРОК (владелец): логин СЛУЧАЙНЫЙ (не admin),
	// пароль одноразовый (must_change=1) — первый вход блокирует до смены.
	// Сброс: xkit-panel reset-password (SSH) → новый одноразовый, снова менять.
	au := auth.New(st)
	adminUser := st.GetSetting("admin_username", "")
	// УРОК (баг повторного создания): если admin_username указывает на удалённого оператора,
	// EnsureAdmin создавал НОВОГО xkit-<hex> owner при каждом старте. Если в базе уже есть
	// операторы — берём первого существующего (не плодим дубли).
	if adminUser == "" || !au.AdminExists(adminUser) {
		if existing := au.AdminUsername(); existing != "" {
			adminUser = existing
			st.SetSetting("admin_username", adminUser)
		}
	}
	if adminUser == "" {
		adminUser = env("XKIT_ADMIN_USER", "")
		if adminUser == "" {
			adminUser = randHex(6) // случайный логин, не admin
		}
	}
	adminPass := env("XKIT_ADMIN_PASS", "")
	adminPassExplicit := adminPass != ""
	if adminPass == "" {
		adminPass = randPassword()
	}
	if created, err := au.EnsureAdmin(adminUser, adminPass); err != nil {
		log.Fatalf("admin: %v", err)
	} else if created {
		st.SetSetting("admin_username", adminUser)
		if adminPassExplicit {
			st.SetSetting("admin_pass_bootstrap", sha256Hex(adminPass))
		}
		log.Printf("=== ПЕРВЫЙ ЗАПУСК: логин %s, одноразовый пароль: %s (сменить при входе) ===", adminUser, adminPass)
		fmt.Fprintf(os.Stderr, "\n  XKIT Panel login: %s\n  one-time password: %s\n  (сменить при первом входе)\n\n", adminUser, adminPass)
		// сохраняем реквизиты в файл (install.sh показывает их; пароль одноразовый)
		os.WriteFile(parentDir(*dbPath)+"/first-login.txt", []byte(fmt.Sprintf("login=%s\npassword=%s\nодноразовый — сменить при первом входе\n", adminUser, adminPass)), 0600)
	} else if adminPassExplicit {
		// ПОВТОРНАЯ установка над существующей БД (урок 28.11.2026): установщик кладёт
		// свежий XKIT_ADMIN_PASS, но EnsureAdmin пропускает существующего админа, и БД
		// хранила старый хеш, пока печатался новый пароль → вход не работал. Здесь новый
		// пароль установщика явно ложится в БД (ровно один раз за значение), а повторные
		// рестарты с тем же значением пароль больше не трогают.
		if changed, err := applyBootstrapPass(st, au, adminUser, adminPass); err != nil {
			log.Printf("admin bootstrap: %v", err)
		} else if changed {
			log.Printf("=== ПОВТОРНАЯ УСТАНОВКА: пароль админа %s обновлён (одноразовый) ===", adminUser)
			fmt.Fprintf(os.Stderr, "\n  XKIT Panel login: %s\n  one-time password: %s\n  (сменить при первом входе)\n\n", adminUser, adminPass)
			os.WriteFile(parentDir(*dbPath)+"/first-login.txt", []byte(fmt.Sprintf("login=%s\npassword=%s\nодноразовый — сменить при первом входе\n", adminUser, adminPass)), 0600)
		}
	}

	// UI (embed)
	uiSub, _ := fs.Sub(webFS, "web")
	tmpl := template.Must(template.ParseFS(webFS, "web/index.html"))
	loginTmpl := template.Must(template.ParseFS(webFS, "web/login.html"))
	setupPassTmpl := template.Must(template.ParseFS(webFS, "web/setup-password.html"))
	srv.SetAuth(au)
	// locale/theme читаются из БД при КАЖДОМ запросе (не при старте) — смена применяется
	// без рестарта панели. УРОК: замыкание захватывало старое значение → рестарт был нужен.
	curLocale := func() string { return st.GetSetting("locale", "ru") }
	curTheme := func() string { return st.GetSetting("theme", "dark") }
	xrayVer := "26.11.9"
	loginPath := prefix + "/login"

	renderLogin := func(w http.ResponseWriter, r *http.Request, errMsg bool) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := map[string]any{"Locale": curLocale(), "Theme": curTheme(), "Version": Version, "Domain": *domain, "Base": prefix, "Error": errMsg}
		loginTmpl.Execute(w, data)
	}

	// login GET/POST (без auth). SEC-06: rate limit 5 попыток/IP/минуту,
	// экспоненциальный backoff при повторных превышениях + лимит тела 1 MiB.
	loginLimiter := newLoginLimiter()
	mux.HandleFunc(loginPath, func(w http.ResponseWriter, r *http.Request) {
		if u := au.User(r); u != "" {
			if au.MustChange(u) {
				http.Redirect(w, r, prefix+"/setup-password", http.StatusFound)
				return
			}
			http.Redirect(w, r, prefix+"/", http.StatusFound)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if ok, wait := loginLimiter.allow(clientIP(r)); !ok {
				secs := int(wait.Seconds()) + 1
				w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
				http.Error(w, fmt.Sprintf("Слишком много попыток входа. Повторите через %d с. / Too many login attempts. Retry in %d s.", secs, secs), http.StatusTooManyRequests)
				return
			}
			r.ParseForm()
			if au.Login(w, r, r.FormValue("username"), r.FormValue("password")) {
				if au.MustChange(r.FormValue("username")) {
					http.Redirect(w, r, prefix+"/setup-password", http.StatusFound)
					return
				}
				http.Redirect(w, r, prefix+"/", http.StatusFound)
				return
			}
			renderLogin(w, r, true)
			return
		}
		renderLogin(w, r, false)
	})
	// setup-password — блокирующий шаг первого входа (одноразовый пароль → постоянный).
	// Доступен только залогиненным с must_change=1 (Require пропускает этот путь).
	mux.Handle(prefix+"/setup-password", au.Require(loginPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setupPassTmpl.Execute(w, map[string]any{"Locale": curLocale(), "Theme": curTheme(), "Version": Version, "Domain": *domain, "Base": prefix, "AdminLogin": au.User(r)})
	})))
	mux.HandleFunc(prefix+"/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { http.Error(w, "POST only", 405); return }
		au.Logout(w, r)
		http.Redirect(w, r, loginPath, http.StatusFound)
	})

	// защищённый UI
	uiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, prefix)
		if p == "" || p == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			tmpl.Execute(w, map[string]string{"Locale": curLocale(), "Theme": curTheme(), "Version": Version, "XrayVersion": xrayVer, "Domain": *domain, "Base": prefix})
			return
		}
		if p == "/manifest.json" {
			w.Header().Set("Content-Type", "application/manifest+json")
			fmt.Fprintf(w, `{"name":"XKIT Panel","short_name":"XKIT","start_url":"%s/","display":"standalone","background_color":"#0d1117","theme_color":"#0d1117","icons":[{"src":"%s/static/icon-192.png","sizes":"192x192","type":"image/png"}]}`, prefix, prefix)
			return
		}
		http.StripPrefix(prefix+"/", http.FileServer(http.FS(uiSub))).ServeHTTP(w, r)
	})
	mux.Handle(prefix+"/", au.Require(loginPath, uiHandler))

	// API под тем же секретным путём (защищён)
	apiHandler := srv.Router()
	mux.Handle(prefix+"/api/", au.Require(loginPath, http.StripPrefix(prefix, apiHandler)))

	// health без секрета (для nginx/мониторинга, локальный)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	})

	// DECOY catch-all (P1 #6): любой путь вне секрета/sub/healthz → заглушка обычного сайта.
	// Анти-пробинг ТСПУ: корень "/" и мусор не выдают VPN-панель. Регистрируется ПОСЛЕДНИМ
	// (mux longest-match: /sub/, /healthz, prefix/ имеют приоритет над "/").
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		decoyResponse(w, r)
	})

	// ПУБЛИЧНАЯ подписка /<sub_prefix>/<subId> — base64 список ссылок для клиентских приложений.
	// УРОК (владелец): ВСЕ пути рандом — никакого предсказуемого /sub/. Префикс случайный
	// (settings sub_prefix), subId случайный. Без auth (клиенты не логинятся). nginx camo проксирует.
	subPrefix := st.SubPrefix()
	mux.HandleFunc("/"+subPrefix+"/", func(w http.ResponseWriter, r *http.Request) {
		subPath := strings.TrimPrefix(r.URL.Path, "/"+subPrefix+"/")
		if subPath == "" {
			decoyResponse(w, r); return
		}
		// АНТИ-ПРОБИНГ (P1 #6, Remnawave Response Rules / Marzban): корень /sub/ и
		// несуществующие subId отдают decoy (не 404 панели — скрываем что это VPN-панель).
		// Реальный subId (16 hex) проходит; мусор/зонды → camo-заглушка.
		subID := strings.SplitN(subPath, "/", 2)[0]
		if !validSubID(subID) {
			decoyResponse(w, r); return
		}
		// /sub/<id>/amnezia — AmneziaWG: vpn:// redirect / conf / QR-страница.
		// УРОК XKIT main: Amnezia клиент открывает vpn:// ссылку → импорт конфига.
		if len(strings.SplitN(subPath, "/", 2)) > 1 && strings.SplitN(subPath, "/", 2)[1] == "amnezia" {
			peer, ok := srv.AWGPeerBySubID(subID)
			if !ok {
				http.Error(w, "AmneziaWG не настроен для этого клиента (создайте пир в панели)", 404)
				return
			}
			conf, vpnLink := peer.ClientConf(), peer.VPNLink()
			q := r.URL.Query().Get("format")
			switch q {
			case "conf":
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Content-Disposition", "attachment; filename=xkit-amnezia.conf")
				fmt.Fprint(w, conf)
			case "vpn":
				// Amnezia клиент: redirect на vpn:// (импорт в приложение)
				http.Redirect(w, r, vpnLink, http.StatusFound)
			default:
				// HTML страница: vpn:// кнопка + conf + ПРАВИЛЬНЫЙ multi-frame QR
				// (Amnezia containers → Qt zlib → чанки '>hBBI', анимация 700мс — src/28).
				chunks, _ := amnezia.AWGQRPayload(peer, "XKIT "+peer.Name)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprint(w, amneziaSubPage(conf, vpnLink, chunks))
			}
			return
		}
		// /<prefix>/<id>/antifilter/<kind> — blocked-наборы для клиентских подписок
		// (clash rule-provider / sing-box rule-set). Тот же случайный subId, без auth.
		if parts := strings.SplitN(subPath, "/", 3); len(parts) == 3 && parts[1] == "antifilter" {
			srv.ServeAntifilterBlocked(w, r, parts[0], parts[2])
			return
		}
		// /<prefix>/<id>/routing — публичный API роутинга клиента (GET/POST, без auth по subId).
		// Клиент редактирует СВОИ правила на странице подписки. Серверные правила владельца не трогает.
		if len(strings.SplitN(subPath, "/", 2)) > 1 && strings.SplitN(subPath, "/", 2)[1] == "routing" {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // R-4: лимит 64KB
			srv.PublicClientRouting(w, r, subID)
			return
		}
		// /<prefix>/<id>/country — публичный выбор страны выхода (Any/NL/US…).
		// Одна ссылка на протокол; страна = clients.country → базовое per-user правило.
		if len(strings.SplitN(subPath, "/", 2)) > 1 && strings.SplitN(subPath, "/", 2)[1] == "country" {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // R-4: лимит 64KB
			srv.PublicClientCountry(w, r, subID)
			return
		}
		var email, uuid, name string
		var quota, used, expiry int64
		err := st.DB().QueryRow(`SELECT email,uuid,name,quota_bytes,used_bytes,expiry FROM clients WHERE sub_id=? AND enabled=1`, subID).
			Scan(&email, &uuid, &name, &quota, &used, &expiry)
		if err != nil {
			// несуществующий/отключённый subId → decoy (не 404 панели — анти-пробинг P1 #6)
			decoyResponse(w, r); return
		}
		// HWID-лимит устройств (P0 #1, стандарт Happ x-hwid). УРОК (panels-research):
		// без лимита подписку расшаривают бесконечно. Новое устройство сверх лимита →
		// понятная ошибка (НЕ 404 как Remnawave), существующие устройства всегда проходят.
		hwid := r.Header.Get("x-hwid")
		if hwid != "" {
			model := r.Header.Get("x-hwid-model")
			platform := subscription.PlatformByUA(r.UserAgent())
			allowed, _, derr := st.RegisterDevice(email, hwid, model, platform)
			if derr == nil && !allowed {
				limit := st.ClientHWIDLimit(email)
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("x-hwid-limit", fmt.Sprintf("%d", limit))
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintf(w, "Достигнут лимит устройств (%d). Отвяжите неиспользуемое устройство в панели или попросите администратора увеличить лимит.\nDevice limit reached (%d). Unlink an unused device or ask admin to raise the limit.", limit, limit)
				return
			}
			// ответные x-hwid заголовки (стандарт Happ — клиент показывает лимит/устройства)
			w.Header().Set("x-hwid-limit", fmt.Sprintf("%d", st.ClientHWIDLimit(email)))
			w.Header().Set("x-hwid-count", fmt.Sprintf("%d", st.DeviceCount(email)))
		}
		// УРОК (владелец): подписка из ВСЕХ включённых протоколов мастера (inbounds таблица).
		// Одна ссылка на протокол (базовый UUID): страна = clients.country, меняется
		// через /country API или TG-бот → балансир горячо перестраивает assignment.
		var specs []subscription.InboundSpec
		ibRows, _ := st.DB().Query(`SELECT tag,protocol,port,network,security,settings,stream,hidden,public_port FROM inbounds WHERE enabled=1 AND in_sub=1 AND tag NOT IN ('api-in','api','tls-dispatcher')`)
		if ibRows != nil {
			for ibRows.Next() {
				var tag, protocol, network, security, settingsJ, streamJ string
				var port, hidden, pubPort int
				ibRows.Scan(&tag,&protocol,&port,&network,&security,&settingsJ,&streamJ,&hidden,&pubPort)
				sp := subscription.ParseInboundSpec(tag, protocol, port, network, security, settingsJ, streamJ)
				// маскировка: hidden-протокол клиент видит как домен:443 TLS (dispatcher терминирует)
				if hidden == 1 && pubPort > 0 {
					sp.Port = pubPort
					sp.Security = "tls"
					var stg map[string]any
					json.Unmarshal([]byte(streamJ), &stg)
					if stg == nil { stg = map[string]any{} }
					sni := *domain
					var sett map[string]any
					json.Unmarshal([]byte(settingsJ), &sett)
					if sett != nil { if sn, _ := sett["subSni"].(string); sn != "" { sni = sn } }
					stg["tlsSettings"] = map[string]any{"serverName": sni}
					sp.Stream = stg
				}
				specs = append(specs, sp)
			}
			ibRows.Close()
		}
		// Набор протоколов клиента (вариант B): свой override > группа > все включённые.
		// Реальный запрет синхронизируется отдельно (syncClientInboundAccess).
		if eff, _ := st.EffectiveProtocols(email); eff != nil {
			allowed := map[string]bool{}
			for _, t := range eff { allowed[t] = true }
			var filtered []subscription.InboundSpec
			for _, sp := range specs {
				if allowed[sp.Tag] { filtered = append(filtered, sp) }
			}
			specs = filtered
		}
		var links []string
		if len(specs) > 0 {
			// hosts (P1 #10): несколько рекламных точек входа (CDN-фронтинг/per-host SNI).
			var hosts []subscription.HostEntry
			if mh, _ := st.AllMasterHosts(); len(mh) > 0 {
				for _, h := range mh {
					hosts = append(hosts, subscription.HostEntry{Address: h.Address, Port: h.Port, SNI: h.SNI, Label: h.Label})
				}
			}
			links = subscription.LinksFromInboundsHosts(specs, uuid, email, name, hosts, *domain)
		} else {
			// fallback: legacy REALITY (если inbounds таблица пуста — старая установка)
			m := subscription.MasterParams{Address: *domain, Port: 443, SNI: *domain,
				PublicKey: env("XKIT_REALITY_PUB", ""), ShortID: env("XKIT_REALITY_SID", ""),
				Fingerprint: "chrome", Flow: "xtls-rprx-vision"}
			links = subscription.ClientLinks(uuid, email, name, m)
		}
		subURL := fmt.Sprintf("https://%s/%s/%s", *domain, subPrefix, subID)
		// AWG в подписке: пир создаётся автоматически (если сервер включён), vpn:// ссылка
		// добавляется к остальным протоколам. УРОК: «не вижу амнезии в подписках».
		srv.EnsureAWGPeerForSub(email)
		if awgPeer, ok := srv.AWGPeerBySubID(subID); ok {
			if vl := awgPeer.VPNLink(); vl != "" {
				links = append(links, vl)
			}
		}
		// Telegram-прокси (MTProto FakeTLS + Web Proxy) — если включены
		links = append(links, srv.TGProxyLinks()...)

		// УРОК (исследование): реальный Subscription-Userinfo (был захардкожен нулями),
		// UA-детект формата, браузерная страница с QR вместо голого base64.
		format, wantsPage := subscription.DetectFormat(r.UserAgent(), r.Header.Get("Accept"), r.URL.Query().Get("format"))
		if format == "invalid" {
			// QA BUG-12: неизвестный ?format= — честный 400, не молчаливый raw
			http.Error(w, "unknown format (raw|clash|singbox|xray|page)", http.StatusBadRequest)
			return
		}
		ui := subscription.Userinfo{Upload: 0, Download: used, Total: quota, Expire: expiry}
		// общие заголовки оформления (урок: no-store/noindex/profile-title)
		w.Header().Set("Subscription-Userinfo", ui.Header())
		w.Header().Set("Profile-Update-Interval", "6")
		w.Header().Set("Profile-Title", "XKIT "+name)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Referrer-Policy", "no-referrer")

		if wantsPage {
			// браузерная страница: QR (go-qrcode в процесс) + трафик/срок + приложения
			qrDataURL := ""
			if png, err := qrcode.Encode(subURL, qrcode.Medium, 256); err == nil {
				qrDataURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
			}
			locale := st.GetSetting("locale", "ru")
			// P2 роутинг: режим/разрешение/deeplink для страницы подписки.
			// УРОК (QA BUG-12): deeplink строим ВСЕГДА (Happ-кнопка применяет наши
			// правила и без кастома); редактор кастома страница покажет только при rAllowed.
			rMode, rr, rAllowed := st.ClientRouting(email)
			cr := routing.CustomRules{DirectSites: rr.DirectSites, ProxySites: rr.ProxySites, BlockSites: rr.BlockSites, DirectIP: rr.DirectIP, ProxyIP: rr.ProxyIP, BlockIP: rr.BlockIP}
			d, p, b, dip, pip, bip := routing.MergedRulesBase(rMode, cr, routingBase(st))
			rDeeplink := routing.HappDeeplink("XKIT "+name, d, p, b, dip, pip, bip)
			// antifilter: Happ-дефолт инвертируется (GlobalProxy=false), always-правила владельца
			var nodesN int
			st.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE enabled=1`).Scan(&nodesN)
			if afRules := srv.AntifilterSubscriptionRules(nodesN > 0); afRules != nil {
				rDeeplink = routing.AntifilterHappDeeplink("XKIT "+name, afRules.DirectSites, afRules.ProxySites, nil, afRules.DirectIP, afRules.ProxyIP, nil)
			}
			page := subscription.RenderPage(subscription.PageData{
				Name: name, SubURL: subURL, Links: links, QRDataURL: qrDataURL,
				UsedBytes: used, QuotaBytes: quota, Expiry: expiry,
				Platform: subscription.PlatformByUA(r.UserAgent()), Locale: locale, Domain: *domain,
				RoutingMode: rMode, RoutingAllowed: rAllowed, RoutingDeeplink: rDeeplink, SubID: subID,
			})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, page)
			return
		}
		// форматы: raw (base64), clash (YAML), singbox (JSON), xray (JSON) — UA-детект.
		// УРОК: hiddify→raw (YAML ломает Hiddify 4.x), incy→xray, clash/mihomo→YAML.
		// P2 роутинг: наш дефолт + кастом клиента (если mode=custom и разрешено владельцем).
		rMode, rRules, rAllowed := st.ClientRouting(email)
		var clashExtra []string
		var xrayExtra []map[string]any
		if rMode == "custom" && rAllowed {
			cr := routing.CustomRules{DirectSites: rRules.DirectSites, ProxySites: rRules.ProxySites, BlockSites: rRules.BlockSites, DirectIP: rRules.DirectIP, ProxyIP: rRules.ProxyIP, BlockIP: rRules.BlockIP}
			d, p, b, dip, pip, bip := routing.MergedRulesBase("custom", cr, routingBase(st))
			clashExtra = routing.ClashRules(d, p, b, dip, pip, bip)
			xrayExtra = routing.XrayRules(d, p, b, dip, pip, bip)
		}
		// ANTIFILTER (mode-aware подписки): инверсия — blocked через ноду, остальное
		// direct; always-правила владельца доходят до клиента. Клиентские blocked-наборы
		// качаются с панели по подписочному URL (clash provider / sing-box rule-set).
		var nodesN int
		st.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE enabled=1`).Scan(&nodesN)
		afRules := srv.AntifilterSubscriptionRules(nodesN > 0)
		afBase := fmt.Sprintf("https://%s/%s/%s/antifilter", *domain, subPrefix, subID)
		switch format {
		case "clash":
			w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
			w.Header().Set("Content-Disposition", "inline; filename=xkit.yaml")
			if afRules != nil {
				fmt.Fprint(w, subscription.ClashYAMLAntifilter(links, clashExtra, *afRules, afBase))
			} else {
				fmt.Fprint(w, subscription.ClashYAMLRouting(links, clashExtra))
			}
		case "singbox":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			if afRules != nil {
				fmt.Fprint(w, subscription.SingboxJSONAntifilter(links, *afRules, afBase))
			} else {
				fmt.Fprint(w, subscription.SingboxJSON(links))
			}
		case "xray":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			// INCY: балансер прячет профили за одним «авто» → отдаём все профили выбираемыми.
			ua := strings.ToLower(r.UserAgent())
			if afRules != nil {
				if strings.Contains(ua, "incy") {
					fmt.Fprint(w, subscription.XrayJSONAntifilterProfiles(links, xrayExtra, *afRules, afBase))
				} else {
					fmt.Fprint(w, subscription.XrayJSONAntifilter(links, xrayExtra, *afRules, afBase))
				}
			} else if strings.Contains(ua, "incy") {
				fmt.Fprint(w, subscription.XrayJSONProfiles(links, xrayExtra))
			} else {
				fmt.Fprint(w, subscription.XrayJSONRouting(links, xrayExtra))
			}
		default:
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprint(w, subscription.Subscription(links))
		}
	})

	httpSrv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("XKIT Panel %s слушает %s (secret=%q domain=%s)", Version, *listen, prefix, *domain)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("завершение…")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(ctx)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// randPassword — генерация пароля admin (16 символов, crypto/rand).
func randPassword() string {
	const charset = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "xkit-" + fmt.Sprintf("%d", time.Now().UnixNano())
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

// sha256Hex — строковый fingerprint значения (для отслеживания применённого пароля).
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// applyBootstrapPass — ложит пароль установщика в БД существующего админа ровно один раз
// за конкретное значение (по fingerprint в settings). Возвращает true, если пароль менялся.
func applyBootstrapPass(st *store.Store, au *auth.Auth, adminUser, adminPass string) (bool, error) {
	if adminPass == "" || !au.AdminExists(adminUser) {
		return false, nil
	}
	fp := sha256Hex(adminPass)
	if st.GetSetting("admin_pass_bootstrap", "") == fp {
		return false, nil
	}
	if err := au.ResetPassword(adminUser, adminPass); err != nil {
		return false, err
	}
	if err := st.SetSetting("admin_pass_bootstrap", fp); err != nil {
		return true, err
	}
	return true, nil
}

// randHex — случайная hex-строка (для случайного логина).
func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func parentDir(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "."
	}
	return p[:i]
}

// seedDemo — тестовые ноды/клиенты для первого запуска (полигон).
func seedDemo(st *store.Store) {
	nodes := []store.Node{
		{ID: "node-de-1", Name: "Frankfurt-1", Country: "DE", CountryCode: 1, Priority: 1, Price: 1.0, Host: "de1.example.com", Tunnel: "reality", Health: "alive", Enabled: true},
		{ID: "node-de-2", Name: "Frankfurt-2", Country: "DE", CountryCode: 1, Priority: 2, Price: 1.0, Host: "de2.example.com", Tunnel: "reality", Health: "alive", Enabled: true},
		{ID: "node-nl-1", Name: "Amsterdam-1", Country: "NL", CountryCode: 2, Priority: 1, Price: 1.2, Host: "nl1.example.com", Tunnel: "xhttp", Health: "alive", Enabled: true},
		{ID: "node-us-1", Name: "NewYork-1", Country: "US", CountryCode: 3, Priority: 1, Price: 1.5, Host: "us1.example.com", Tunnel: "ws", Health: "down", Enabled: true},
	}
	for _, n := range nodes {
		st.UpsertNode(n)
	}
	clients := []store.Client{
		{Email: "ivan@test.ru", UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", SubID: "sub1", Country: "DE", CountryCode: 1, Enabled: true},
		{Email: "petra@test.ru", UUID: "c931381d-6324-4d53-ad4f-8cda48b30822", SubID: "sub2", Country: "DE", CountryCode: 1, Enabled: true},
		{Email: "john@test.ru", UUID: "d931381d-6324-4d53-ad4f-8cda48b30833", SubID: "sub3", Country: "US", CountryCode: 3, Enabled: true},
	}
	for _, c := range clients {
		st.UpsertClient(c)
	}
	st.SetAssignment(store.Assignment{Email: "ivan@test.ru", Country: "DE", NodeID: "node-de-1", RuleTag: "c:ivan@test.ru:de", Status: "sticky"})
	st.SetAssignment(store.Assignment{Email: "petra@test.ru", Country: "DE", NodeID: "node-de-1", RuleTag: "c:petra@test.ru:de", Status: "sticky"})
	st.SetAssignment(store.Assignment{Email: "john@test.ru", Country: "US", NodeID: "node-nl-1", RuleTag: "c:john@test.ru:us", Status: "failover", FailoverFrom: "US"})
	st.AddEvent("node_down", "error", "нода NewYork-1 недоступна (3 проб)", `{"node":"node-us-1"}`)
	st.AddEvent("failover", "warn", "US→NL: john@test.ru перенесён на Amsterdam-1", `{"email":"john@test.ru"}`)
	st.AddEvent("backup", "ok", "Бэкап отправлен в TG", `{}`)
	log.Println("seed: demo ноды/клиенты/назначения добавлены")
}

// routingBase — базовый набор владельца из БД для генерации подписок/deeplink.
func routingBase(st *store.Store) routing.BaseRules {
	dr := st.DefaultRouting()
	return routing.BaseRules{DirectSites: dr.DirectSites, ProxySites: dr.ProxySites, BlockSites: dr.BlockSites, DirectIP: dr.DirectIP, ProxyIP: dr.ProxyIP, BlockIP: dr.BlockIP}
}
