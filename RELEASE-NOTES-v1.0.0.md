# XKIT Panel — Release Notes

## v1.0.0 — 2026-11-27

Первый публичный релиз. Ниже — что вошло, что мы сами считаем недоделанным и как переезжать со старых версий.

### Что вошло

**Antifilter-режим**
- Точные списки заблокированного (RunetFreedom): ETag-поллинг каждые 30 минут, sanity-пределы, кеш с backoff (60 мин → 6 ч), fallback на старый срез при недоступности источников (>24 ч или пустой кеш).
- Always-правила владельца: категории geosite/geoip и отдельные домены, валидация (IDNA, конфликты direct > proxy).
- Режимы маршрутизации: `solo` (всё напрямую), `ru-direct` (RU-домены/IP напрямую, остальное через ноды), `antifilter` (заблокированное — через ноды, остальное напрямую).
- `/24-margin` — expert-флаг, расширяющий IP-список до подсетей /24; включение/отключение применяется сразу (POST вызывает RefreshNow).
- Подписки с заблокированными доменами во всех форматах (clash rule-provider txt, sing-box remote rule-set source-JSON с реальным fetch в тестах, xray-json inline, инверсия для Happ).
- Фоновый цикл обновления: A/B-файлы geodata с hot-reload без рестарта ядра, атомарная запись.
- Sticky per-user: заблокированный трафик идёт на «свою» ноду без скачков между соединениями; reconnect при офлайне — к лучшей доступной.
- Серия фиксов по итогам QA (AF-BUG-1…4): xray-json подписка стартует на xray 26.11.9 (dialerProxy вместо удалённого proxySettings), правила af/always адресуют балансир через balancerTag, /24-margin OFF сужает список обратно, поддомены blocked-доменов больше не утекают в DIRECT.

**Упрощённый роутинг**
- Слой cs/vlessRoute удалён: страна выхода = поле `clients.country`, один UUID на клиента, базовое per-user правило.
- Смена страны — горячая, тем же UUID, через API подписки или TG-бот (единая store-точка: rate-limit 10 с, валидация, аудит). Смерть страны → fallback на живую без обрыва; родная страна ожила + reconnect → возврат; mid-session без скачков.
- Миграция при старте: старые cs-правила стрипаются автоматически, страна сохраняется.

**Трафик**
- Lifetime-потребление клиента и ноды (Σ за всё время).
- Периодный трафик: почасовые бакеты (миграция 036), скользящие 24 ч / 7 д / 30 д в UTC, up/down раздельно, retention 90 дней, lifetime не трогаем.
- UI: селект периода в шапке таблиц, тултип с разбивкой 24ч/7д/30д/Σ, мобильные карточки следуют периоду.

**Expert-режим**
- Один чекбокс показывает/прячет расширенное: редактор туннельных полей, MTU, mask-scan, каскад AWG, биллинг/capacity, MTProto, версии xray-пикер, /24-margin и статус antifilter.
- Фикс сброса флага: `expert_mode` нормализуется (`'1'`/1/true/`'on'` → канон `1`), фронт не сбрасывает при ошибке/пустом ответе.
- Expert-меню узла: transport/tunnel-поля/каскад AWG/биллинг/capacity скрыты в простом режиме.

**Версии компонентов**
- `GET /api/system/versions` + hysteria2 (через xray) и AmneziaWG (встроена; BuildInfo go.mod ↔ теги GitHub, кеш 5 минут).
- Xray-пикер — expert-only, версия pinned из API, предупреждение при непinned.
- Инвариант: go.mod ↔ бинарь xray. Релиз собран с xray-core 26.11.9 (pinned).

**Подписки**
- Mode-aware во всех форматах: base64-ссылки, clash YAML, sing-box JSON (1.11/1.12), xray-json (INCY-профили + default), Happ (cryptoLink crypt3).
- Смена страны подпиской — без перегенерации ключей, один UUID.
- DNS-политика в подписках: RU-домены — локальный резолв (Яндекс DoH для .ru/.su, DoH Cloudflare/Google для остальных), QUIC/STUN block во всех форматах, DNS-applications hijack в sing-box.

**Безопасность**
- Host-guard: SSH `accept-new` по всем путям, секция Host-check на всех вызовах, изоляция known_hosts.
- Валидация публичных POST: MaxBytesReader, IDNA, hwid, node name, secret_path.
- Подписи Ed25519 для релизов (SHA256SUMS + .sig, проверка install.sh ДО установки — отказ на несовпадении), ре-подпись после каждого rebuild dist.
- Doctor-отчёт без секретов: без IP/emails/доменов/логов клиентов (sanitization).
- Валидация параметров подписки: `?format=bogus` → 400, country и email проверяются до записи (404/400 без сиротских правил).

**Survey транспортов**
- Бенчмарк всех 5 транспортов full-path (16 MiB) на реальных нодах: авто-очистка артефактов, восстановление исходного конфига, выбор лучшего из UI.

**Прочее**
- gRPC-транспорт удалён (Xray 26.x deprecates gRPC, замена — XHTTP): из селекторов туннеля нод, клиентских пресетов и каталога визарда.
- RU-direct: geoip:ru + geosite:category-ru + .ru/.su → direct на мастере, персистентно в config.json; в solo — чистый catch-all direct.
- BBR + fq + буферы TCP включаются автоматически при установке (sysctl 99-xkit.conf) и на нодах при provision; IPv4-only резолв (dns UseIPv4 + freedom UseIPv4).
- Camo sitegen: 22 категории игровых прикрытий, реалистичные сгенерированные сайты (Minecraft, Rust, CS2, Valheim…), загрузка своего сайта ZIP drag-drop (10 МБ, без серверных скриптов).
- Rollback-система: снапшоты до деструктивных действий, цепной откат (откатывает и более новые изменения той же сущности), окно 24 часа.
- Fail2ban на панели и нодах: автоустановка, статус/бан-лист/unban UI, эскалация 5-try-5m-1h-forever; топ-5 забаненных IP + «+N» со списком целиком.
- Doctor: 13 проверок мастера (cert/camo/xray/reality/sub/bbr/ufw/f2b/disk/geo/nginx/backup) + агент /doctor на нодах (xray alive/version, BBR, disk, UFW), per-item статусы, индивидуальные кнопки «исправить».
- Self-update панели: проверка GitHub releases (кеш 5 мин), бейдж версии в сайдбаре, скачивание+установка+рестарт в один клик.
- TG-бот: ссылки подписок в tg-spoiler, транспорт через ноду (SSH SOCKS auto-failover), напоминания об окончании аренды нод (7/3/1 д).
- AWG: каскад master→node, multi-frame QR, режим 2.0 для роутеров (Keenetic), IPv4-only (::/0 убран из AllowedIPs — IPv6 мёртв).
- Мобильная версия: expert-чекбокс в шапке, компактные шапки 390/320px, таб-бар flex-1.

### Known issues / бэклог (честно)

- **Сетевой шум MSK↔ноды** — канал с заметной служебной нагрузкой, частично косметика, частично архитектура; планируем снизить пост-1.0.
- **sing-box selector default (prep=ws)** — селектор `select` в sing-box-подписках содержит все профили, и дефолтная активная — ws-подготовка, не лучший вариант. Ручная смена в клиенте.
- **AWG соло-выход** — by design на 1.0: клиент получает соло-выход с мастер-сервера (каскад AWG с нодами — полный каскад post-1.0).
- **legacy dns → new-format к sing-box 1.14** — подписки используют legacy dns.servers, которые sing-box 1.12 пропускает без ошибки, но 1.14 будет предупреждать/удалять; миграция на new-format запланирована.
- **REALITY sing-box/mihomo PQ-несовместимость** — апстрим: xray 26.11.9 требует keyshare X25519MLKEM768, sing-box 1.11–1.13 не отправляет PQ-keyshare ни с одним fingerprint → сервер отдает клиента на dest. **xray-клиенты работают.** Не баг панели; следим за PQ-fingerprint в апстримах.
- **Flaky mihomo-тест** — тест генерации clash-конфига требует бинарь mihomo (XKIT_MIHOMO_BIN); при недоступности — skip, поэтому прогоны неравномерные.

### Требования

- Go 1.27+ (сборка)
- xray-core 26.11.9 (pinned, инвариант go.mod ↔ бинарь)
- Linux (мастер и ноды)

### Миграция со старых версий

- **cs-правила** — стрипаются автоматически при старте новой версии, страна выхода сохраняется.
- **Подписки** — перегенерировать: один UUID вместо страновых профилей, старые страновые ссылки попадают в базовое правило (документация миграции в README).
- **Install.sh** — при обновлении проверяет Ed25519-подпись и SHA256 до установки, отказ при несовпадении.

---

# XKIT Panel — Release Notes (EN, brief)

## v1.0.0 — 2026-11-27

First public release.

**Highlights**
- **Antifilter mode**: precise blocked lists (RunetFreedom, 30-min ETag refresh, cache + fallback), owner always-rules (geosite/geoip categories + domains, IDNA-validated), routing modes solo / ru-direct / antifilter, /24-margin expert flag, mode-aware subscriptions in every format.
- **Simplified routing**: country = `clients.country` field, single UUID per client, hot country switch via subscription API / TG bot (same UUID), sticky per-user without connection jumps, failover to a live node when the current country dies, automatic migration strips legacy cs-rules.
- **Traffic**: lifetime totals + rolling 24h / 7d / 30d windows (hourly buckets, 90-day retention), per-period UI.
- **Expert mode**: one toggle for advanced UI (tunnel editor, MTU, AWG cascade, billing, xray picker, /24-margin); fixed flag reset bug.
- **Component versions**: `/api/system/versions` incl. hysteria2 and AmneziaWG; xray picker is expert-only and pinned (26.11.9, go.mod ↔ binary invariant).
- **Subscriptions**: all formats mode-aware (base64 links, clash YAML, sing-box JSON, xray-json, Happ), one UUID, RU-DNS policy, QUIC/STUN blocked.
- **Security**: SSH accept-new host-guard everywhere, public POST validation (MaxBytesReader, IDNA, hwid), Ed25519 release signatures verified before install, sanitized doctor reports.
- **Transport survey**: full-path benchmark of all 5 transports (16 MiB) with auto-cleanup and best-pick from UI.
- **Misc**: gRPC transport removed (deprecated upstream, XHTTP replaces it), RU-direct + BBR + IPv4-only, camo sitegen (22 categories), rollback system, fail2ban, TG bot improvements.

**Known issues (honest)**
- MSK↔nodes service-channel noise — to be reduced post-1.0.
- sing-box selector default is ws-prep, not the best node — pick manually in the client.
- AWG solo exit from master (by design; full AWG cascade is post-1.0).
- Legacy dns format in sing-box subscriptions — new-format migration needed for sing-box 1.14.
- REALITY PQ keyshare incompatibility (upstream): xray 26.11.9 vs sing-box/mihomo — xray clients work fine.
- Flaky mihomo test (requires local binary, skips otherwise).

**Requirements**: Go 1.27+ (build), xray-core 26.11.9 (pinned), Linux.

**Migration from older versions**: legacy cs-rules are stripped automatically (country preserved); regenerate subscriptions — single UUID, old country links fall into the base rule.
