#!/usr/bin/env bash
# XKIT Panel — one-command install.
# curl -fsSL https://raw.githubusercontent.com/kambarro/xkit-panel/main/install.sh | bash
# Спрашивает ТОЛЬКО домен (или IP) — остальное дефолты. Маскировка по умолчанию.
# Ставит: xray + panel + nginx camo + TLS + systemd. Печатает URL+логин+пароль.
set -euo pipefail

REPO="kambarro/xkit-panel"
BRANCH="main"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/xkit-panel"
XRAY_DIR="/usr/local/etc/xray"
CAMO_DIR="/var/www/camo"

echo "╔══════════════════════════════════════╗"
echo "║        XKIT Panel — установка        ║"
echo "╚══════════════════════════════════════╝"

# root check
if [[ $EUID -ne 0 ]]; then echo "Запустите от root: sudo bash install.sh"; exit 1; fi

# === МИНИМУМ вопросов: только домен/IP ===
# УРОК XKIT (input_clean): read -r без readline оставляет DEL/BS/escape-хвосты после
# правки ввода; кириллица/пробелы ломают regex. Чистим управляющие символы + trim
# ДО валидации. Валидация строгая, но чистятся только артефакты терминала.
clean_input() { printf '%s' "$1" | tr -d '[:cntrl:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
DOMAIN="${XKIT_DOMAIN:-}"

# non-interactive (pipe/curl | bash): нет TTY → автоопределяем IP или требуем XKIT_DOMAIN
if [[ -z "$DOMAIN" && ! -t 0 ]]; then
  DOMAIN=$(curl -s --max-time 8 ifconfig.me || curl -s --max-time 8 api.ipify.org || echo "")
  DOMAIN="$(clean_input "$DOMAIN")"
  if [[ -z "$DOMAIN" ]]; then
    echo "ОШИБКА: не TTY (pipe) и не задан XKIT_DOMAIN. Запустите:"
    echo "  XKIT_DOMAIN=<домен|IP> curl -fsSL https://raw.githubusercontent.com/kambarro/xkit-panel/main/install.sh | bash"
    exit 1
  fi
  echo "→ Автоопределен внешний IP: $DOMAIN"
elif [[ -z "$DOMAIN" ]]; then
  # interactive: спрашиваем
  read -rp "Домен мастера (например vpn.example.com) или Enter для IP: " DOMAIN || true
  DOMAIN="$(clean_input "$DOMAIN")"
  if [[ -z "$DOMAIN" ]]; then
    DOMAIN=$(curl -s --max-time 8 ifconfig.me || curl -s --max-time 8 api.ipify.org || echo "")
    DOMAIN="$(clean_input "$DOMAIN")"
    [[ -n "$DOMAIN" ]] && echo "Используем IP: $DOMAIN"
  fi
fi
# валидация домена/IP ДО любых необратимых шагов (урок: пустой XKIT_HOST проходил
# через необратимые шаги и установка умирала позже). Пустой/невалидный = явный die.
if [[ -z "$DOMAIN" ]]; then
  echo "ОШИБКА: не указан домен/IP и не удалось определить внешний IP. Задайте XKIT_DOMAIN=<домен|IP>."
  exit 1
fi
if [[ ! "$DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$ ]]; then
  printf 'ОШИБКА: невалидный домен/IP: %q\n' "$DOMAIN"
  echo "  Ожидается домен (vpn.example.com) или IPv4 (1.2.3.4). Проверьте ввод (кириллица/спецсимволы недопустимы)."
  exit 1
fi
echo "→ Мастер: $DOMAIN"

# === зависимости ===
# УРОК XKIT: unattended-upgrades держит dpkg-лок минутами → apt без Lock::Timeout
# мгновенно отказывает. Все apt-get с -o DPkg::Lock::Timeout=300.
echo "→ Установка зависимостей…"
export DEBIAN_FRONTEND=noninteractive
APT_OPTS="-o DPkg::Lock::Timeout=300"
apt-get $APT_OPTS update -qq || { echo "ОШИБКА: apt-get update не удался (проверьте сеть/репозитории)"; exit 1; }
apt-get $APT_OPTS install -y -qq curl unzip sqlite3 sshpass certbot python3-certbot-nginx gnupg >/dev/null 2>&1 || {
  echo "ОШИБКА: не удалось установить зависимости (curl unzip sqlite3 sshpass certbot gnupg)"; exit 1; }

# === nginx из nginx.org (НЕ Ubuntu nginx!) ===
# КРИТИЧНО (NGINX2Root, 18.11.2026): 5 CVE CVSS 9.2, RCE без auth через HTTP/2 + root через
# SCTP-баг ядра. Ubuntu nginx (1.24 на 24.04) НЕ получает фикс вовремя. Ставим nginx.org stable
# (>=1.30.7) / mainline (>=1.31.9). Ubuntu-пакет nginx НЕ используем.
UBUNTU_CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")
curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg 2>/dev/null
# Явно STABLE-ветка nginx.org (mainline — только осознанно, через UI/репо).
# apt pin: nginx.org приоритетнее Ubuntu-пакета (иначе apt может взять Ubuntu nginx).
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu $UBUNTU_CODENAME nginx" > /etc/apt/sources.list.d/nginx.list
printf 'Package: nginx*\nPin: origin nginx.org\nPin-Priority: 900\n' > /etc/apt/preferences.d/nginx-pin
apt-get $APT_OPTS update -qq
apt-get $APT_OPTS install -y -qq nginx >/dev/null 2>&1 || { echo "ОШИБКА: nginx.org nginx не установился"; exit 1; }
NGINX_VER=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
echo "→ nginx $NGINX_VER (nginx.org stable, NGINX2Root fixed)"

# === архитектура ===
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) XRAY_ARCH="64";;
  aarch64) XRAY_ARCH="arm64-v8a";;
  *) echo "Неподдерживаемая архитектура: $ARCH"; exit 1;;
esac

# === Xray ===
# УРОК XKIT: GitHub-загрузки с РФ-хостов троттлятся/обрываются → --retry-all-errors
# + -C - (resume) + длинный --max-time, а не один короткий timeout.
echo "→ Установка Xray…"
mkdir -p "$XRAY_DIR" /usr/local/share/xray
# geoip/geosite для RU-direct routing (трафик .ru не покидает Россию)
if [[ ! -f /usr/local/share/xray/geoip.dat ]]; then
  curl -sL "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" -o /usr/local/share/xray/geoip.dat
  curl -sL "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" -o /usr/local/share/xray/geosite.dat
fi
TMP=$(mktemp -d)
# ИНВАРИАНТ: версия xray = xrayPinnedVersion в internal/api/system_update.go
# (= xray-core в go.mod панели). latest ЗАПРЕЩЁН: новое ядро меняет wire-format
# gRPC (routing geodata 26.11.x) и молча ломает ReplaceRules у собранной панели.
XRAY_PIN="26.11.9"
curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 -C - --max-time 600 \
  -o "$TMP/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_PIN}/Xray-linux-${XRAY_ARCH}.zip" \
  || { echo "ОШИБКА: не удалось скачать Xray с GitHub (сеть/троттлинг). Повторите позже."; exit 1; }
unzip -o -q "$TMP/xray.zip" xray -d "$TMP" || { echo "ОШИБКА: архив Xray повреждён"; exit 1; }
install -m755 "$TMP/xray" "$INSTALL_DIR/xray"
XRAY_VER=$("$INSTALL_DIR/xray" version | head -1 | awk '{print $2}')
echo "  Xray $XRAY_VER"

# === REALITY ключи мастера ===
KEYS=$("$INSTALL_DIR/xray" x25519)
PRIV=$(echo "$KEYS" | grep PrivateKey | awk '{print $2}')
PUB=$(echo "$KEYS" | grep -E 'Password|PublicKey' | sed 's/.*: //')
SID=$(openssl rand -hex 4)
TUNNEL_UUID=$(cat /proc/sys/kernel/random/uuid)

# === верификация релиза (SHA-256 + Ed25519 подпись, принцип «не доверяй — проверяй») ===
# Публичный ключ подписи — в репо assets/allowed_signers. Не совпало → отказ установки.
verify_artifact() {
  local file="$1" name="$2"
  local base="https://github.com/${REPO}/releases/latest/download"
  local raw="https://raw.githubusercontent.com/${REPO}/main/assets"
  # SHA256SUMS + подпись + allowed_signers (кешируем в TMP)
  [[ -f "$TMP/SHA256SUMS" ]] || curl -fsSL -o "$TMP/SHA256SUMS" "$base/SHA256SUMS" 2>/dev/null || return 1
  [[ -f "$TMP/SHA256SUMS.sig" ]] || curl -fsSL -o "$TMP/SHA256SUMS.sig" "$base/SHA256SUMS.sig" 2>/dev/null || return 1
  [[ -f "$TMP/allowed_signers" ]] || curl -fsSL -o "$TMP/allowed_signers" "$raw/allowed_signers" 2>/dev/null || return 1
  # подпись файла SHA256SUMS (Ed25519, namespace xkit-release)
  if ! ssh-keygen -Y verify -f "$TMP/allowed_signers" -I xkit-release -n xkit-release -s "$TMP/SHA256SUMS.sig" < "$TMP/SHA256SUMS" >/dev/null 2>&1; then
    echo "  ✗ ПОДПИСЬ РЕЛИЗА НЕВЕРНА — установка остановлена (не совпало с ключом xkit-release)"; return 2
  fi
  # SHA-256 конкретного файла
  local want got
  want=$(grep "  ${name}$" "$TMP/SHA256SUMS" | awk '{print $1}')
  got=$(sha256sum "$file" | awk '{print $1}')
  if [[ -z "$want" || "$want" != "$got" ]]; then
    echo "  ✗ SHA-256 ${name} НЕ СОВПАЛ — установка остановлена"; return 2
  fi
  echo "  ✓ ${name}: подпись и SHA-256 проверены"
  return 0
}

# === панель бинарь ===
echo "→ Установка XKIT Panel…"
# берём из GitHub releases (или локально если есть)
PANEL_URL="https://github.com/${REPO}/releases/latest/download/xkit-panel-linux-${XRAY_ARCH}"
if curl -fsSL -o "$TMP/xkit-panel" "$PANEL_URL" 2>/dev/null; then
  if verify_artifact "$TMP/xkit-panel" "xkit-panel-linux-${XRAY_ARCH}"; then
    install -m755 "$TMP/xkit-panel" "$INSTALL_DIR/xkit-panel"
  else
    echo "  ✗ панель не прошла проверку — установите из исходников: go build ./cmd/panel"; exit 1
  fi
else
  echo "  WARN: релиз не найден, соберите из исходников: go build ./cmd/panel"
  echo "  Продолжаю с конфигурацией (бинарь нужно положить в $INSTALL_DIR/xkit-panel)"
fi

# === агент ноды (лёгкий раннер метрик, ставится на ноды при provision) ===
# Мастер хранит бинарь агента чтобы разливать на ноды. Берём из релиза или собираем.
AGENT_URL="https://github.com/${REPO}/releases/latest/download/xkit-agent-linux-${XRAY_ARCH}"
if curl -fsSL -o "$TMP/xkit-agent" "$AGENT_URL" 2>/dev/null; then
  if verify_artifact "$TMP/xkit-agent" "xkit-agent-linux-${XRAY_ARCH}"; then
    install -m755 "$TMP/xkit-agent" "$INSTALL_DIR/xkit-agent"
    echo "→ агент ноды установлен (метрики изнутри нод через SSH)"
  else
    echo "  ✗ агент не прошёл проверку — соберите: go build ./cmd/agent"
  fi
else
  echo "  NOTE: бинарь агента не найден в релизе — соберите: CGO_ENABLED=0 go build -o $INSTALL_DIR/xkit-agent ./cmd/agent"
fi

# === Telegram-прокси: mtg-multi (MTProto FakeTLS + WEB mode, один бинарь) ===
# dolonet/mtg-multi: Go, arm64, SOCKS5 каскад через ноду, WEB mode встроен
# (заменяет tproxy-server + official C mtproxy). nftables НЕ нужен (UFW deny).
MTGM_VER="1.15.0"
case "$ARCH" in
  x86_64) MTGM_ARCH="amd64";;
  aarch64) MTGM_ARCH="arm64";;
esac
if curl -fsSL --retry 3 --max-time 120 -o "$TMP/mtgm.tgz" \
  "https://github.com/dolonet/mtg-multi/releases/download/v${MTGM_VER}/mtg-multi-${MTGM_VER}-linux-${MTGM_ARCH}.tar.gz" 2>/dev/null; then
  tar xzf "$TMP/mtgm.tgz" -C "$TMP"
  install -m755 "$TMP/mtg-multi-${MTGM_VER}-linux-${MTGM_ARCH}/mtg-multi" "$INSTALL_DIR/mtg-multi"
  echo "→ mtg-multi $MTGM_VER установлен (Telegram MTProto + Web Proxy)"
else
  echo "  NOTE: mtg-multi не скачался — Telegram-прокси недоступен (повторите позже)"
fi

# === секретный путь + пароль ===
SECRET=$(openssl rand -hex 8)
ADMIN_PASS=$(openssl rand -base64 12 | tr -d '/+=' | head -c 16)

# === TLS сертификат ===
# УРОК XKIT 9.3.2 (баг друга): молчаливый провал LE → nginx ссылается на несуществующий
# серт → падает; self-signed для ДОМЕНА ломает TLS-подписки (клиенты не доверяют).
# Правило: домен → ТОЛЬКО доверенный LE, провал = явная ошибка ДО необратимых шагов.
# IP → self-signed с предупреждением «TLS-подписки не работают» (резерв).
echo "→ TLS сертификат…"
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
if [[ "$DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  # IP — self-signed (резерв; TLS-подписки НЕ работают с самоподписанным)
  echo "  ⚠️  IP-адрес: self-signed сертификат. TLS-подписки (ws-tls/security=tls) НЕ будут"
  echo "     работать в клиентах — для полноценных подписок нужен домен + Let's Encrypt."
  mkdir -p /etc/xkit-panel/tls
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout /etc/xkit-panel/tls/privkey.pem -out /etc/xkit-panel/tls/fullchain.pem \
    -days 3650 -subj "/CN=$DOMAIN" 2>/dev/null || { echo "ОШИБКА: не удалось создать self-signed сертификат"; exit 1; }
  CERT_DIR="/etc/xkit-panel/tls"
else
  # домен — Let's Encrypt (единственный доверенный вариант; self-signed для домена ЗАПРЕЩЁН)
  if ! certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" >/dev/null 2>&1; then
    if ! certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" >/dev/null 2>&1; then
      echo "ОШИБКА: не удалось выпустить Let's Encrypt для $DOMAIN."
      echo "  Проверьте: A-запись домена указывает на этот IP, порт 80 открыт, домен валиден."
      echo "  Без доверенного сертификата TLS-подписки не работают — установка прервана."
      exit 1
    fi
  fi
  # проверка что серт реально создан (не доверяем exit-коду certbot)
  if [[ ! -f "$CERT_DIR/fullchain.pem" || ! -f "$CERT_DIR/privkey.pem" ]]; then
    echo "ОШИБКА: certbot отчитался OK, но файлы сертификата не найдены в $CERT_DIR"
    exit 1
  fi
fi

# === camo сайт (маскировка) — sitegen: правдоподобный SaaS/игровой сервер ===
mkdir -p "$CAMO_DIR" /usr/local/lib/xkit-panel
# копируем генератор (если есть рядом с install.sh)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "$SCRIPT_DIR/tools/sitegen.py" ]]; then
  cp "$SCRIPT_DIR/tools/sitegen.py" /usr/local/lib/xkit-panel/sitegen.py
  cp "$SCRIPT_DIR/tools/camo_sitegen.py" /usr/local/lib/xkit-panel/camo_sitegen.py
fi
if [[ ! -f "$CAMO_DIR/index.html" ]]; then
  CAMO_SEED="$(head -c 32 /dev/urandom | xxd -p -c 64)"
  if [[ -f /usr/local/lib/xkit-panel/sitegen.py ]]; then
    python3 /usr/local/lib/xkit-panel/camo_sitegen.py --seed "$CAMO_SEED" --out "$CAMO_DIR" --domain "$DOMAIN" -q 2>/dev/null || true
  fi
  # fallback если sitegen не сработал
  if [[ ! -f "$CAMO_DIR/index.html" ]]; then
    echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Welcome</title></head><body><h1>It works!</h1></body></html>' > "$CAMO_DIR/index.html"
  fi
fi

# === Xray config мастера ===
cat > "$XRAY_DIR/config.json" << XEOF
{
  "log":{"loglevel":"warning"},
  "api":{"tag":"api","listen":"127.0.0.1:62789","services":["HandlerService","RoutingService","StatsService","ReflectionService"]},
  "stats":{},
  "policy":{"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true},"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true}}},
  "inbounds":[
    {"tag":"vless-reality","listen":"0.0.0.0","port":443,"protocol":"vless","settings":{"clients":[],"decryption":"none"},
     "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"show":false,"dest":"127.0.0.1:8443","xver":0,"serverNames":["$DOMAIN"],"privateKey":"$PRIV","shortIds":["$SID"]}}},
    {"tag":"api-in","listen":"127.0.0.1","port":62789,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}}
  ],
  "dns":{"servers":["1.1.1.1","8.8.8.8"],"queryStrategy":"UseIPv4"},
  "outbounds":[{"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}},{"tag":"blackhole","protocol":"blackhole"},{"tag":"api","protocol":"freedom"}],
  "routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","inboundTag":["api-in"],"outboundTag":"api"},{"type":"field","port":"0-65535","outboundTag":"direct"}]}
}
XEOF

# === BBR + сетевой tuning (как XKIT: ускорение TCP, буферы) ===
cat > /etc/sysctl.d/99-xkit.conf << 'SYSEOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
SYSEOF
sysctl --system >/dev/null 2>&1
echo "  ✓ BBR + fq + buffers enabled"

# === systemd ===
cat > /etc/systemd/system/xray.service << 'XEOF'
[Unit]
Description=Xray-core (XKIT Panel)
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
XEOF

mkdir -p "$DATA_DIR" /etc/systemd/system/xkit-panel.service.d
cat > /etc/systemd/system/xkit-panel.service << XEOF
[Unit]
Description=XKIT Panel
After=network.target xray.service
Wants=xray.service
[Service]
Type=simple
Environment=XKIT_LISTEN=127.0.0.1:8080
Environment=XKIT_DB=$DATA_DIR/panel.db
Environment=XKIT_XRAY_API=127.0.0.1:62789
Environment=XKIT_SECRET_PATH=$SECRET
Environment=XKIT_DOMAIN=$DOMAIN
Environment=XKIT_REALITY_PUB=$PUB
Environment=XKIT_REALITY_SID=$SID
ExecStart=$INSTALL_DIR/xkit-panel
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
XEOF
cat > /etc/systemd/system/xkit-panel.service.d/pass.conf << XEOF
[Service]
Environment=XKIT_ADMIN_PASS=$ADMIN_PASS
XEOF
chmod 600 /etc/systemd/system/xkit-panel.service.d/pass.conf
# сохраняем tunnel_uuid для каскада
echo "tunnel_uuid=$TUNNEL_UUID" > "$DATA_DIR/tunnel.env"

# === nginx маскировка ===
# nginx.org пакет использует conf.d/*.conf (НЕ sites-enabled Ubuntu). Пишем в conf.d.
mkdir -p /etc/nginx/conf.d
rm -f /etc/nginx/conf.d/default.conf  # дефолтный :80 конфликтует
cat > /etc/nginx/conf.d/xkit-panel.conf << XEOF
server {
    listen 127.0.0.1:8443 ssl;
    server_name $DOMAIN;
    ssl_certificate $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/privkey.pem;
    root $CAMO_DIR;
    index index.html;
    location /$SECRET/ {
        proxy_pass http://127.0.0.1:8080/$SECRET/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
    location = /$SECRET { return 301 /$SECRET/; }
    location /sub/ { proxy_pass http://127.0.0.1:8080/sub/; proxy_set_header Host \$host; }
    location ~ "^/s[0-9a-f]{12}/" { proxy_pass http://127.0.0.1:8080; proxy_set_header Host \$host; }
    location / { try_files \$uri \$uri/ /index.html; }
}
server {
    listen 80;
    server_name $DOMAIN;
    root $CAMO_DIR;
    location / { try_files \$uri \$uri/ /index.html; }
}
# plaintext fallback для xray TLS-dispatcher (TLS уже снят, :8443 ssl не примет)
server {
    listen 127.0.0.1:8081;
    server_name $DOMAIN;
    root $CAMO_DIR;
    index index.html;
    location /$SECRET/ {
        proxy_pass http://127.0.0.1:8080/$SECRET/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
    location = /$SECRET { return 301 /$SECRET/; }
    location /sub/ { proxy_pass http://127.0.0.1:8080/sub/; proxy_set_header Host \$host; }
    location ~ "^/s[0-9a-f]{12}/" { proxy_pass http://127.0.0.1:8080; proxy_set_header Host \$host; }
    location / { try_files \$uri \$uri/ /index.html; }
}
XEOF
# уберём Ubuntu-стиль симлинки если остались (nginx.org их не читает)
rm -f /etc/nginx/sites-enabled/xkit-panel.conf /etc/nginx/sites-enabled/default 2>/dev/null || true

# === FIREWALL (автоматика панели, директива «домохозяйка») ===
# Панель сама управляет UFW при старте (InitFirewall): default deny incoming,
# ssh/http/https + порты активных протоколов. Здесь — базовая страховка до старта панели.
if command -v ufw >/dev/null 2>&1; then
  ufw default deny incoming >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  ufw allow 22/tcp comment 'XKIT:ssh' >/dev/null 2>&1   # SSH НЕ закрываем никогда
  ufw allow 80/tcp comment 'XKIT:http' >/dev/null 2>&1
  ufw allow 443/tcp comment 'XKIT:https' >/dev/null 2>&1
  ufw --force enable >/dev/null 2>&1
  echo "→ UFW: deny incoming, открыты 22/80/443 (порты протоколов панель откроет сама)"
fi

# === запуск ===
systemctl daemon-reload
nginx -t || { echo "ОШИБКА: nginx конфиг невалиден (проверьте сертификат/пути)"; exit 1; }
systemctl restart nginx
systemctl enable xray xkit-panel >/dev/null 2>&1
systemctl restart xray
sleep 2
systemctl restart xkit-panel
sleep 2

# === ПРОВЕРКА ЭФФЕКТА (УРОК XKIT: «без ERR в логе» ≠ «сработало») ===
# Шаги, обёрнутые || true, падают молча — проверяем живой результат, не exit-код.
echo "→ Проверка установки…"
VERIFY_FAIL=0
if ! systemctl is-active --quiet xray; then echo "  ✗ xray не запущен (journalctl -u xray)"; VERIFY_FAIL=1; else echo "  ✓ xray активен"; fi
if ! systemctl is-active --quiet xkit-panel; then echo "  ✗ панель не запущена (journalctl -u xkit-panel)"; VERIFY_FAIL=1; else echo "  ✓ панель активна"; fi
if ! systemctl is-active --quiet nginx; then echo "  ✗ nginx не запущен"; VERIFY_FAIL=1; else echo "  ✓ nginx активен"; fi
# camo-заглушка на месте (маскировка)
if [[ ! -f "$CAMO_DIR/index.html" ]]; then echo "  ✗ camo-сайт не создан"; VERIFY_FAIL=1; else echo "  ✓ camo-сайт на месте"; fi
# панель отвечает через секретный путь (живой HTTP-замер)
PANEL_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -k "https://127.0.0.1:8443/$SECRET/" -H "Host: $DOMAIN" 2>/dev/null || echo "000")
if [[ "$PANEL_CODE" != "200" && "$PANEL_CODE" != "302" && "$PANEL_CODE" != "301" ]]; then
  echo "  ⚠️  панель по секретному пути ответила HTTP=$PANEL_CODE (ожидался 200/302) — проверьте вручную"
else
  echo "  ✓ панель отвечает (HTTP $PANEL_CODE)"
fi
if [[ "$VERIFY_FAIL" == "1" ]]; then
  echo ""
  echo "⚠️  Установка завершена, но НЕ все службы поднялись. Реквизиты ниже, диагностика:"
  echo "    journalctl -u xray -u xkit-panel -u nginx -n 50 --no-pager"
fi

rm -rf "$TMP"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║         XKIT Panel установлен!               ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "  Панель:  https://$DOMAIN/$SECRET/"
# логин случайный (не admin), пароль одноразовый — панель прочитает first-login.txt
if [[ -f "$DATA_DIR/first-login.txt" ]]; then
  echo "  Логин:   $(grep '^login=' "$DATA_DIR/first-login.txt" | cut -d= -f2)"
  echo "  Пароль:  $(grep '^password=' "$DATA_DIR/first-login.txt" | cut -d= -f2) (одноразовый — сменить при входе)"
else
  echo "  Логин:   см. journalctl -u xkit-panel | grep 'ПЕРВЫЙ ЗАПУСК'"
  echo "  Пароль:  одноразовый, см. лог панели"
fi
echo "  Забыли пароль? SSH: xkit-panel reset-password"
echo ""
echo "  Xray:    $XRAY_VER"
echo "  Маскировка: camo-сайт + секретный путь (по умолчанию)"
echo "  Подписки: https://$DOMAIN/<префикс>/<subId> (префикс и ссылки — в панели, раздел Клиенты)"
echo ""
echo "  Сохраните пароль! Сменить можно в панели: Настройки → 🔑"
echo ""