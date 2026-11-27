package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/kambarro/xkit-panel/internal/auth"
	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/tunnel"
)

// qrCode — PNG QR-код ссылки (для сканирования клиентским приложением).
func (s *Server) qrCode(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	if data == "" {
		http.Error(w, "data required", 400); return
	}
	png, err := qrcode.Encode(data, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, err.Error(), 500); return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(png)
}

// changePassword — смена пароля админа (текущий → новый).
// first=true (блокирующий первый вход с одноразовым паролем): current не нужен —
// сессия уже аутентифицирована одноразовым паролем, проверяем must_change.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
		First   bool   `json:"first"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400); return
	}
	if len(body.New) < 8 {
		http.Error(w, "new password min 8 chars", 400); return
	}
	// определяем пользователя из сессии (не доверяем телу запроса)
	username := s.auth.User(r)
	if username == "" {
		http.Error(w, "unauthorized", 401); return
	}
	var hash string
	if err := s.store.DB().QueryRow(`SELECT pass_hash FROM admins WHERE username=?`, username).Scan(&hash); err != nil {
		http.Error(w, "admin not found", 500); return
	}
	if body.First && s.auth.MustChange(username) {
		// первый вход: сессия с одноразовым паролем — current не требуется
	} else if !auth.VerifyPassword(body.Current, hash) {
		http.Error(w, "current password wrong", 403); return
	}
	if auth.VerifyPassword(body.New, hash) {
		http.Error(w, "новый пароль должен отличаться от текущего", 400); return
	}
	if err := s.auth.ChangePassword(username, body.New); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.SetSetting("pass_changed", "1")
	s.store.AddEvent("password", "ok", "пароль админа изменён", "{}")
	writeJSON(w, map[string]string{"ok": "true"})
}

// addNode — добавить ноду: ПРОСТАЯ форма для не-технарей (концепция «для домохозяек»).
// Только IP/домен + пароль root + страна. Цена/приоритет НЕ спрашиваются (дефолт 0,
// балансировщик сам разруливает по тестам/нагрузке — это настройки балансира, не формы).
// Панель сама по SSH (sshpass) ставит Xray на ноде. 0 команд в терминале.
// SSH-ключ — опция для продвинутых (ssh_key путь), по умолчанию пароль.
func (s *Server) addNode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string  `json:"name"`
		Country  string  `json:"country"`
		Host     string  `json:"host"`
		Port     int     `json:"port"`
		Priority int     `json:"priority"` // дефолт 0 (балансир сам), не спрашивается в форме
		Price    float64 `json:"price"`    // дефолт 0 (балансир сам), не спрашивается в форме
		SSHUser  string  `json:"ssh_user"`
		SSHPass  string  `json:"ssh_pass"` // основной способ для не-технарей
		SSHKey   string  `json:"ssh_key"`  // опция для продвинутых (путь к ключу на мастере)
		Tunnel   string  `json:"tunnel"`
		ExpiryDays int   `json:"expiry_days"` // дата аренды (опционально): дней от сегодня, 0 = бессрочно
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400); return
	}
	// УРОК XKIT (валидация на границе доверия + input_clean): trim + проверка.
	body.Host = strings.TrimSpace(body.Host)
	body.Country = strings.TrimSpace(body.Country)
	body.Name = strings.TrimSpace(body.Name)
	// SEC-13: валидация имени (без кавычек/угловых скобок — XSS в onclick)
	if strings.ContainsAny(body.Name, "'\"<>&;|`$") {
		http.Error(w, "имя ноды содержит недопустимые символы", 400); return
	}
	if body.Host == "" || body.Country == "" {
		http.Error(w, "host and country required", 400); return
	}
	// нужен либо пароль, либо ключ (для не-технарей — пароль)
	if body.SSHPass == "" && body.SSHKey == "" {
		http.Error(w, "ssh_pass required (пароль root от сервера ноды)", 400); return
	}
	// имя по умолчанию = страна+host (чтобы не спрашивать лишнее поле)
	if body.Name == "" { body.Name = fmt.Sprintf("%s (%s)", body.Country, body.Host) }
	if body.Port == 0 { body.Port = 443 }
	// price/priority дефолт 0 — балансировщик сам по тестам/нагрузке (не форма)
	if body.Tunnel == "" { body.Tunnel = "reality" }
	if body.SSHUser == "" { body.SSHUser = "root" }

	// country_code: СТАБИЛЬНЫЙ из country_codes (урок QA: не выводить из нод —
	// иначе переустановка ноды меняет код и ломает старые UUID клиентов).
	code, err := s.store.CountryCode(body.Country)
	if err != nil || code == 0 {
		http.Error(w, "не удалось выдать код страны", 500); return
	}

	nodeID := fmt.Sprintf("node-%s-%d", strings.ToLower(body.Country), time.Now().Unix()%10000)

	// SSH-оркестрация установки ноды (асинхронно, статус в events)
	go s.provisionNode(nodeID, body.Name, body.Country, body.Host, body.Port, body.Tunnel, body.SSHUser, body.SSHPass, body.SSHKey, code)

	// сохраняем ноду в SQLite (health=unknown пока ставится)
	// дата аренды (опционально): expiry_days>0 → unix ts, иначе 0 = бессрочно
	var expiry int64
	if body.ExpiryDays > 0 { expiry = time.Now().AddDate(0, 0, body.ExpiryDays).Unix() }
	n := store.Node{ID: nodeID, Name: body.Name, Country: body.Country, CountryCode: code,
		Priority: body.Priority, Price: body.Price, Host: body.Host, Port: body.Port,
		Tunnel: body.Tunnel, Health: "provisioning", Expiry: expiry, Enabled: true}
	s.store.UpsertNode(n)
	s.store.AddEvent("node_add", "info", fmt.Sprintf("нода %s (%s) добавляется: %s", body.Name, body.Country, body.Host), fmt.Sprintf(`{"node":%q}`, nodeID))
	writeJSON(w, map[string]any{"node": n, "status": "provisioning"})
}

// provisionNode — SSH-установка Xray на ноде (бинарь+конфиг+systemd+nginx camo).
func (s *Server) provisionNode(nodeID, name, country, host string, port int, tunnelType, sshUser, sshPass, sshKey string, code uint32) {
	logEvent := func(sev, msg string) {
		s.store.AddEvent("node_provision", sev, fmt.Sprintf("%s: %s", name, msg), fmt.Sprintf(`{"node":%q}`, nodeID))
	}
	// SSH команда helper
	sshCmd := func(remote string) (string, error) {
		args := []string{"-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/var/lib/xkit-panel/known_hosts", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=15"}
		if sshKey != "" {
			args = append(args, "-i", sshKey)
		}
		args = append(args, fmt.Sprintf("%s@%s", sshUser, host), remote)
		var cmd *exec.Cmd
		if sshPass != "" && sshKey == "" {
			cmd = exec.Command("sshpass", append([]string{"-e", "ssh"}, args...)...)
			cmd.Env = append(os.Environ(), "SSHPASS="+sshPass)
		} else {
			cmd = exec.Command("ssh", args...)
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	scpCmd := func(local, remote string) error {
		args := []string{"-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/var/lib/xkit-panel/known_hosts", "-o", "LogLevel=ERROR"}
		if sshKey != "" { args = append(args, "-i", sshKey) }
		args = append(args, local, fmt.Sprintf("%s@%s:%s", sshUser, host, remote))
		var cmd *exec.Cmd
		if sshPass != "" && sshKey == "" {
			cmd = exec.Command("sshpass", append([]string{"-e", "scp"}, args...)...)
			cmd.Env = append(os.Environ(), "SSHPASS="+sshPass)
		} else {
			cmd = exec.Command("scp", args...)
		}
		out, err := cmd.CombinedOutput()
		if err != nil { return fmt.Errorf("%s: %s", err, out) }
		return nil
	}

	logEvent("info", "SSH подключение…")
	if out, err := sshCmd("echo OK; hostname"); err != nil {
		logEvent("error", "SSH failed: "+out)
		s.store.SetNodeHealth(nodeID, "down", 3)
		return
	}
	// УРОК (владелец): первое подключение по паролю → панель ставит СВОЙ SSH-ключ на ноду,
	// дальше работает по ключу (пароль не хранится/не используется повторно).
	if sshPass != "" && sshKey == "" {
		keyPath := "/var/lib/xkit-panel/node_key"
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "xkit-panel").Run()
		}
		if pub, err := os.ReadFile(keyPath + ".pub"); err == nil {
			pubStr := strings.TrimSpace(string(pub))
			// положим pubkey на ноду (идемпотентно: grep -q || echo)
			installKey := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && grep -qF '%s' ~/.ssh/authorized_keys || echo '%s' >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys", pubStr, pubStr)
			if out, err := sshCmd(installKey); err != nil {
				logEvent("warn", "SSH-ключ не установлен (продолжаю по паролю): "+out)
			} else {
				// переключаемся на ключ для всех последующих команд
				sshKey = keyPath
				sshPass = ""
				logEvent("info", "SSH-ключ панели установлен на ноде — дальше по ключу")
			}
		}
	}
	// копируем xray бинарь (с мастера /usr/local/bin/xray).
	// УРОК (QA): scp прямо в /usr/local/bin/xray → "text file busy" если xray запущен
	// (переустановка ноды). Копируем во временный файл, затем install (атомарная замена).
	logEvent("info", "копирую Xray…")
	if err := scpCmd("/usr/local/bin/xray", "/tmp/xray-new"); err != nil {
		logEvent("error", "scp xray: "+err.Error())
		s.store.SetNodeHealth(nodeID, "down", 3)
		return
	}
	if out, err := sshCmd("systemctl stop xray 2>/dev/null; install -m755 /tmp/xray-new /usr/local/bin/xray && rm -f /tmp/xray-new && echo installed"); err != nil || !strings.Contains(out, "installed") {
		logEvent("error", "install xray: "+out)
		s.store.SetNodeHealth(nodeID, "down", 3)
		return
	}
	// генерим REALITY ключи ноды
	out, err := sshCmd("/usr/local/bin/xray x25519 2>/dev/null | head -2")
	if err != nil {
		logEvent("error", "x25519: "+err.Error())
		s.store.SetNodeHealth(nodeID, "down", 3)
		return
	}
	priv, pub := parseX25519(out)
	sid := fmt.Sprintf("%08x", time.Now().UnixNano()%0xffffffff)
	// tunnel uuid (общий для каскада). SEC-03: никакого хардкода — берём из settings
	// (заполняется при старте из tunnel.env), при пустом значении генерим crypto/rand.
	tunnelUUID := s.store.GetSetting("tunnel_uuid", "")
	if tunnelUUID == "" {
		tunnelUUID = newUUID()
		s.store.SetSetting("tunnel_uuid", tunnelUUID)
	}

	// транспорт каскада (УРОК: не ограничены 3X-UI — любой транспорт Xray 26.x).
	// xhttp-reality приоритет (лучший анти-DPI), дефолт tcp-reality (проверен E2E).
	tr := tunnel.TCPReality
	switch tunnelType {
	case "xhttp", "xhttp-reality": tr = tunnel.XHTTPReality
	case "ws", "ws-tls": tr = tunnel.WSTLS
	case "grpc", "grpc-tls": tr = tunnel.GRPCTLS
	case "hysteria2", "hy2": tr = tunnel.Hysteria2
	}
	tp := tunnel.Params{Transport: tr, Host: host, Port: port, UUID: tunnelUUID,
		PublicKey: pub, PrivateKey: priv, ShortID: sid, SNI: host, MTU: s.store.NodeMTU(nodeID)}
	// УРОК (QA BUG#21): REALITY serverName ДОЛЖЕН совпадать с доменом camo-cert ноды
	// (nginx dest 127.0.0.1:8443). Если host=IP, клиент получит x509 "no IP SANs".
	// Читаем домен из nginx cert на ноде; если host уже домен — оставляем.
	if net.ParseIP(host) != nil {
		// grep -R (следует по symlink sites-enabled), читаем домен из letsencrypt cert пути
		certDomain, _ := sshCmd(`grep -Rh 'ssl_certificate ' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null | grep letsencrypt | head -1 | sed 's|.*/live/||;s|/.*||'`)
		certDomain = strings.TrimSpace(certDomain)
		if certDomain != "" {
			tp.SNI = certDomain
			logEvent("info", "REALITY SNI = "+certDomain+" (домен camo-cert, host=IP)")
		}
	}
	// hysteria2: пароль + obfs (генерим)
	if tr == tunnel.Hysteria2 {
		tp.Hy2Pass = randHex(16)
		tp.Hy2Obfs = randHex(8)
	}
	// конфиг ноды через пакет tunnel (inbound + outbounds + routing)
	nodeIB, err := tp.NodeInbound()
	if err != nil {
		logEvent("error", "tunnel config: "+err.Error())
		s.store.SetNodeHealth(nodeID, "down", 3)
		return
	}
	nodeCfgMap := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"dns": ipv4OnlyDNS(), // аудит #10: IPv6 ноды мёртв — только A-записи
		"inbounds": []any{nodeIB},
		"outbounds": []any{freedomIPv4("direct"), map[string]any{"tag": "blackhole", "protocol": "blackhole"}},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "port": "0-65535", "outboundTag": "direct"}}},
	}
	nodeCfgBytes, _ := json.MarshalIndent(nodeCfgMap, "", "  ")
	nodeCfg := string(nodeCfgBytes)

	// заливаем конфиг через SSH base64-обёрткой (SEC-04: не heredoc — SNI/path
	// внутри JSON могли разорвать heredoc-маркер и выполнить команды на ноде)
	cfgB64 := base64.StdEncoding.EncodeToString([]byte(nodeCfg))
	cfgCmd := fmt.Sprintf("mkdir -p /usr/local/etc/xray && echo '%s' | base64 -d > /usr/local/etc/xray/config.json", cfgB64)
	if out, err := sshCmd(cfgCmd); err != nil {
		logEvent("error", "config: "+out)
		s.store.SetNodeHealth(nodeID, "down", 3)
		return
	}
	// systemd unit
	unit := `[Unit]
Description=Xray-core (XKIT Panel node)
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target`
	unitCmd := fmt.Sprintf("cat > /etc/systemd/system/xray.service << 'XEOF'\n%s\nXEOF\nchmod +x /usr/local/bin/xray; systemctl daemon-reload; systemctl enable xray 2>/dev/null; systemctl restart xray", unit)
	if out, err := sshCmd(unitCmd); err != nil {
		logEvent("error", "systemd: "+out)
		s.store.SetNodeHealth(nodeID, "down", 3)
		return
	}
	// сохраняем tunnel_cfg (pub/sid/transport для мастера outbound)
	tunnelCfgMap := map[string]any{"publicKey": pub, "privateKey": priv, "shortId": sid, "sni": tp.SNI, "uuid": tunnelUUID, "transport": string(tr)}
	if tr == tunnel.Hysteria2 {
		tunnelCfgMap["hy2Pass"] = tp.Hy2Pass
		tunnelCfgMap["hy2Obfs"] = tp.Hy2Obfs
	}
	tunnelCfgBytes, _ := json.Marshal(tunnelCfgMap)
	s.store.DB().Exec(`UPDATE nodes SET tunnel=?, tunnel_cfg=?, health='alive' WHERE id=?`, string(tr), string(tunnelCfgBytes), nodeID)
	logEvent("ok", fmt.Sprintf("нода установлена, транспорт=%s pub=%s sid=%s", tr, pub, sid))

	// BBR + сетевой tuning на ноде (глобальная настройка, как на мастере).
	bbrScript := `cat > /etc/sysctl.d/99-xkit.conf << 'SYSEOF'
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
SYSEOF
sysctl --system >/dev/null 2>&1`
	if out, err := sshCmd(bbrScript); err != nil {
		logEvent("warn", "BBR sysctl: "+out)
	} else {
		logEvent("ok", "BBR + fq + buffers enabled")
	}

	// FIREWALL АВТОМАТИКА на ноде (директива: домохозяйка не трогает ufw).
	// Default deny incoming; открыты только SSH(22)/HTTP(80)/HTTPS(443) + порт туннеля.
	// Панель/gRPC на ноде НЕ слушает публично — лишние порты закрыты.
	nodeProto := "tcp"
	if tr == tunnel.Hysteria2 { nodeProto = "udp" }
	fwScript := fmt.Sprintf(`command -v ufw >/dev/null || { apt-get install -y -qq ufw >/dev/null 2>&1; }
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
ufw allow 22/tcp comment 'XKIT:node-ssh' >/dev/null 2>&1
ufw allow 80/tcp comment 'XKIT:node-http' >/dev/null 2>&1
ufw allow 443/tcp comment 'XKIT:node-https' >/dev/null 2>&1
ufw allow %d/%s comment 'XKIT:node-tunnel' >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1
echo FW_OK`, port, nodeProto)
	if out, err := sshCmd(fwScript); err != nil {
		logEvent("warn", "UFW на ноде не настроен: "+out)
	} else {
		logEvent("info", fmt.Sprintf("UFW ноды: deny incoming, открыты 22/80/443 + %d/%s (туннель)", port, nodeProto))
	}
	// fail2ban на ноде (защита SSH от брутфорса, эскалация 5→5м→1ч→навсегда)
	if out, err := sshCmd(f2bSetupScript()); err != nil || !strings.Contains(out, "F2B_OK") {
		logEvent("warn", "fail2ban на ноде не настроен: "+out)
	} else {
		logEvent("info", "fail2ban ноды настроен (sshd: 5 попыток → 5м/1ч/навсегда)")
	}

	// CAMO на ноде: sitegen с master_seed + node name (лёгкая вариация того же бренда).
	masterSeed := s.store.GetSetting("camo_seed", "")
	if masterSeed == "" { masterSeed = randHex(32); s.store.SetSetting("camo_seed", masterSeed) }
	// копирую генератор на ноду
	if scpCmd("/usr/local/lib/xkit-panel/sitegen.py", "/tmp/xkit-sitegen.py") == nil {
		scpCmd("/usr/local/lib/xkit-panel/camo_sitegen.py", "/tmp/xkit-camo-sitegen.py")
		camoDomain := host // если host=домен — используем; если IP — sitegen сам сгенерит бренд-домен
		camoCmd := fmt.Sprintf(`mkdir -p /usr/local/lib/xkit-panel /var/www/camo
cp /tmp/xkit-sitegen.py /usr/local/lib/xkit-panel/sitegen.py
cp /tmp/xkit-camo-sitegen.py /usr/local/lib/xkit-panel/camo_sitegen.py
python3 /usr/local/lib/xkit-panel/camo_sitegen.py --seed %s --out /var/www/camo --domain %s --node %s -q 2>/dev/null
rm -f /tmp/xkit-sitegen.py /tmp/xkit-camo-sitegen.py
echo CAMO_OK`, masterSeed, camoDomain, name)
		if out, err := sshCmd(camoCmd); err != nil || !strings.Contains(out, "CAMO_OK") {
			logEvent("warn", "camo sitegen на ноде: "+out)
		} else {
			logEvent("ok", "Camo-сайт ноды сгенерирован (вариация мастера, seed "+masterSeed[:8]+"…)")
		}
	}

	// АГЕНТ НОДЫ (метрики изнутри): ставим автоматически если бинарь есть на мастере.
	if _, err := os.Stat("/usr/local/bin/xkit-agent"); err == nil {
		if err := s.installAgent(nodeID, host); err != nil {
			logEvent("warn", "агент не установлен: "+err.Error())
		} else {
			logEvent("info", "агент ноды установлен (метрики изнутри через SSH)")
		}
	}

	// добавляем outbound на мастере (через пакет tunnel — тот же транспорт что нода)
	s.addMasterOutbound(nodeID, tp)
}

// addMasterOutbound — добавляет outbound ноды в конфиг мастера (транспорт из tunnel.Params) + рестарт xray.
func (s *Server) addMasterOutbound(nodeID string, tp tunnel.Params) {
	cfgPath := "/usr/local/etc/xray/config.json"
	out, err := exec.Command("cat", cfgPath).Output()
	if err != nil { return }
	var cfg map[string]any
	if json.Unmarshal(out, &cfg) != nil { return }
	ob, _ := cfg["outbounds"].([]any)
	mob, err := tp.MasterOutbound(nodeID)
	if err != nil {
		s.store.AddEvent("node_provision", "error", "outbound config: "+err.Error(), "{}")
		return
	}
	// УРОК (retunnel): при смене транспорта ЗАМЕНЯЕМ outbound ноды, не дублируем.
	replaced := false
	for i, o := range ob {
		if om, ok := o.(map[string]any); ok && om["tag"] == nodeID {
			ob[i] = mob
			replaced = true
			break
		}
	}
	if !replaced {
		ob = append(ob, mob)
	}
	cfg["outbounds"] = ob
	s.rebuildConfigClients(cfg) // УРОК (QA BUG#23): сохранить клиентов при перезаписи config
	data, _ := json.MarshalIndent(cfg, "", "  ")
	exec.Command("bash", "-c", fmt.Sprintf("cat > %s << 'XEOF'\n%s\nXEOF", cfgPath, data)).Run()
	exec.Command("systemctl", "restart", "xray").Run()
	s.store.AddEvent("node_provision", "ok", fmt.Sprintf("outbound %s (%s) добавлен на мастер", nodeID, tp.Transport), "{}")
	// переподключаем gRPC клиент панели (рестарт xray оборвал соединение)
	time.Sleep(2 * time.Second)
	if s.xray != nil {
		if err := s.xray.Reconnect(); err != nil {
			s.store.AddEvent("node_provision", "warn", "gRPC reconnect: "+err.Error(), "{}")
		} else {
			s.store.AddEvent("node_provision", "ok", "gRPC переподключен после рестарта xray", "{}")
			if s.ctrl != nil {
				s.ctrl.SyncRulesNow(context.Background())
			}
		}
	}
	go s.RestoreInbounds() // УРОК (QA): рестарт xray убивает горячие preset-inbound — восстановить
}

func parseX25519(out string) (priv, pub string) {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "PrivateKey:") {
			priv = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey:"))
		}
		if strings.HasPrefix(line, "Password") || strings.HasPrefix(line, "PublicKey:") {
			pub = strings.TrimSpace(line[strings.Index(line, ":")+1:])
		}
	}
	return
}

// deleteNode — DELETE /api/nodes/delete?id=... : удалить ноду из панели.
// УРОК XKIT 9.3.5 (round-trip соло→+нода→-нода): при удалении ноды ОБЯЗАТЕЛЬНО:
// 1) убрать outbound ноды из config мастера, 2) убрать assignments клиентов,
// 3) пересобрать правила (клиенты уходят на другие ноды страны или catch-all direct),
// 4) при 0 нод — панель возвращается в соло-минимум (api + catch-all direct).
// Никаких мёртвых правил/стран в карте. Нода на хостинге НЕ удаляется (только из панели).
func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("id")
	if nodeID == "" {
		var body struct{ ID string `json:"id"` }
		if json.NewDecoder(r.Body).Decode(&body) == nil { nodeID = body.ID }
	}
	if nodeID == "" { http.Error(w, "id required", 400); return }
	var exists int
	if err := s.store.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE id=?`, nodeID).Scan(&exists); err != nil || exists == 0 {
		http.Error(w, "node not found", 404); return
	}
	// 1) assignments этой ноды — убрать (клиенты будут переназначены reevaluate/failover)
	moved := 0
	if rows, err := s.store.DB().Query(`SELECT email,country FROM assignments WHERE node_id=?`, nodeID); err == nil {
		type ac struct{ email, country string }
		var affected []ac
		for rows.Next() { var a ac; rows.Scan(&a.email, &a.country); affected = append(affected, a) }
		rows.Close()
		s.store.DB().Exec(`DELETE FROM assignments WHERE node_id=?`, nodeID)
		moved = len(affected)
		// переназначить клиентов на живые ноды их страны (если есть)
		if s.ctrl != nil {
			for _, a := range affected {
				if _, err := s.ctrl.PushAssignment(r.Context(), a.email, a.country); err != nil {
					// нет живой ноды страны — клиент упадёт в catch-all direct (соло),
					// это явно логируем, не молча
					s.store.AddEvent("node_delete", "warn", fmt.Sprintf("клиент %s: нет живой ноды страны %s → direct с мастера", a.email, a.country), "{}")
				}
			}
		}
	}
	// 2) удалить ноду из SQLite. УРОК (QA): проверяем ошибку — database locked/busy
	// при MaxOpenConns(1) молча съедал DELETE (нода "воскресала").
	if res, err := s.store.DB().Exec(`DELETE FROM nodes WHERE id=?`, nodeID); err != nil {
		s.store.AddEvent("node_delete", "error", fmt.Sprintf("DELETE nodes %s: %v", nodeID, err), "{}")
		http.Error(w, "delete node: "+err.Error(), 500)
		return
	} else if n, _ := res.RowsAffected(); n == 0 {
		s.store.AddEvent("node_delete", "warn", fmt.Sprintf("DELETE nodes %s: 0 rows (уже удалена?)", nodeID), "{}")
	}
	s.store.DeleteTrafficTotal("node", nodeID) // lifetime-трафик удалённой ноды
	// УРОК (QA): удалить AWG-каскад ноды (иначе осиротевший каскад поднимется при рестарте
	// к несуществующей ноде) + остановить активный каскад.
	s.store.DeleteAWGCascade(nodeID)
	s.stopAWGCascade(nodeID)
	// 3) убрать outbound из config мастера + рестарт + reconnect + пересборка правил
	s.removeMasterOutbound(nodeID)
	// 4) пересобрать коды стран и правила (соло-минимум если нод не осталось)
	if s.ctrl != nil {
		s.ctrl.SyncRulesNow(r.Context())
	}
	var left int
	s.store.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE enabled=1`).Scan(&left)
	s.store.AddEvent("node_delete", "ok", fmt.Sprintf("нода %s удалена из панели (клиентов перенесено: %d, нод осталось: %d)", nodeID, moved, left), fmt.Sprintf(`{"node":%q}`, nodeID))
	writeJSON(w, map[string]any{"ok": true, "deleted": nodeID, "clients_moved": moved, "nodes_left": left, "solo": left == 0})
}

// removeMasterOutbound — убирает outbound ноды из config.json мастера + рестарт xray.
// УРОК XKIT: проверять эффект (outbound реально исчез), не доверять exit-коду.
func (s *Server) removeMasterOutbound(nodeID string) {
	cfgPath := "/usr/local/etc/xray/config.json"
	out, err := exec.Command("cat", cfgPath).Output()
	if err != nil {
		s.store.AddEvent("node_delete", "error", "не прочитан config мастера: "+err.Error(), "{}")
		return
	}
	var cfg map[string]any
	if json.Unmarshal(out, &cfg) != nil {
		s.store.AddEvent("node_delete", "error", "config мастера не JSON", "{}")
		return
	}
	ob, _ := cfg["outbounds"].([]any)
	var kept []any
	removed := false
	for _, o := range ob {
		if m, ok := o.(map[string]any); ok && m["tag"] == nodeID { removed = true; continue }
		kept = append(kept, o)
	}
	if !removed { return } // outbound уже отсутствует — идемпотентно
	cfg["outbounds"] = kept
	s.rebuildConfigClients(cfg) // УРОК (QA BUG#23): сохранить клиентов при перезаписи config
	data, _ := json.MarshalIndent(cfg, "", "  ")
	// атомарная запись: tmp + mv (не heredoc — урок квиллинга)
	tmp := cfgPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		s.store.AddEvent("node_delete", "error", "запись config: "+err.Error(), "{}")
		return
	}
	if err := os.Rename(tmp, cfgPath); err != nil {
		s.store.AddEvent("node_delete", "error", "mv config: "+err.Error(), "{}")
		return
	}
	exec.Command("systemctl", "restart", "xray").Run()
	time.Sleep(2 * time.Second)
	if s.xray != nil {
		if err := s.xray.Reconnect(); err != nil {
			s.store.AddEvent("node_delete", "warn", "gRPC reconnect: "+err.Error(), "{}")
		}
	}
	go s.RestoreInbounds() // УРОК (QA): рестарт xray убивает горячие preset-inbound — восстановить
	s.store.AddEvent("node_delete", "ok", fmt.Sprintf("outbound %s убран с мастера", nodeID), "{}")
}