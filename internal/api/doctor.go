package api

import (
	"regexp"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type DoctorCheck struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"` // ok, warn, error, checking
	Detail  string `json:"detail"`
	Fixable bool   `json:"fixable"`
	FixLabel string `json:"fix_label,omitempty"`
}

func (s *Server) doctorRun(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.runDoctorChecks())
}

func (s *Server) runDoctorChecks() []DoctorCheck {
	var checks []DoctorCheck
	add := func(id, name, status, detail string, fixable bool, fixLabel string) {
		checks = append(checks, DoctorCheck{ID: id, Name: name, Status: status, Detail: detail, Fixable: fixable, FixLabel: fixLabel})
	}

	// 1. Certificate expiry
	certPath := "/etc/letsencrypt/live/" + s.domain + "/fullchain.pem"
	if out, err := exec.Command("openssl", "x509", "-enddate", "-noout", "-in", certPath).Output(); err == nil {
		dateStr := strings.TrimSpace(strings.TrimPrefix(string(out), "notAfter="))
		if t, err := time.Parse("Jan  2 15:04:05 2006 MST", dateStr); err == nil {
			days := int(time.Until(t).Hours() / 24)
			if days > 14 { add("cert", "Сертификат TLS", "ok", fmt.Sprintf("Действителен ещё %d дн.", days), false, "")
			} else if days > 0 { add("cert", "Сертификат TLS", "warn", fmt.Sprintf("Истекает через %d дн.!", days), true, "Продлить")
			} else { add("cert", "Сертификат TLS", "error", "ИСТЁК!", true, "Продлить") }
		} else { add("cert", "Сертификат TLS", "warn", "Не удалось разобрать дату: "+dateStr, true, "Продлить") }
	} else { add("cert", "Сертификат TLS", "error", "Сертификат не найден: "+certPath, true, "Выпустить") }

	// 2. Camo alive
	if out, err := exec.Command("curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", "https://"+s.domain+"/").Output(); err == nil && strings.TrimSpace(string(out)) == "200" {
		add("camo", "Camo-сайт", "ok", "Отдаёт 200", false, "")
	} else { add("camo", "Camo-сайт", "error", "Не отвечает или не 200", true, "Сгенерировать") }

	// 3. Xray alive
	if out, err := exec.Command("systemctl", "is-active", "xray").Output(); err == nil && strings.TrimSpace(string(out)) == "active" {
		add("xray", "Xray-core", "ok", "Работает", false, "")
	} else { add("xray", "Xray-core", "error", "Не работает!", true, "Перезапустить") }

	// 4. Xray version
	if out, err := exec.Command("/usr/local/bin/xray", "version").Output(); err == nil {
		ver := strings.Fields(string(out))
		if len(ver) > 1 { add("xray_ver", "Версия Xray", "ok", ver[1], false, "") }
	} else { add("xray_ver", "Версия Xray", "warn", "Не удалось определить", false, "") }

	// 5. REALITY anchor
	if ib, _ := s.store.GetInbound("vless-reality"); ib != nil && ib.Enabled {
		add("reality", "REALITY якорь :443", "ok", "Включён", false, "")
	} else { add("reality", "REALITY якорь :443", "error", "Выключен или отсутствует!", true, "Включить") }

	// 5b. Hysteria2: РЕАЛЬНАЯ auth-проба (аудит #2c) — порт может слушать,
	// но inbound без users отвечает 404 на любой auth.
	for _, c := range s.doctorHy2Smoke() {
		checks = append(checks, c)
	}

	// 6. Subscription alive
	subPrefix := s.store.SubPrefix()
	if subPrefix != "" {
		testURL := "https://" + s.domain + "/" + subPrefix + "/"
		if out, err := exec.Command("curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", testURL).Output(); err == nil {
			code := strings.TrimSpace(string(out))
			if code == "200" || code == "404" { add("sub", "Подписки", "ok", "Endpoint отвечает ("+code+")", false, "")
			} else { add("sub", "Подписки", "warn", "HTTP "+code, true, "Перезапустить панель") }
		} else { add("sub", "Подписки", "error", "Не отвечает", true, "Перезапустить панель") }
	} else { add("sub", "Подписки", "warn", "Префикс не задан", false, "") }

	// 7. BBR
	if out, err := exec.Command("sysctl", "-n", "net.ipv4.tcp_congestion_control").Output(); err == nil && strings.TrimSpace(string(out)) == "bbr" {
		add("bbr", "BBR", "ok", "Включён", false, "")
	} else { add("bbr", "BBR", "warn", "Не включён", true, "Включить") }

	// 8. UFW
	if out, err := exec.Command("ufw", "status").Output(); err == nil && strings.Contains(string(out), "Status: active") {
		needed := s.neededPorts()
		missing := []string{}
		for port, proto := range needed {
			if !strings.Contains(string(out), fmt.Sprintf("%d", port)) { missing = append(missing, fmt.Sprintf("%d/%s", port, proto)) }
		}
		if len(missing) == 0 { add("ufw", "Firewall (UFW)", "ok", "Активен, порты открыты", false, "")
		} else { add("ufw", "Firewall (UFW)", "warn", "Не открыты: "+strings.Join(missing, ", "), true, "Открыть") }
	} else { add("ufw", "Firewall (UFW)", "warn", "Не активен", true, "Включить") }

	// 9. fail2ban
	if out, err := exec.Command("systemctl", "is-active", "fail2ban").Output(); err == nil && strings.TrimSpace(string(out)) == "active" {
		add("f2b", "Fail2ban", "ok", "Работает", false, "")
	} else { add("f2b", "Fail2ban", "warn", "Не работает", true, "Установить/запустить") }

	// 10. Disk space
	if out, err := exec.Command("df", "--output=avail", "-B1", "/").Output(); err == nil {
		lines := strings.Fields(string(out))
		if len(lines) > 1 {
			var avail int64
			fmt.Sscanf(lines[1], "%d", &avail)
			gb := avail / (1024*1024*1024)
			if gb > 2 { add("disk", "Диск", "ok", fmt.Sprintf("%d GB свободно", gb), false, "")
			} else if gb > 0 { add("disk", "Диск", "warn", fmt.Sprintf("Мало: %d GB", gb), false, "")
			} else { add("disk", "Диск", "error", "Нет места!", false, "") }
		}
	}

	// 11. Geo files
	if _, err := os.Stat("/usr/local/share/xray/geoip.dat"); err == nil {
		if _, err2 := os.Stat("/usr/local/share/xray/geosite.dat"); err2 == nil {
			add("geo", "GeoIP/GeoSite", "ok", "Файлы на месте", false, "")
		} else { add("geo", "GeoIP/GeoSite", "warn", "geosite.dat отсутствует", true, "Скачать") }
	} else { add("geo", "GeoIP/GeoSite", "warn", "geoip.dat отсутствует", true, "Скачать") }

	// 12. nginx
	if out, err := exec.Command("systemctl", "is-active", "nginx").Output(); err == nil && strings.TrimSpace(string(out)) == "active" {
		add("nginx", "Nginx", "ok", "Работает", false, "")
	} else { add("nginx", "Nginx", "error", "Не работает!", true, "Перезапустить") }

	// 13. Backup freshness
	bkDir := "/var/lib/xkit-panel/backups"
	if entries, err := os.ReadDir(bkDir); err == nil && len(entries) > 0 {
		latest := entries[len(entries)-1]
		if info, err := latest.Info(); err == nil {
			age := time.Since(info.ModTime())
			if age < 7*24*time.Hour { add("backup", "Бэкап", "ok", fmt.Sprintf("Последний: %d дн. назад", int(age.Hours()/24)), false, "")
			} else { add("backup", "Бэкап", "warn", fmt.Sprintf("Старый: %d дн.", int(age.Hours()/24)), true, "Создать") }
		}
	} else { add("backup", "Бэкап", "warn", "Бэкапов нет", true, "Создать") }

	// === Ноды (через агент /doctor) ===
	if nodes, e := s.store.AllNodes(); e == nil {
		for _, n := range nodes {
			if !n.Enabled { continue }
			prefix := "node_" + n.Name + "_"
			// SSH + curl агент /doctor
			token := s.agentToken(n.ID)
			remote := fmt.Sprintf("curl -s --max-time 8 -H 'X-Agent-Token: %s' http://127.0.0.1:%d/doctor", token, agentPort)
			out, err := s.sshToNode(n.Host, remote)
			if err != nil {
				add(prefix+"ssh", n.Name+": SSH/агент", "error", "Недоступен: "+err.Error(), false, "")
				continue
			}
			var nodeChecks []DoctorCheck
			if json.Unmarshal([]byte(strings.TrimSpace(out)), &nodeChecks) != nil {
				add(prefix+"agent", n.Name+": агент", "warn", "Не удалось разобрать ответ", false, "")
				continue
			}
			for _, nc := range nodeChecks {
				add(prefix+nc.ID, n.Name+": "+nc.Name, nc.Status, nc.Detail, nc.Fixable, "")
			}
		}
	}
	return checks
}

func (s *Server) doctorFix(w http.ResponseWriter, r *http.Request) {
	var body struct{ ID string `json:"id"` }
	json.NewDecoder(r.Body).Decode(&body)
	var result string
	var err error
	switch body.ID {
	case "cert":
		out, e := exec.Command("certbot", "renew", "--quiet").CombinedOutput()
		result, err = string(out), e
	case "camo":
		out, e := exec.Command("python3", "/usr/local/lib/xkit-panel/camo_sitegen.py", "--seed", randHex(32), "--out", "/var/www/camo", "--domain", s.domain, "-q").CombinedOutput()
		result, err = string(out), e
	case "xray", "nginx", "sub":
		svc := body.ID
		if svc == "sub" { svc = "xkit-panel" }
		out, e := exec.Command("systemctl", "restart", svc).CombinedOutput()
		result, err = string(out), e
	case "reality":
		s.store.SetInboundEnabled("vless-reality", true)
		result = "vless-reality enabled"
	case "bbr":
		os.WriteFile("/etc/sysctl.d/99-xkit.conf", []byte("net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\nnet.ipv4.ip_forward=1\n"), 0644)
		out, e := exec.Command("sysctl", "--system").CombinedOutput()
		result, err = string(out), e
	case "ufw":
		s.syncFirewall()
		result = "UFW synced"
	case "f2b":
		out, e := exec.Command("bash", "-c", "command -v fail2ban-client >/dev/null || apt-get install -y -qq fail2ban; systemctl enable --now fail2ban").CombinedOutput()
		result, err = string(out), e
	case "geo":
		out, e := exec.Command("bash", "-c", "mkdir -p /usr/local/share/xray; curl -sL https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat -o /usr/local/share/xray/geoip.dat; curl -sL https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat -o /usr/local/share/xray/geosite.dat").CombinedOutput()
		result, err = string(out), e
	case "backup":
		if s.backupMgr != nil { _, e := s.backupMgr.Create(r.Context()); if e != nil { err = e; result = e.Error() } else { result = "Backup created" } } else { result = "Backup manager not available"; err = fmt.Errorf("no backupMgr") }
	default:
		// hy2_<tag>: нормализация version=2 + пересоздание с clients[] (аудит #2)
		if strings.HasPrefix(body.ID, "hy2_") {
			if e := s.fixHysteria2(strings.TrimPrefix(body.ID, "hy2_")); e != nil {
				err, result = e, e.Error()
			} else {
				result = "hysteria2 inbound пересоздан с clients[]"
			}
			break
		}
		http.Error(w, "unknown check id", 400); return
	}
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error(), "output": result})
	} else {
		writeJSON(w, map[string]any{"ok": true, "output": result})
	}
}

// doctorReport — формирует отчёт для комьюнити (JSON, копируется в issue).
func (s *Server) doctorReport(w http.ResponseWriter, r *http.Request) {
	report := map[string]any{
		"panel_version": s.version,
		"domain": s.domain,
		"time": time.Now().UTC().Format(time.RFC3339),
	}
	if out, e := exec.Command("/usr/local/bin/xray", "version").Output(); e == nil { report["xray_version"] = strings.Fields(string(out))[1] }
	if out, e := exec.Command("uname", "-r").Output(); e == nil { report["kernel"] = strings.TrimSpace(string(out)) }
	if out, e := exec.Command("sysctl", "-n", "net.ipv4.tcp_congestion_control").Output(); e == nil { report["congestion"] = strings.TrimSpace(string(out)) }
	if out, e := exec.Command("df", "-h", "/").Output(); e == nil { report["disk"] = strings.TrimSpace(string(out)) }
	if out, e := exec.Command("free", "-m").Output(); e == nil { report["memory_mb"] = strings.TrimSpace(string(out)) }
	if out, e := exec.Command("systemctl", "is-active", "xray", "nginx", "xkit-panel", "fail2ban").Output(); e == nil { report["services"] = strings.TrimSpace(string(out)) }
	// последние ошибки xray
	if out, e := exec.Command("journalctl", "-u", "xray", "--no-pager", "-n", "20", "--priority=err").Output(); e == nil { report["xray_errors"] = strings.TrimSpace(string(out)) }
	// последние 20 строк xray log (accepted/rejected — важно для диагностики)
	if out, e := exec.Command("journalctl", "-u", "xray", "--no-pager", "-n", "20").Output(); e == nil { report["xray_log_tail"] = strings.TrimSpace(string(out)) }
	// nginx error log
	if out, e := exec.Command("tail", "-20", "/var/log/nginx/error.log").Output(); e == nil { report["nginx_errors"] = strings.TrimSpace(string(out)) }
	// routing rules
	if data, e := os.ReadFile("/usr/local/etc/xray/config.json"); e == nil {
		var cfg map[string]any
		json.Unmarshal(data, &cfg)
		if rt, ok := cfg["routing"].(map[string]any); ok { report["routing_rules"] = rt["rules"] }
	}
	// inbounds (без ключей/UUID — только tag/port/protocol/security/enabled)
	if ibs, e := s.store.AllInbounds(); e == nil {
		var ibList []map[string]any
		for _, ib := range ibs {
			ibList = append(ibList, map[string]any{"tag": ib.Tag, "port": ib.Port, "protocol": ib.Protocol, "network": ib.Network, "security": ib.Security, "enabled": ib.Enabled, "hidden": ib.Hidden, "in_sub": ib.InSub})
		}
		report["inbounds"] = ibList
	}
	// UFW status
	if out, e := exec.Command("ufw", "status", "numbered").Output(); e == nil { report["ufw_status"] = strings.TrimSpace(string(out)) }
	// cert expiry
	certPath := "/etc/letsencrypt/live/" + s.domain + "/fullchain.pem"
	if out, e := exec.Command("openssl", "x509", "-enddate", "-noout", "-in", certPath).Output(); e == nil { report["cert_expiry"] = strings.TrimSpace(string(out)) }
	// doctor checks results (запускаем проверки и включаем результат)
	// (вызов doctorRun напрямую — переиспользуем логику)
	report["doctor_checks"] = s.runDoctorChecks()
	// ноды (без SSH-ключей/паролей)
	if nodes, e := s.store.AllNodes(); e == nil {
		var nList []map[string]any
		for _, n := range nodes {
			nList = append(nList, map[string]any{"id": n.ID, "name": n.Name, "country": n.Country, "host": n.Host, "enabled": n.Enabled, "health": n.Health})
		}
		report["nodes"] = nList
	}
	sanitizeReport(report)
	writeJSON(w, report)
}

// sanitizeReport — убирает компрометирующие данные из отчёта для комьюнити:
// IP-адреса, email клиентов, домены, имена нод/хосты. Остаётся только диагностика.
var reIPv4 = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
var reEmail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
var reDomain = regexp.MustCompile(`\b[a-z0-9-]+\.(ru|su|com|net|org|io|me|cloud|uk|de|fr|us|xn--p1ai)\b`)

func sanitizeStr(v string) string {
	v = reEmail.ReplaceAllString(v, "<email>")
	v = reIPv4.ReplaceAllString(v, "<ip>")
	v = reDomain.ReplaceAllString(v, "<domain>")
	return v
}

func sanitizeReport(m map[string]any) {
	// xray_log_tail: содержит IP клиентов + посещённые домены — убираем целиком
	delete(m, "xray_log_tail")
	// nodes: host убираем, имена оставляем (пользователь сам их называл, но лучше обобщить)
	if nodes, ok := m["nodes"].([]map[string]any); ok {
		for i, n := range nodes {
			delete(n, "host")
			n["name"] = fmt.Sprintf("node-%d", i+1)
			nodes[i] = n
		}
	}
	delete(m, "domain")
	for k, v := range m {
		switch val := v.(type) {
		case string:
			m[k] = sanitizeStr(val)
		case []any:
			m[k] = sanitizeSlice(val)
		case []map[string]any:
			for _, item := range val {
				sanitizeReport(item)
			}
		case map[string]any:
			sanitizeReport(val)
		}
	}
	// doctor_checks: имена нод в name/detail → обобщить
	if checks, ok := m["doctor_checks"].([]DoctorCheck); ok {
		for i, c := range checks {
			c.Name = sanitizeStr(c.Name)
			c.Detail = sanitizeStr(c.Detail)
			checks[i] = c
		}
	}
}

func sanitizeSlice(arr []any) []any {
	for i, v := range arr {
		switch val := v.(type) {
		case string:
			arr[i] = sanitizeStr(val)
		case map[string]any:
			sanitizeReport(val)
		case []any:
			arr[i] = sanitizeSlice(val)
		}
	}
	return arr
}