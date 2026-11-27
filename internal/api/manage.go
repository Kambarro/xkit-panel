package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kambarro/xkit-panel/internal/balancer"
	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/subscription"
)

// createClient — создать клиента: UUID/email/страна → SQLite + AddUser в Xray + Assign.
func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email   string `json:"email"`
		Name    string `json:"name"`
		Country string `json:"country"`
		ExpiryDays int `json:"expiry_days"`
		QuotaGB int    `json:"quota_gb"`
		HWIDLimit int  `json:"hwid_limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400); return
	}
	// УРОК (владелец): соло-сервер — страна не спрашивается (нет нод = выход с мастера).
	// Страна обязательна только если есть ноды (каскад/country-select).
	if body.Email == "" {
		http.Error(w, "name required", 400); return
	}
	// УРОК (владелец): это ИМЯ, не email — не сбивать с толку. Имя = латиница/цифры/._+-
	// (технический идентификатор Xray user). Если не похоже на email — добавим суффикс
	// @xkit.local чтобы Xray routing по email работал (email-формат обязателен в ядре).
	body.Email = strings.TrimSpace(body.Email)
	body.Country = strings.TrimSpace(body.Country)
	if body.Email != "" && !strings.Contains(body.Email, "@") {
		// простое имя → технический email-идентификатор (имя остаётся именем в UI)
		if body.Name == "" { body.Name = body.Email }
		body.Email = body.Email + "@xkit.local"
	}
	if !validClientEmail(body.Email) {
		http.Error(w, "invalid name (только латиница, цифры и . _ + -)", 400); return
	}
	// UUID
	uuid := newUUID()
	subID := hex.EncodeToString(randBytes(8))
	var expiry int64
	if body.ExpiryDays > 0 { expiry = time.Now().AddDate(0, 0, body.ExpiryDays).Unix() }
	var quota int64
	if body.QuotaGB > 0 { quota = int64(body.QuotaGB) * 1024 * 1024 * 1024 }

	// country_code из нод. УРОК (владелец): соло (нет нод) — страна не нужна,
	// клиент выходит с мастера (catch-all direct). Каскад — страна обязательна.
	var code uint32
	var nodeCount int
	s.store.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE enabled=1`).Scan(&nodeCount)
	if nodeCount > 0 {
		if body.Country == "" {
			http.Error(w, "country required (есть ноды — выберите страну выхода)", 400); return
		}
		// канон country_codes (QA BUG-1/7: nodes.country_code рассинхронизирован)
		code, _ = s.store.LookupCountryCode(body.Country)
		var nc int
		s.store.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE country=? AND enabled=1`, body.Country).Scan(&nc)
		if code == 0 || nc == 0 {
			http.Error(w, "unknown country (нет нод в стране "+body.Country+")", 400); return
		}
	}

	cl := store.Client{Email: body.Email, UUID: uuid, SubID: subID, Name: body.Name, Country: body.Country, CountryCode: code, Expiry: expiry, QuotaBytes: quota, Enabled: true}
	if err := s.store.UpsertClient(cl); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	if body.HWIDLimit > 0 {
		s.store.SetClientHWIDLimit(body.Email, body.HWIDLimit)
	}
	// AddUser во ВСЕ включённые vless-inbound (горячо) — подписка сразу работает по всем протоколам
	s.syncInboundUsers(r, body.Email, uuid)
	// AWG: пир автоматически (если сервер включён) — амнезия сразу в подписке
	s.ensureAWGPeer(body.Email)
	// Assign на лучшую ноду страны + push rules (только каскад; соло — catch-all direct)
	var assign *store.Assignment
	if s.ctrl != nil && nodeCount > 0 {
		var err error
		assign, err = s.ctrl.PushAssignment(r.Context(), body.Email, body.Country)
		if err != nil {
			// УРОК: не глотаем ошибку назначения — клиент создан, но маршрут не назначен
			s.store.AddEvent("assign_error", "warn", fmt.Sprintf("клиент %s создан, но назначение не удалось: %v", body.Email, err), "{}")
		}
	}
	s.store.AddEvent("client_created", "ok", fmt.Sprintf("клиент %s создан (%s)", body.Name, body.Country), fmt.Sprintf(`{"email":%q}`, body.Email))
	writeJSON(w, map[string]any{"client": cl, "assignment": assign, "uuid": uuid, "sub_id": subID})
}

// assignClient — переназначить клиента на ноду (страна) вручную.
func (s *Server) assignClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email   string `json:"email"`
		Country string `json:"country"`
		NodeID  string `json:"node_id"` // опционально: конкретная нода
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400); return
	}
	// УРОК (QA BUG-6): валидация ДО записи — иначе 500 FK и сиротские правила в xray.
	body.Email = strings.TrimSpace(body.Email)
	body.Country = strings.TrimSpace(body.Country)
	if body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	cl, _ := s.store.GetClient(body.Email)
	if cl == nil {
		http.Error(w, "client not found", 404); return
	}
	if body.Country != "" && !strings.EqualFold(body.Country, "any") {
		code, _ := s.store.LookupCountryCode(body.Country)
		var nc int
		s.store.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE country=? AND enabled=1`, body.Country).Scan(&nc)
		if code == 0 || nc == 0 {
			http.Error(w, "unknown country (нет нод в стране "+body.Country+")", 400); return
		}
	}
	if s.ctrl == nil {
		http.Error(w, "controller not available (xray offline)", 503); return
	}
	a, err := s.ctrl.PushAssignment(r.Context(), body.Email, body.Country)
	if err != nil {
		http.Error(w, err.Error(), 500); return
	}
	writeJSON(w, map[string]any{"assignment": a})
}

// failoverNode — принудительный failover ноды (симуляция отвала / ручное).
func (s *Server) failoverNode(w http.ResponseWriter, r *http.Request) {
	var body struct { NodeID string `json:"node_id"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400); return
	}
	if s.ctrl == nil || s.xray == nil {
		http.Error(w, "controller not available", 503); return
	}
	// УРОК (QA BUG-10): несуществующая нода → 404, без мусорного события node_down.
	if n := s.getNode(body.NodeID); n == nil {
		http.Error(w, "нода не найдена", 404); return
	}
	// пометить ноду down
	s.store.SetNodeHealth(body.NodeID, "down", 3)
	s.store.AddEvent("node_down", "error", fmt.Sprintf("нода %s принудительно down (failover)", body.NodeID), "{}")
	// failover клиентов (базовое per-user правило, без cs-слоя)
	moved, err := s.bal.FailoverNode(r.Context(), body.NodeID, map[string]balancer.NodeLoad{})
	// УРОК XKIT (никаких молчаливых ошибок): фиксируем результат failover в events,
	// ошибку не глотаем — возвращаем в ответе и пишем событие.
	if err != nil {
		s.store.AddEvent("failover_error", "error", fmt.Sprintf("failover %s: %v", body.NodeID, err), "{}")
	} else {
		s.store.AddEvent("failover", "ok", fmt.Sprintf("нода %s down, перенесено клиентов: %d", body.NodeID, moved), "{}")
	}
	// sync rules через controller
	s.ctrl.SyncRulesNow(r.Context())
	writeJSON(w, map[string]any{"node": body.NodeID, "status": "down", "moved": moved, "failover": "done", "err": fmt.Sprint(err)})
}

// syncRules — принудительная синхронизация правил в Xray.
func (s *Server) syncRules(w http.ResponseWriter, r *http.Request) {
	if s.ctrl == nil {
		http.Error(w, "controller not available", 503); return
	}
	s.ctrl.SyncRulesNow(r.Context())
	writeJSON(w, map[string]string{"sync": "done"})
}

// testRoute — проверить маршрут клиента через Xray gRPC TestRoute (read-only).
func (s *Server) testRoute(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	country := r.URL.Query().Get("country")
	if s.xray == nil {
		http.Error(w, "xray offline", 503); return
	}
	rc, err := s.xray.TestRoute(r.Context(), "vless-reality", email)
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()}); return
	}
	writeJSON(w, map[string]any{"email": email, "country": country, "outbound": rc.GetOutboundTag()})
}

// liveRules — текущие правила Xray через gRPC ListRule (debug).
func (s *Server) liveRules(w http.ResponseWriter, r *http.Request) {
	if s.xray == nil {
		http.Error(w, "xray offline", 503); return
	}
	rules, err := s.xray.ListRules(r.Context())
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()}); return
	}
	type rv struct {
		Outbound    string `json:"outbound"`
		BalancerTag string `json:"balancerTag,omitempty"`
		RuleTag     string `json:"ruleTag"`
	}
	var out []rv
	for _, rl := range rules {
		out = append(out, rv{rl.Tag, "", rl.RuleTag})
	}
	// QA AF-BUG-3: gRPC ListRule отдаёт только outboundTag — у balancerTag-правил
	// он пуст. Обогащаем из персистентного снапшота config.json по ruleTag.
	if data, err := os.ReadFile(masterConfigPath); err == nil {
		var cfg map[string]any
		if json.Unmarshal(data, &cfg) == nil {
			if rt, ok := cfg["routing"].(map[string]any); ok {
				bal := map[string]string{}
				if rulesAny, ok := rt["rules"].([]any); ok {
					for _, ra := range rulesAny {
						rm, ok := ra.(map[string]any)
						if !ok {
							continue
						}
						tag, _ := rm["ruleTag"].(string)
						bt, _ := rm["balancerTag"].(string)
						if tag != "" && bt != "" {
							bal[tag] = bt
						}
					}
				}
				for i := range out {
					out[i].BalancerTag = bal[out[i].RuleTag]
				}
			}
		}
	}
	writeJSON(w, out)
}

// clientSubscription — ссылки/подписка клиента (базовый UUID + QR data).
func (s *Server) clientSubscription(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cl, err := s.store.GetClient(email)
	if err != nil || cl == nil {
		http.Error(w, "client not found", 404); return
	}
	// базовая ссылка (один UUID; страна — clients.country, меняется через API/бот)
	links := subscription.ClientLinks(cl.UUID, cl.Email, cl.Name, s.master)
	sub := subscription.Subscription(links)
	// подписочный URL (base64 отдаётся по /sub/<subId> — later отдельный endpoint)
	writeJSON(w, map[string]any{
		"email": cl.Email, "uuid": cl.UUID, "sub_id": cl.SubID,
		"links": links, "subscription_base64": sub,
		"subscription_url": fmt.Sprintf("https://%s/%s/%s", s.domain, s.store.SubPrefix(), cl.SubID),
		"master": s.master.Address,
	})
}

// masterInfo — параметры мастера (для отладки/подписок).
func (s *Server) masterInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.master)
}

// setupStatus — статус first-run wizard (что настроено).
// УРОК (владелец): мастер = пароль(блокирующий, отдельная страница) → протоколы(≥1) →
// первый клиент(имя) → доп.возможности → чеклист. Ноды/балансир в мастер НЕ входят.
func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	var nodeCount, clientCount, inboundCount int
	s.store.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE enabled=1`).Scan(&nodeCount)
	s.store.DB().QueryRow(`SELECT COUNT(*) FROM clients WHERE enabled=1`).Scan(&clientCount)
	// клиентские inbounds (не служебные api) — признак что панель уже используется
	s.store.DB().QueryRow(`SELECT COUNT(*) FROM inbounds WHERE enabled=1 AND tag NOT IN ('api-in','api')`).Scan(&inboundCount)
	passChanged := s.store.GetSetting("pass_changed", "0") == "1"
	protocolsSelected := s.store.GetSetting("setup_protocols", "") != ""
	wizardDone := s.store.GetSetting("wizard_done", "0") == "1"
	// УРОК (владелец): мастер показываем ТОЛЬКО на реально пустой установке.
	// Есть клиенты ИЛИ клиентские протоколы = панель уже используется → мастер не нужен
	// (старые установки развёрнутые до мастера не должны в него попадать).
	established := clientCount > 0 || inboundCount > 1 // >1: установочный REALITY всегда есть
	writeJSON(w, map[string]any{
		"has_nodes": nodeCount > 0, "node_count": nodeCount,
		"has_clients": clientCount > 0, "client_count": clientCount,
		"pass_changed": passChanged,
		"protocols_selected": protocolsSelected,
		"wizard_done": wizardDone,
		"established": established,
		"complete": passChanged && protocolsSelected && clientCount > 0,
	})
}

// wizardProtocols — GET/POST /api/wizard/protocols: выбор протоколов (шаг 2, минимум 1).
// Список доступных с описанием «зачем»; REALITY рекомендован по умолчанию (не догма).
func (s *Server) wizardProtocols(w http.ResponseWriter, r *http.Request) {
	type proto struct {
		ID string `json:"id"`; Name string `json:"name"`; DescRu string `json:"desc_ru"`; DescEn string `json:"desc_en"`
		Recommended bool `json:"recommended"`; Available bool `json:"available"`
		RAMMB int `json:"ram_mb"`; CPULoad string `json:"cpu_load"`; Light bool `json:"light"`
		CostRu string `json:"cost_ru"`; CostEn string `json:"cost_en"`
		Installed bool `json:"installed"`
	}
	// УРОК (владелец): при выборе протокола предупреждаем о нагрузке —
	// «если не нужно не включайте», целимся в минимальный набор ресурсов.
	protos := []proto{
		{"reality", "VLESS REALITY", "Универсальный: маскируется под обычный сайт, работает везде. Рекомендуется.", "Universal: looks like a regular website, works everywhere. Recommended.", true, true, 0, "низкая", true, "Внутри Xray — почти не добавляет нагрузки.", "Inside Xray — adds almost no load.", false},
		{"xhttp", "VLESS XHTTP", "Лучший анти-DPI (HTTP/2/3 multiplex). Внутри Xray.", "Best anti-DPI (HTTP/2/3 multiplex). Inside Xray.", false, true, 0, "низкая", true, "Внутри Xray — минимальная нагрузка.", "Inside Xray — minimal load.", false},
		{"hysteria2", "Hysteria2", "Быстрый на мобильных сетях и при потерях пакетов (UDP). Отдельный демон.", "Fast on mobile networks and packet loss (UDP). Separate daemon.", false, true, 30, "средняя", false, "Отдельный демон ~30 МБ RAM, QUIC грузит CPU. Включайте если нужен.", "Separate daemon ~30 MB RAM, QUIC uses CPU. Enable only if needed.", false},
		{"ws-tls", "WebSocket + TLS", "Для строгих сетей где блокируют нестандартный трафик (через HTTPS).", "For strict networks that block non-standard traffic (over HTTPS).", false, true, 0, "низкая", true, "Внутри Xray — минимальная нагрузка.", "Inside Xray — minimal load.", false},
		{"trojan-tls", "Trojan + TLS", "Классический Trojan под обычный HTTPS. Совместим со старыми клиентами.", "Classic Trojan over regular HTTPS. Compatible with older clients.", false, true, 0, "низкая", true, "Внутри Xray — минимальная нагрузка.", "Inside Xray — minimal load.", false},
		{"vmess-ws", "VMess + WebSocket", "VMess через WebSocket+TLS. Для совместимости со старыми клиентами.", "VMess over WebSocket+TLS. For legacy client compatibility.", false, true, 0, "низкая", true, "Внутри Xray — минимальная нагрузка.", "Inside Xray — minimal load.", false},
		{"ss2022", "Shadowsocks 2022", "Лёгкий SS-2022 (шифрование без TLS). Минимум накладных.", "Lightweight SS-2022 (encryption without TLS). Minimal overhead.", false, true, 0, "низкая", true, "Внутри Xray — минимальная нагрузка.", "Inside Xray — minimal load.", false},
		{"amnezia", "AmneziaWG", "Обфусцированный WireGuard, устойчив к DPI. Внутри панели (Go).", "Obfuscated WireGuard, DPI-resistant. Inside panel (Go).", false, true, 15, "низкая", true, "Внутри панели ~15 МБ — лёгкий.", "Inside panel ~15 MB — light.", false},
	}
	if r.Method == http.MethodPost {
		var body struct{ Selected []string `json:"selected"` }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400); return
		}
		if len(body.Selected) == 0 {
			http.Error(w, "выберите хотя бы один протокол", 400); return
		}
		// валидация: только известные id
		valid := map[string]bool{"reality": true, "xhttp": true, "hysteria2": true, "ws-tls": true, "amnezia": true, "trojan-tls": true, "vmess-ws": true, "ss2022": true}
		for _, id := range body.Selected {
			if !valid[id] { http.Error(w, "unknown protocol: "+id, 400); return }
		}
		s.store.SetSetting("setup_protocols", strings.Join(body.Selected, ","))
		// Создаём inbounds из пресетов (переиспользуется и при ручном добавлении галочками).
		created, errs := s.applyProtocolPresets(r, body.Selected)
		s.store.AddEvent("wizard", "ok", "протоколы выбраны: "+strings.Join(body.Selected, ","), "{}")
		writeJSON(w, map[string]any{"ok": true, "selected": body.Selected, "created": created, "errors": errs})
		return
	}
	sel := strings.Split(s.store.GetSetting("setup_protocols", ""), ",")
	//installed: пресет уже создан (preset-<id>) ИЛИ есть эквивалентный inbound (protocol/network/security)
	type inst struct{ Protocol, Network, Security string }
	var have []inst
	if rows, err := s.store.DB().Query(`SELECT protocol,network,security FROM inbounds WHERE enabled=1`); err == nil {
		for rows.Next() { var i inst; rows.Scan(&i.Protocol,&i.Network,&i.Security); have = append(have, i) }
		rows.Close()
	}
	presetMap := map[string][3]string{"reality":{"vless","tcp","reality"},"xhttp":{"vless","xhttp","reality"},"ws-tls":{"vless","ws","tls"},"hysteria2":{"hysteria2","udp","tls"},"trojan-tls":{"trojan","tcp","tls"},"vmess-ws":{"vmess","ws","tls"},"ss2022":{"shadowsocks","tcp","none"}}
	for i := range protos {
		if ib, _ := s.store.GetInbound("preset-"+protos[i].ID); ib != nil { protos[i].Installed = true; continue }
		if pm, ok := presetMap[protos[i].ID]; ok {
			for _, h := range have { if h.Protocol==pm[0]&&h.Network==pm[1]&&h.Security==pm[2] { protos[i].Installed = true; break } }
		}
	}
	writeJSON(w, map[string]any{"protocols": protos, "selected": sel})
}

// wizardChecklist — GET /api/wizard/checklist: автодиагностика мастера (финальный шаг).
// УРОК XKIT: проверять ЭФФЕКТ живым замером (DNS/TLS/Xray/порт/camo), не статус-строки.
func (s *Server) wizardChecklist(w http.ResponseWriter, r *http.Request) {
	type check struct {
		ID string `json:"id"`; OK bool `json:"ok"`; MsgRu string `json:"msg_ru"`; MsgEn string `json:"msg_en"`
	}
	var checks []check
	// Xray gRPC жив?
	xrayOK := false
	if s.xray != nil {
		if _, err := s.xray.ListRules(r.Context()); err == nil { xrayOK = true }
	}
	checks = append(checks, check{"xray", xrayOK, "Xray запущен и управляется панелью", "Xray running and managed by panel"})
	// клиенты есть?
	var cc int
	s.store.DB().QueryRow(`SELECT COUNT(*) FROM clients WHERE enabled=1`).Scan(&cc)
	checks = append(checks, check{"clients", cc > 0, fmt.Sprintf("Клиентов: %d", cc), fmt.Sprintf("Clients: %d", cc)})
	// пароль сменён?
	pc := s.store.GetSetting("pass_changed", "0") == "1"
	checks = append(checks, check{"password", pc, "Пароль сменён с одноразового", "Password changed from one-time"})
	// протоколы выбраны?
	pr := s.store.GetSetting("setup_protocols", "") != ""
	checks = append(checks, check{"protocols", pr, "Протоколы выбраны", "Protocols selected"})
	// бэкап настроен?
	bk := s.store.GetSetting("backup_enabled", "1") == "1"
	checks = append(checks, check{"backup", bk, "Авто-бэкапы включены", "Auto-backups enabled"})
	// бот настроен?
	bot := s.store.GetSetting("tg_token", "") != ""
	checks = append(checks, check{"bot", bot, "Telegram-бот настроен (опционально)", "Telegram bot configured (optional)"})
	allOK := xrayOK && cc > 0 && pc && pr
	writeJSON(w, map[string]any{"checks": checks, "all_ok": allOK})
}

// wizardDone — POST /api/wizard/done: завершить мастер.
func (s *Server) wizardDone(w http.ResponseWriter, r *http.Request) {
	s.store.SetSetting("wizard_done", "1")
	s.store.AddEvent("wizard", "ok", "мастер первого запуска завершён", "{}")
	writeJSON(w, map[string]any{"ok": true})
}

func newUUID() string {
	b := randBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// validClientEmail — строгая валидация email клиента (как в боте): только
// латиница/цифры/. _ @ + -, длина 1..64, обязательно @. Кириллица/спецсимволы
// отклоняются — иначе Xray routing по email молча ломается.
func validClientEmail(s string) bool {
	if len(s) == 0 || len(s) > 64 || !strings.Contains(s, "@") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '_' || r == '@' || r == '+' || r == '-') {
			return false
		}
	}
	return true
}