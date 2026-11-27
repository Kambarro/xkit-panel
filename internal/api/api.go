// Package api — HTTP API XKIT Panel (chi). Дашборд/балансировщик/клиенты/ноды/настройки.
// Control plane: читает SQLite store, пушит изменения в Xray через gRPC (balancer).
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kambarro/xkit-panel/internal/antifilter"
	"github.com/kambarro/xkit-panel/internal/auth"
	"github.com/kambarro/xkit-panel/internal/backup"
	"github.com/kambarro/xkit-panel/internal/balancer"
	"github.com/kambarro/xkit-panel/internal/notify"
	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/subscription"
	"github.com/kambarro/xkit-panel/internal/tgproxy"
	"github.com/kambarro/xkit-panel/internal/xray"
)

type Server struct {
	store     *store.Store
	xray      *xray.Client
	bal       *balancer.Balancer
	ctrl      *balancer.Controller
	botMgr    *BotManager
	backupMgr *backup.Manager
	backupDir string
	auth      *auth.Auth
	version   string
	domain    string
	master    subscription.MasterParams
	awgMu     *awgState
	webhook   *notify.Webhook
	// Telegram-прокси (MTProto FakeTLS + Web Proxy), каскад через ноду
	tgTunnel *tgproxy.Tunnel
	tgMgr    *tgproxy.Manager
	afMgr    *antifilter.Manager
	ctx      context.Context
}

func NewServer(s *store.Store, x *xray.Client, version, domain string) *Server {
	return &Server{store: s, xray: x, bal: balancer.New(s, x), version: version, domain: domain,
		master: subscription.MasterParams{Address: domain, Port: 443, SNI: domain, Fingerprint: "chrome", Flow: "xtls-rprx-vision"}}
}

func (s *Server) SetController(c *balancer.Controller)  { s.ctrl = c }
func (s *Server) SetMaster(m subscription.MasterParams) { s.master = m }
func (s *Server) SetBotManager(m *BotManager)           { s.botMgr = m }
func (s *Server) SetAuth(a *auth.Auth)                  { s.auth = a }
func (s *Server) SetWebhook(w *notify.Webhook)          { s.webhook = w }

const apiRequestTimeout = 240 * time.Second

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(apiRequestTimeout))
	r.Use(limitBody) // SEC-06: лимит тела запроса (MaxBytesReader) для JSON-декодеров
	r.Get("/api/dashboard", s.dashboard)
	r.Get("/api/balancer", s.balancerView)
	r.Get("/api/balancer/settings", s.balancerSettings)
	r.Post("/api/balancer/settings", s.balancerSettings)
	r.Get("/api/clients", s.clients)
	r.Get("/api/nodes", s.nodes)
	r.Get("/api/doctor", s.doctorRun)
	r.Post("/api/doctor/fix", s.doctorFix)
	r.Get("/api/doctor/report", s.doctorReport)
	r.Get("/api/settings", s.getSettings)
	r.Post("/api/settings", s.setSettings)
	r.Get("/api/health", s.health)
	r.Get("/api/system/versions", s.systemVersions)
	r.Get("/api/metrics", s.metricsHistory)
	r.Get("/api/firewall", s.firewallStatus)
	r.Post("/api/firewall/sync", s.firewallSync)
	r.Post("/api/system/restart", s.systemRestart)
	r.Post("/api/system/update", s.systemUpdate)
	r.Get("/api/system/panel-update", s.panelUpdateCheck)
	r.Post("/api/system/panel-update", s.panelUpdateApply)
	r.Get("/api/system/xray-versions", s.xrayVersions)
	r.Get("/api/fail2ban", s.fail2banStatus)
	r.Post("/api/fail2ban/unban", s.fail2banUnban)
	r.Post("/api/fail2ban/setup", s.fail2banSetupNode)
	r.Post("/api/nodes/capacity", s.setNodeCapacity)
	r.Post("/api/nodes/settings", s.nodeSettings)
	r.Post("/api/nodes/toggle", s.nodeToggle)
	r.Get("/api/nodes/quality", s.nodeQuality)
	r.Post("/api/nodes/quality/reset", s.nodeQualityReset)
	r.Get("/api/nodes/quality/all", s.nodesQualityAll)
	r.Get("/api/nodes/agent", s.nodeAgentMetrics)
	r.Post("/api/nodes/agent/install", s.nodeAgentInstall)
	r.Post("/api/nodes/transport", s.changeNodeTransport)
	// survey транспортов каскада (background job + polling)
	r.Post("/api/nodes/survey", s.surveyStart)
	r.Get("/api/nodes/survey", s.surveyStatus)
	r.Get("/api/nodes/tunnel", s.getNodeTunnel)
	r.Post("/api/nodes/tunnel/update", s.updateNodeTunnel)
	r.Get("/api/mtu", s.getMTU)
	r.Post("/api/mtu/default", s.setMTUDefault)
	r.Post("/api/nodes/mtu", s.setNodeMTU)
	r.Post("/api/nodes/mtu-probe", s.probeNodeMTU)
	r.Post("/api/clients/mtu", s.setClientMTU)
	r.Post("/api/clients/mtu-probe", s.probeClientMTU)
	r.Post("/api/nodes/reboot", s.nodeReboot)
	r.Get("/api/nodes/versions", s.nodeVersions)
	r.Post("/api/nodes/update", s.nodeUpdate)
	r.Get("/api/nodes/check", s.nodeCheck)
	r.Post("/api/nodes/awg-cascade", s.awgCascadeHandler)
	r.Get("/api/nodes/awg-cascade", s.awgCascadeStatus)
	r.Get("/api/nodes/awg-cascade/test", s.awgCascadeTest)
	// управление балансировщиком
	r.Post("/api/clients/create", s.createClient)
	r.Post("/api/clients/delete", s.deleteClient)
	r.Post("/api/clients/toggle", s.toggleClient)
	r.Post("/api/clients/renew", s.renewClient)
	r.Post("/api/assign", s.assignClient)
	r.Post("/api/failover", s.failoverNode)
	r.Post("/api/sync", s.syncRules)
	r.Get("/api/testroute", s.testRoute)
	r.Get("/api/rules", s.liveRules)
	r.Get("/api/subscription", s.clientSubscription)
	r.Get("/api/clients/crypto-link", s.clientCryptoLink)
	// per-client роутинг (P2: наш дефолт + кастом поверх)
	r.Get("/api/clients/routing", s.getClientRouting)
	r.Post("/api/clients/routing", s.setClientRouting)
	r.Post("/api/clients/routing/allow", s.setAllowRouting)
	r.Get("/api/clients/routing/deeplink", s.routingDeeplink)
	// дефолт-маршрутизация владельца (админ)
	r.Get("/api/routing/default", s.defaultRouting)
	r.Post("/api/routing/default", s.defaultRouting)
	r.Post("/api/routing/default/reset", s.resetDefaultRouting)
	// режим маршрутизации мастера (solo/ru-direct/antifilter) + always-правила владельца
	r.Get("/api/routing/mode", s.routingMode)
	r.Post("/api/routing/mode", s.routingMode)
	r.Post("/api/routing/antifilter/refresh", s.antifilterRefresh)
	r.Get("/api/master", s.masterInfo)
	r.Get("/api/qr", s.qrCode)
	r.Post("/api/password", s.changePassword)
	r.Post("/api/nodes/add", s.addNode)
	r.Post("/api/nodes/delete", s.deleteNode)
	// трафик-бюджет ноды под биллинг хостера (P1 #5)
	r.Get("/api/nodes/billing", s.nodeBilling)
	r.Post("/api/nodes/billing", s.setNodeBilling)
	r.Post("/api/nodes/billing/reset", s.resetNodeBilling)
	r.Get("/api/setup-status", s.setupStatus)
	// мастер первого запуска (протоколы ≥1, чеклист, завершение)
	r.Get("/api/wizard/protocols", s.wizardProtocols)
	r.Post("/api/wizard/protocols", s.wizardProtocols)
	r.Get("/api/wizard/checklist", s.wizardChecklist)
	r.Post("/api/wizard/done", s.wizardDone)
	// управление протоколами мастера (inbounds, горячо gRPC)
	r.Get("/api/inbounds", s.listInbounds)
	r.Get("/api/inbounds/get", s.getInbound)
	r.Post("/api/inbounds", s.createInbound)
	r.Post("/api/inbounds/update", s.updateInbound)
	r.Post("/api/inbounds/delete", s.deleteInbound)
	r.Post("/api/inbounds/toggle", s.toggleInbound)
	// страна клиента (закрепление предпочтительной) + доступные страны
	r.Post("/api/clients/country", s.setClientCountry)
	r.Get("/api/countries", s.availableCountries)
	// HWID-лимит устройств (P0 #1, стандарт Happ)
	r.Post("/api/clients/hwid-limit", s.setHWIDLimit)
	r.Post("/api/clients/ip-limit", s.setIPLimit)
	r.Get("/api/clients/devices", s.clientDevices)
	r.Post("/api/clients/devices/remove", s.removeDevice)
	// автопродление (P0 #2)
	r.Post("/api/clients/autorenew", s.setAutoRenew)
	r.Get("/api/clients/autorenew", s.getAutoRenew)
	// invite-link самопривязки к TG-боту (P0 #4)
	r.Post("/api/clients/claim-link", s.claimLink)
	r.Post("/api/clients/unlink-tg", s.unlinkTG)
	// группы доступа/тарифы (P1 #8, squads)
	r.Get("/api/squads", s.listSquads)
	r.Post("/api/squads", s.saveSquad)
	r.Post("/api/squads/delete", s.deleteSquad)
	r.Post("/api/squads/assign", s.assignSquad)
	r.Post("/api/squads/bulk", s.bulkAssignSquad)
	r.Get("/api/clients/protocols", s.getClientProtocols)
	r.Post("/api/clients/protocols", s.setClientProtocols)
	// точки входа мастера / CDN-фронтинг (P1 #10)
	r.Get("/api/hosts", s.listHosts)
	r.Post("/api/hosts", s.addHost)
	r.Post("/api/hosts/delete", s.deleteHost)
	// сканер целей маскировки REALITY (порт из XKIT main)
	r.Post("/api/reality/scan", s.scanStart)
	r.Get("/api/reality/scan", s.scanStatus)
	// теги нод + bulk (P1 #13)
	r.Post("/api/nodes/tags", s.setNodeTags)
	r.Get("/api/nodes/by-tag", s.nodesByTag)
	r.Post("/api/nodes/bulk-delete", s.bulkDeleteNodes)
	r.Post("/api/nodes/bulk-enable", s.bulkEnableNodes)
	r.Post("/api/nodes/delete-expired", s.deleteExpiredNodes)
	r.Post("/api/nodes/test-tunnel", s.testTunnel)
	r.Post("/api/nodes/retunnel", s.nodeRetunnel)
	// BUG-01: /api/countries занят availableCountries (схема {country,code} для UI).
	// Справочник стран перенесён на /api/countries/reference (chi молча перезатирал дубль).
	r.Get("/api/countries/reference", s.countries)
	r.Get("/api/events/rollback", s.eventsRollback)
	r.Post("/api/events/rollback", s.rollbackEvent)
	r.Get("/api/camo", s.camoStatus)
	r.Post("/api/camo/upload", s.camoUpload)
	r.Post("/api/camo/generate", s.camoGenerate)
	r.Get("/api/tgproxy", s.tgproxyStatus)
	r.Post("/api/tgproxy/mtproto", s.tgproxyMTProto)
	r.Post("/api/tgproxy/web", s.tgproxyWeb)
	// AmneziaWG сервер в процессе панели (amneziawg-go библиотека)
	r.Get("/api/amnezia", s.awgStatus)
	r.Post("/api/amnezia/enable", s.awgEnable)
	r.Post("/api/amnezia/peer", s.awgCreatePeer)
	r.Get("/api/amnezia/peer", s.awgPeerConf)
	r.Post("/api/amnezia/peer/delete", s.awgDeletePeer)
	// управление Telegram-ботом (меню в UI, без терминала)
	r.Get("/api/bot", s.botStatus)
	r.Post("/api/bot", s.botConfigure)
	r.Post("/api/bot/restart", s.botRestart)
	// бэкапы (настраиваемые, как в XKIT main)
	r.Get("/api/backup", s.backupStatus)
	r.Post("/api/backup/settings", s.backupConfigure)
	r.Post("/api/backup/create", s.backupCreate)
	r.Get("/api/backup/download", s.backupDownload)
	// webhook-уведомления (P1 #14)
	r.Get("/api/webhook", s.webhookStatus)
	r.Post("/api/webhook", s.webhookConfigure)
	r.Post("/api/webhook/test", s.webhookTest)
	return r
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// sysStats — CPU/RAM хоста (лёгкий, без зависимостей).
func sysStats() (cpuPct float64, ramMB int) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	ramMB = int(m.Sys / 1024 / 1024)
	// CPU: грубо по loadavg через /proc (linux)
	cpuPct = readCPUPct()
	return
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	cpu, ram := sysStats()
	hw := readHardware()
	nodes, _ := s.store.NodesByCountry("") // все
	// NodesByCountry("") вернёт пусто — берём все ноды отдельно
	allNodes := s.allNodes()
	type nodeView struct {
		ID       string  `json:"id"`
		Name     string  `json:"name"`
		Country  string  `json:"country"`
		Priority int     `json:"priority"`
		Host     string  `json:"host"`
		Tunnel   string  `json:"tunnel"`
		Health   string  `json:"health"`
		Clients  int     `json:"clients"`
		Load     int     `json:"load"`
		Expiry   int64   `json:"expiry"`
		Note     string  `json:"note"`
		Price    float64 `json:"price"`
		Capacity int     `json:"capacity"`
		Enabled  bool    `json:"enabled"`
	}
	var nv []nodeView
	online := 0
	if s.xray != nil {
		if u, err := s.xray.OnlineUsers(r.Context()); err == nil {
			online = len(u)
		}
	}
	for _, n := range allNodes {
		cnt := 0
		if a, err := s.store.AssignmentsByNode(n.ID); err == nil {
			cnt = len(a)
		}
		nv = append(nv, nodeView{n.ID, n.Name, n.Country, n.Priority, n.Host, n.Tunnel, n.Health, cnt, 0, n.Expiry, n.Note, n.Price, n.Capacity, n.Enabled})
	}
	_ = nodes
	events, _ := s.store.RecentEvents(8)
	rxSec, txSec := netRate()
	// реальный трафик за сегодня (дельта счётчиков из истории метрик)
	trafficToday := int64(0)
	if ms, err := s.store.MetricsSince(time.Now().Unix() - 86400); err == nil && len(ms) > 1 {
		trafficToday = counterDelta(ms, func(m store.MetricSample) int64 { return m.NetRx }) + counterDelta(ms, func(m store.MetricSample) int64 { return m.NetTx })
	}
	writeJSON(w, map[string]any{
		"cpu": cpu, "ram": ram, "clients_online": online, "traffic_today": trafficToday,
		"net_rx_sec": rxSec, "net_tx_sec": txSec,
		"hardware": hw,
		"nodes":    nv, "events": events,
	})
}

func (s *Server) allNodes() []store.Node {
	rows, err := s.store.DB().Query(`SELECT id,name,country,country_code,priority,price,host,port,tunnel,tunnel_cfg,health,health_fails,expiry,enabled,capacity,latency_ms,uptime_pct,quality_score,note FROM nodes ORDER BY country,priority`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []store.Node
	for rows.Next() {
		var n store.Node
		var en int
		rows.Scan(&n.ID, &n.Name, &n.Country, &n.CountryCode, &n.Priority, &n.Price, &n.Host, &n.Port, &n.Tunnel, &n.TunnelCfg, &n.Health, &n.HealthFails, &n.Expiry, &en, &n.Capacity, &n.LatencyMs, &n.UptimePct, &n.QualityScore, &n.Note)
		n.Enabled = en == 1
		out = append(out, n)
	}
	return out
}

func (s *Server) balancerView(w http.ResponseWriter, r *http.Request) {
	all := s.allNodes()
	byCountry := map[string][]store.Node{}
	for _, n := range all {
		byCountry[n.Country] = append(byCountry[n.Country], n)
	}
	type nview struct {
		Name     string `json:"name"`
		Priority int    `json:"priority"`
		Clients  int    `json:"clients"`
		Load     int    `json:"load"`
		Health   string `json:"health"`
	}
	type cview struct {
		Country string  `json:"country"`
		Alive   int     `json:"alive"`
		Total   int     `json:"total"`
		Nodes   []nview `json:"nodes"`
	}
	var countries []cview
	for c, ns := range byCountry {
		alive := 0
		var nvs []nview
		for _, n := range ns {
			if n.Health != "down" {
				alive++
			}
			cnt := 0
			if a, err := s.store.AssignmentsByNode(n.ID); err == nil {
				cnt = len(a)
			}
			nvs = append(nvs, nview{n.Name, n.Priority, cnt, 0, n.Health})
		}
		countries = append(countries, cview{c, alive, len(ns), nvs})
	}
	assigns, _ := s.store.CurrentAssignments()
	type aview struct {
		Email       string `json:"email"`
		Country     string `json:"country"`
		Node        string `json:"node"`
		NodeName    string `json:"node_name"`
		NodeCountry string `json:"node_country"`
		Status      string `json:"status"`
		Variant     bool   `json:"variant"` // явный country-вариант (второе устройство)
	}
	var av []aview
	for _, a := range assigns {
		av = append(av, aview{a.Email, a.Country, a.NodeID, a.NodeName, a.NodeCountry, a.Status, a.Variant})
	}
	if av == nil {
		av = []aview{}
	}
	writeJSON(w, map[string]any{"countries": countries, "assignments": av})
}

func (s *Server) clients(w http.ResponseWriter, r *http.Request) {
	totals := s.store.AllTrafficTotals("client") // ДО Query: MaxOpenConns=1, вложенный query при открытых rows = дедлок
	periods := s.store.AllTrafficPeriods("client")
	rows, err := s.store.DB().Query(`SELECT email,country,enabled,expiry,quota_bytes,used_bytes FROM clients ORDER BY email`)
	if err != nil {
		writeJSON(w, []any{})
		return
	}
	defer rows.Close()
	type cv struct {
		Email           string `json:"email"`
		Country         string `json:"country"`
		Enabled         bool   `json:"enabled"`
		Expiry          int64  `json:"expiry"`
		Quota           int64  `json:"quota_bytes"`
		Used            int64  `json:"used_bytes"`
		TrafficTotal    int64  `json:"traffic_total_bytes"` // lifetime up+down
		TrafficUp       int64  `json:"traffic_up_bytes"`
		TrafficDown     int64  `json:"traffic_down_bytes"`
		TrafficLifetime bool   `json:"traffic_lifetime"` // false = данные ещё не накопились (показан текущий счётчик)
		store.TrafficPeriods
	}
	var out []cv
	for rows.Next() {
		var c cv
		var en int
		rows.Scan(&c.Email, &c.Country, &en, &c.Expiry, &c.Quota, &c.Used)
		c.Enabled = en == 1
		if t, ok := totals[c.Email]; ok {
			c.TrafficTotal, c.TrafficUp, c.TrafficDown, c.TrafficLifetime = t.Total(), t.UpBytes, t.DownBytes, true
		} else {
			c.TrafficTotal = c.Used // накопитель ещё пуст — текущий доступный счётчик
		}
		c.TrafficPeriods = periods[c.Email] // zero если бакетов нет
		out = append(out, c)
	}
	if out == nil {
		out = []cv{}
	}
	writeJSON(w, out)
}

func (s *Server) nodes(w http.ResponseWriter, r *http.Request) {
	all := s.allNodes()
	totals := s.store.AllTrafficTotals("node")
	periods := s.store.AllTrafficPeriods("node")
	type nv struct {
		ID              string  `json:"id"`
		Name            string  `json:"name"`
		Country         string  `json:"country"`
		Priority        int     `json:"priority"`
		Price           float64 `json:"price"`
		Host            string  `json:"host"`
		Tunnel          string  `json:"tunnel"`
		Health          string  `json:"health"`
		Capacity        int     `json:"capacity"`
		Enabled         bool    `json:"enabled"`
		Expiry          int64   `json:"expiry"`
		Note            string  `json:"note"`
		TrafficTotal    int64   `json:"traffic_total_bytes"` // lifetime up+down
		TrafficUp       int64   `json:"traffic_up_bytes"`
		TrafficDown     int64   `json:"traffic_down_bytes"`
		TrafficLifetime bool    `json:"traffic_lifetime"` // false = накопитель пуст, показан биллинг-счётчик периода
		store.TrafficPeriods
	}
	var out []nv
	for _, n := range all {
		v := nv{ID: n.ID, Name: n.Name, Country: n.Country, Priority: n.Priority, Price: n.Price, Host: n.Host, Tunnel: n.Tunnel, Health: n.Health, Capacity: n.Capacity, Enabled: n.Enabled, Expiry: n.Expiry, Note: n.Note}
		if t, ok := totals[n.ID]; ok {
			v.TrafficTotal, v.TrafficUp, v.TrafficDown, v.TrafficLifetime = t.Total(), t.UpBytes, t.DownBytes, true
		} else {
			v.TrafficTotal = s.store.GetNodeBilling(n.ID).UsedBytes // текущий доступный (за биллинг-период)
		}
		v.TrafficPeriods = periods[n.ID] // zero если бакетов нет
		out = append(out, v)
	}
	if out == nil {
		out = []nv{}
	}
	writeJSON(w, out)
}

// truthySetting — нормализация булева значения настройки ('1'/1/true/'true'/'on').
// GET может отдать не строку (число/bool) — строгое ==='1' сбрасывало expert-флаг.
func truthySetting(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x == 1
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "1", "true", "on", "yes":
			return true
		}
	}
	return false
}

func (s *Server) setSettings(w http.ResponseWriter, r *http.Request) {
	// map[string]any: значение может прийти строкой, числом или bool —
	// нормализуем expert_mode в канон '1'/'' (иначе GET-нормализация на фронте врёт).
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	for k, v := range body {
		// контракт UI — {key,value} (toggleExpert); допускаю и плоский {expert_mode:...}
		if k == "key" {
			if ks, ok := v.(string); ok && (ks == "locale" || ks == "theme" || ks == "expert_mode") {
				k = ks
				v = body["value"]
			} else {
				continue
			}
		}
		if k == "value" {
			continue
		}
		if k == "locale" || k == "theme" || k == "expert_mode" {
			val := ""
			if k == "expert_mode" {
				if truthySetting(v) {
					val = "1"
				}
			} else if str, ok := v.(string); ok {
				val = str
			} else {
				continue // locale/theme — только строки
			}
			s.store.SetSetting(k, val)
		}
	}
	writeJSON(w, map[string]string{"ok": "true"})
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "key required", 400)
		return
	}
	writeJSON(w, map[string]string{"key": key, "value": s.store.GetSetting(key, "")})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	xrayOK := false
	if s.xray != nil {
		if _, err := s.xray.ListRules(r.Context()); err == nil {
			xrayOK = true
		}
	}
	writeJSON(w, map[string]any{"panel": "ok", "xray_grpc": xrayOK, "version": s.version, "domain": s.domain})
}
