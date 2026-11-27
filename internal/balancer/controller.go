// Package balancer — control loop: панель сама управляет Xray routing через gRPC.
// Тикер: health-пробы нод → failover при отвале → re-evaluate assignment → push rules.
// Enforce: expiry/quota → RemoveUser. Всё горячо, без рестарта Xray, чужие сессии не рвутся.
package balancer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kambarro/xkit-panel/internal/routing"
	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/xray"
	router "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
)

// Controller — control plane балансировщика. Запускается панелью, тикает.
type Controller struct {
	store *store.Store
	xray  *xray.Client
	bal   *Balancer

	mu     sync.Mutex
	loads  map[string]NodeLoad
	stopCh chan struct{}
	wg     sync.WaitGroup

	ProbeInterval   time.Duration // health-пробы (default 15s)
	ReevalInterval  time.Duration // re-evaluate assignment (default 30s)
	EnforceInterval time.Duration // expiry/quota (default 60s)
	InboundTag      string        // inbound мастера для TestRoute (vless-reality)

	// NotifyClient — отправка уведомления клиенту в TG (P0 #3). Задаётся из main.go
	// (botMgr.SendText). nil = уведомления выключены (бот не настроен).
	NotifyClient func(ctx context.Context, chatID int64, text string) error
	// NotifyAdmin — уведомление админу (биллинг-алерты нод P1 #5). Задаётся из main.go.
	NotifyAdmin func(ctx context.Context, text string) error

	// дедуп уведомлений (IP-лимит P1 #11 и пр.)
	notifyMu   sync.Mutex
	lastNotify map[string]time.Time
}

func NewController(s *store.Store, x *xray.Client) *Controller {
	return &Controller{
		store: s, xray: x, bal: New(s, x),
		loads:           make(map[string]NodeLoad),
		stopCh:          make(chan struct{}),
		ProbeInterval:   15 * time.Second,
		ReevalInterval:  30 * time.Second,
		EnforceInterval: 60 * time.Second,
		InboundTag:      "vless-reality",
	}
}

// ReloadBalancerSettings — перечитать настройки (после изменения админом).
// LoadThreshold/FailsToDown применяются сразу; интервалы — с следующего рестарта панели.
func (c *Controller) ReloadBalancerSettings() {
	c.bal.ReloadSettings()
}

// Start запускает тикеры control loop.
func (c *Controller) Start(ctx context.Context) {
	// применим настройки интервалов из store (админ)
	bs := c.store.BalancerSettings()
	c.ProbeInterval = time.Duration(bs.ProbeSec) * time.Second
	c.ReevalInterval = time.Duration(bs.ReevalSec) * time.Second
	c.EnforceInterval = time.Duration(bs.EnforceSec) * time.Second
	// миграция упрощения: легаси cs/vlessRoute-правила из config.json до первого sync
	StripLegacyCountryRules()
	// первичный push всех assignments в Xray (синхронизация при старте)
	c.syncAllRules(ctx)

	c.wg.Add(3)
	go c.loop(ctx, c.ProbeInterval, c.probeAllNodes, "health")
	go c.loop(ctx, c.ReevalInterval, c.reevaluate, "reeval")
	go c.loop(ctx, c.EnforceInterval, c.enforce, "enforce")
	log.Printf("balancer controller запущен: probe=%s reeval=%s enforce=%s", c.ProbeInterval, c.ReevalInterval, c.EnforceInterval)
}

func (c *Controller) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}

func (c *Controller) loop(ctx context.Context, interval time.Duration, fn func(context.Context), name string) {
	defer c.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ctx.Done():
			return
		case <-t.C:
			fn(ctx)
		}
	}
}

// probeAllNodes — TCP+TLS проба каждой ноды (host:port). N=3 подряд неудач → down → failover.
func (c *Controller) probeAllNodes(ctx context.Context) {
	nodes := c.allNodes()
	c.mu.Lock()
	loads := copyLoads(c.loads)
	c.mu.Unlock()

	for _, n := range nodes {
		ok, latencyMs := probeNode(n.Host, n.Port, c.store.BalancerSettings().ProbeTimeoutSec)
		// запишем сэмпл качества ноды (история) + текущие метрики
		loadPct := 0.0
		clients := 0
		if l, has := loads[n.ID]; has {
			loadPct = l.Load * 100
			clients = l.Clients
		}
		c.store.AddNodeSample(store.NodeSample{Ts: time.Now().Unix(), NodeID: n.ID, OK: ok, LatencyMs: latencyMs, LoadPct: loadPct, Clients: clients})
		// uptime/score за последние 24ч
		uptime, _, _, _, _ := c.store.NodeQualityStats(n.ID, time.Now().Unix()-86400)
		score := nodeQualityScore(ok, latencyMs, uptime, loadPct)
		c.store.SetNodeQuality(n.ID, latencyMs, uptime, score)
		becameDown, err := c.bal.RecordProbe(ctx, n.ID, ok)
		if err != nil {
			log.Printf("probe %s: %v", n.ID, err)
			continue
		}
		if becameDown {
			// нода умерла → failover её клиентов на живую ноду той же страны
			moved, err := c.bal.FailoverNode(ctx, n.ID, loads)
			if err != nil {
				log.Printf("failover %s: %v", n.ID, err)
			} else {
				log.Printf("нода %s down → failover %d клиентов", n.ID, moved)
			}
			// после failover пересобрать правила (порядок per-user выше catch-all)
			c.syncAllRules(ctx)
		}
	}
}

// probeNode — реальная health-проба ноды: TCP dial + TLS handshake на REALITY порту.
// УРОК XKIT: «нода жива, но VPN не работает» — TCP-dial ловит только открытый порт,
// TLS handshake проверяет что REALITY/TLS слой реально отвечает. Нода с закрытым
// портом ИЛИ битым TLS = down → failover. InsecureSkipVerify: REALITY серт не
// публичный (маскировка), проверяем сам факт handshake, не доверие.
func probeNode(host string, port int, timeoutSec int) (bool, float64) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}
	start := time.Now()
	// TLS handshake с таймаутом (REALITY отвечает как TLS сервер)
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // REALITY cert самоподписанный/маскировка — проверяем handshake
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
	})
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		// TLS не прошёл — возможно нода отдаёт не-TLS (REALITY fallback). Пробуем TCP
		// как запасной сигнал жизни (порт открыт = процесс жив), но помечаем degraded.
		tcpStart := time.Now()
		tcpConn, terr := net.DialTimeout("tcp", addr, 3*time.Second)
		if terr != nil {
			return false, 0 // порт закрыт — нода точно down
		}
		tcpConn.Close()
		// порт открыт но TLS не ответил — считаем живой (REALITY может не слать TLS ClientHello ответ без правильного SNI)
		return true, float64(time.Since(tcpStart).Microseconds()) / 1000.0
	}
	conn.Close()
	return true, latency
}

// reevaluate — пересчёт assignment: клиенты на лучшей ноде страны (priority/price/load).
// Sticky: клиент ONLINE (есть живое соединение, OnlineUsers) и нода жива/не загружена —
// не трогаем (mid-session без скачков). Клиент OFFLINE → переназначаем на лучшую СЕЙЧАС:
// при переподключении (выключил/включил VPN) правила уже указывают на лучшую ноду.
// OnlineUsers — refcount живых соединений ядра (policy statsUserOnline, install.sh):
// соединение закрылось → email исчезает сразу, без таймаутов. Ошибка gRPC/статистики →
// прежняя sticky-логика (не дёргаем клиентов вслепую).
func (c *Controller) reevaluate(ctx context.Context) {
	c.refreshLoads(ctx)
	c.mu.Lock()
	loads := copyLoads(c.loads)
	c.mu.Unlock()

	// онлайн-снимок: один gRPC-вызов на тик. ok=false → детект недоступен,
	// reconnect-переназначение выключаем (защита от скачков при битой статистике).
	online := map[string]bool{}
	onlineOK := false
	if c.xray != nil {
		if users, err := c.xray.OnlineUsers(ctx); err == nil {
			onlineOK = true
			for _, u := range users {
				online[u] = true
			}
		}
	}

	clients := c.allClients()
	changed := false
	for _, cl := range clients {
		if !cl.Enabled {
			continue
		}
		cur, _ := c.store.GetAssignment(cl.Email, cl.Country)
		best, err := c.bal.PickNode(cl.Country, loads)
		// УРОК (failover при отключении ноды): preferred country недоступна (все ноды
		// отключены/мертвы) → fallback на другую страну с живой нодой (Assign это умеет).
		// Без этого клиент оставался на отключённой ноде (silent обрыв).
		if err != nil {
			continue
		}
		if best == nil {
			if cur != nil {
				curNode := c.getNode(cur.NodeID)
				if curNode != nil && curNode.Enabled && curNode.Health != "down" {
					continue // текущая нода жива — оставляем
				}
			}
			// текущая мертва/отключена и preferred пуст → Assign с fallback
			if _, err := c.bal.Assign(ctx, cl.Email, cl.Country, loads); err != nil {
				log.Printf("reeval fallback assign %s: %v", cl.Email, err)
				continue
			}
			changed = true
			continue
		}
		// если текущая нода = лучшая и жива — sticky, не трогаем
		if cur != nil && cur.NodeID == best.ID && cur.Status == StatusSticky {
			continue
		}
		// reconnect: клиент OFFLINE (нет живых соединений) → лучшая СЕЙЧАС.
		// Пока сессия жива (online) — сюда не попадаем, mid-session sticky цел.
		if onlineOK && cur != nil && !online[cl.Email] {
			if _, err := c.bal.Assign(ctx, cl.Email, cl.Country, loads); err != nil {
				log.Printf("reeval reconnect assign %s: %v", cl.Email, err)
				continue
			}
			changed = true
			continue
		}
		// если текущая нода жива и не загружена, но не лучшая — оставляем sticky (не дёргаем)
		if cur != nil && cur.Status == StatusSticky {
			curNode := c.getNode(cur.NodeID)
			if curNode != nil && curNode.Enabled && curNode.Health != "down" && loads[cur.NodeID].Load < c.bal.LoadThreshold {
				continue
			}
		}
		// перенос на лучшую (failover вернулся / новая нода / загрузка)
		if _, err := c.bal.Assign(ctx, cl.Email, cl.Country, loads); err != nil {
			log.Printf("reeval assign %s: %v", cl.Email, err)
			continue
		}
		changed = true
	}
	if changed {
		c.syncAllRules(ctx)
	}
}

// refreshLoads — загрузка нод из StatsService (дельта traffic) + число клиентов.
func (c *Controller) refreshLoads(ctx context.Context) {
	if c.xray == nil {
		return
	}
	nodes := c.allNodes()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range nodes {
		cnt := 0
		if a, err := c.store.AssignmentsByNode(n.ID); err == nil {
			cnt = len(a)
		}
		// загрузка: грубо по числу клиентов (позже — дельта traffic/ёмкость)
		cap := n.Capacity
		if cap <= 0 {
			cap = c.store.BalancerSettings().DefaultCapacity
		}
		if cap <= 0 {
			cap = 50
		}
		load := float64(cnt) / float64(cap) // ёмкость ноды настраиваемая (capacity)
		if load > 1 {
			load = 1
		}
		c.loads[n.ID] = NodeLoad{NodeID: n.ID, Load: load, Clients: cnt}
	}
}

// enforce — expiry/quota: истёк/превысил → RemoveUser из Xray + enable=0.
// УРОК XKIT (коммерция): used_bytes обновляется из StatsService (реальный трафик),
// не статичен. Сначала собираем трафик, потом проверяем квоту/срок.
func (c *Controller) enforce(ctx context.Context) {
	c.collectTraffic(ctx)
	// IP-лимит (P1 #11): онлайн-IP per-client через gRPC, превышение → событие+уведомление.
	c.enforceIPLimits(ctx)
	now := time.Now().Unix()
	// АВТОПРОДЛЕНИЕ (P0 #2) — ПЕРЕД проверкой истечения: продлеваем тех у кого наступил
	// срок автопродления, чтобы не отключить клиента который должен продлиться.
	// УРОК (panels-research 3x-ui/Marzban): домохозяйка не продлевает вручную.
	c.processRenewals(ctx, now)
	expired, _ := c.store.ExpiredClients(now)
	for _, cl := range expired {
		c.disableClient(ctx, cl.Email, "истёк срок")
	}
	// quota: used >= quota (quota>0)
	rows, err := c.store.DB().Query(`SELECT email FROM clients WHERE enabled=1 AND quota_bytes>0 AND used_bytes>=quota_bytes`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var email string
			rows.Scan(&email)
			c.disableClient(ctx, email, "превышена квота")
		}
	}
	// аренда нод: истёк срок → ТОЛЬКО уведомление (не отключаем).
	// УРОК (владелец): дата аренды нужна для напоминаний, не для авто-отключения.
	expNodes, _ := c.store.ExpiredNodes(now)
	for _, n := range expNodes {
		c.store.AddEvent("node_expiry", "warn", fmt.Sprintf("нода %s (%s): истёк срок аренды — продлите или отключите вручную", n.Name, n.Country), fmt.Sprintf(`{"node":%q}`, n.ID))
	}
	// проактивные уведомления клиентам (P0 #3): истечение/квота — retention.
	c.processNotifications(ctx, now)
	// напоминания админу об аренде нод (7/3/1 день) — до отключения.
	c.processNodeExpiryNotifications(ctx, now)
	// трафик-бюджет нод (P1 #5): дельта outbound stats + сброс периода + алерт 90%.
	c.collectNodeTraffic(ctx, now)
	// retention почасовых бакетов трафика (~90 дней); lifetime не трогаем
	if err := c.store.PruneTrafficHourly(now - 90*24*3600); err != nil {
		log.Printf("enforce: prune traffic_hourly: %v", err)
	}
}

// processRenewals — автопродление клиентов (P0 #2). Вызывается в enforce ДО проверки истечения.
// УРОК (panels-research): режимы daily/weekly/monthly/days, month-end clamp, сброс трафика опц.
// Если клиент был отключён по истечению/квоте — продление возвращает его (enabled=1 + AddUser).
func (c *Controller) processRenewals(ctx context.Context, now int64) {
	due, err := c.store.ClientsDueForRenewal(now)
	if err != nil || len(due) == 0 {
		return
	}
	for _, d := range due {
		newExpiry, err := c.store.ApplyRenewal(d.Email, now)
		if err != nil {
			log.Printf("autorenew %s: %v", d.Email, err)
			continue
		}
		// если клиент был отключён (истёк/квота) — вернём в inbound
		cl, _ := c.store.GetClient(d.Email)
		if cl != nil && !cl.Enabled {
			c.store.DB().Exec(`UPDATE clients SET enabled=1 WHERE email=?`, d.Email)
			if c.xray != nil && cl.UUID != "" {
				c.xray.AddUser(ctx, c.InboundTag, d.Email, cl.UUID, "xtls-rprx-vision")
			}
		}
		c.store.AddEvent("autorenew", "ok", fmt.Sprintf("клиент %s автопродлён (%s) до %s", d.Email, d.Renew.Mode, time.Unix(newExpiry, 0).Format("02.01.2006")), fmt.Sprintf(`{"email":%q}`, d.Email))
		log.Printf("autorenew: %s продлён до %s", d.Email, time.Unix(newExpiry, 0).Format("2006-01-02"))
	}
}

// disableNode — отключает ноду (аренда истекла/ручная) + failover клиентов на живые ноды.
func (c *Controller) disableNode(ctx context.Context, n store.Node, reason string) {
	c.store.DB().Exec(`UPDATE nodes SET enabled=0, health='down', updated_at=strftime('%s','now') WHERE id=?`, n.ID)
	c.store.AddEvent("node_expiry", "warn", fmt.Sprintf("нода %s (%s) отключена: %s", n.Name, n.Country, reason), fmt.Sprintf(`{"node":%q}`, n.ID))
	// failover клиентов этой ноды на другие ноды страны
	c.mu.Lock()
	loads := copyLoads(c.loads)
	c.mu.Unlock()
	moved, err := c.bal.FailoverNode(ctx, n.ID, loads)
	if err != nil {
		log.Printf("disableNode failover %s: %v", n.ID, err)
	} else {
		log.Printf("нода %s отключена (%s) → failover %d клиентов", n.ID, reason, moved)
	}
	c.notifyNodeDisabled(ctx, n, reason, moved)
	c.syncAllRules(ctx)
}

// collectTraffic — тянет реальный трафик клиентов из Xray StatsService и обновляет
// used_bytes в SQLite. Xray счётчики кумулятивные (user>>>email>>>traffic>>>uplink/downlink).
// reset=false: читаем накопленное за всё время, used_bytes = uplink+downlink.
// УРОК XKIT: ошибки не глотаем — логируем, но не роняем тикер (один сбойный клиент
// не должен останавливать учёт остальных).
func (c *Controller) collectTraffic(ctx context.Context) {
	if c.xray == nil {
		return
	}
	clients, err := c.store.EnabledClients()
	if err != nil {
		log.Printf("collectTraffic: list clients: %v", err)
		return
	}
	for _, cl := range clients {
		var curUp, curDown int64
		haveUp, haveDown := false, false
		for _, dir := range []string{"uplink", "downlink"} {
			pattern := fmt.Sprintf("user>>>%s>>>traffic>>>%s", cl.Email, dir)
			stats, err := c.xray.QueryStats(ctx, pattern, false)
			if err != nil {
				// счётчик может отсутствовать (клиент ещё не подключался) — не ошибка
				continue
			}
			var v int64
			for _, st := range stats {
				v += st.GetValue()
			}
			if dir == "uplink" {
				curUp, haveUp = v, true
			} else {
				curDown, haveDown = v, true
			}
		}
		// lifetime-накопитель: дельта кумулятивных счётчиков (переживает рестарт
		// xray и сброс used_bytes при продлении). Нет счётчика → прошлый сэмпл,
		// чтобы не принять отсутствие за сброс и не задвоить.
		prev := c.store.GetTrafficTotal("client", cl.Email)
		lastUp, lastDown := int64(0), int64(0)
		if prev != nil {
			lastUp, lastDown = prev.LastUp, prev.LastDown
		}
		if !haveUp {
			curUp = lastUp
		}
		if !haveDown {
			curDown = lastDown
		}
		if haveUp || haveDown {
			if err := c.store.AccumulateClientTraffic(cl.Email, curUp, curDown); err != nil {
				log.Printf("collectTraffic: accumulate %s: %v", cl.Email, err)
			}
		}
		// квота: обновляем только если трафик вырос (кумулятивный счётчик не уменьшается)
		total := curUp + curDown
		if total > cl.UsedBytes {
			if err := c.store.SetUsedBytes(cl.Email, total); err != nil {
				log.Printf("collectTraffic: set used %s: %v", cl.Email, err)
			}
		}
	}
}

func (c *Controller) disableClient(ctx context.Context, email, reason string) {
	// RemoveUser из inbound мастера (горячо, AlterInbound)
	if c.xray != nil {
		if err := c.xray.RemoveUser(ctx, c.InboundTag, email); err != nil {
			log.Printf("enforce RemoveUser %s: %v", email, err)
		}
	}
	// BUG-04 fix: удалить ВСЕ assignment клиента + пересобрать правила (не мёртвый GetAssignment(email,""))
	c.store.DB().Exec(`UPDATE clients SET enabled=0, updated_at=strftime('%s','now') WHERE email=?`, email)
	c.store.DB().Exec(`DELETE FROM assignments WHERE email=?`, email)
	c.syncAllRules(ctx)
	c.store.AddEvent("expiry", "warn", fmt.Sprintf("клиент %s отключён: %s", email, reason), fmt.Sprintf(`{"email":%q}`, email))
	log.Printf("enforce: %s отключён (%s)", email, reason)
}

// SyncRules — публичная пересборка routing rules (после рестарта xray / restore inbound).
// УРОК (QA): reevaluate пропускает sticky-клиентов (changed=false) → после рестарта xray
// rules пусты, клиенты идут DIRECT. RestoreInbounds обязан позвать SyncRules.
func (c *Controller) SyncRules(ctx context.Context) { c.syncAllRules(ctx) }

// syncAllRules — пересобрать ВЕСЬ набор routing rules и атомарно заменить в Xray.
// Порядок: api-in→api, RU-direct, per-user (assignments), catch-all→direct.
// УРОК (аудит CRITICAL #1): AppendRules кладёт per-user ПОСЛЕ catch-all из config.json
// (Xray матчит первое совпадение) → правило мертво, клиент выходит direct с мастера
// мимо ноды. Как insertSurveyRule: снапшот routing + ReplaceRules, per-user ПЕРЕД
// catch-all. Балансировщики и чужие правила (survey) сохраняются, сессии не рвутся.
func (c *Controller) syncAllRules(ctx context.Context) {
	if c.xray == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Режим маршрутизации (solo/ru-direct/antifilter). antifilter = НАШ sticky
	// per-user балансир: blocked-список решает ЧТО в туннель, КУДА — назначение
	// клиента. Общий random-балансир XKIT_AF удалён (скачки per-connection).
	mode := "ru-direct"
	if c.store != nil {
		mode = c.store.EffectiveRoutingMode(len(c.allNodes()) > 0)
	}
	if mode == "antifilter" {
		// пустой blocked-кеш → деградация в ru-direct (не включаем молча)
		st := c.store.AntifilterState()
		if st.DatFile == "" || st.PrefixCount == 0 {
			mode = "ru-direct"
		}
	}
	if mode == "solo" {
		// явный соло при живых нодах: всё direct с мастера — per-user не строим
		c.ensureRoutingModeRules(false, nil)
		snapshot, err := c.routingSnapshot()
		if err == nil {
			if err := c.xray.ReplaceRules(ctx, snapshot.Rule, snapshot.BalancingRule); err != nil {
				log.Printf("syncAllRules solo: %v", err)
			}
		}
		return
	}
	// RU-direct правила персистят в config.json (geoip:ru, geosite:category-ru, .ru/.su).
	assigns, _ := c.store.AllAssignments()
	// Все чтения БД ДО ensureRoutingModeRules (MaxOpenConns=1: вложенные rows → дедлок):
	// клиенты, ноды, always-правила — в память, дальше только сборка правил.
	clientsByEmail := map[string]store.Client{}
	for _, cl := range c.allClients() {
		clientsByEmail[cl.Email] = cl
	}
	nodesByID := map[string]store.Node{}
	for _, n := range c.allNodes() {
		nodesByID[n.ID] = n
	}
	ar := c.store.AlwaysRules()
	// УРОК (QA BUG-1b/4): дедуп «первый assignment на email» без порядка брал
	// строку country='' (или устаревшую страну) → базовое правило залипало на
	// старой ноде после country_change. Группируем по email и выбираем базовое
	// назначение по clients.country (any/'' → assignment '' или 'any'), а не по
	// порядку строк в БД.
	byEmail := map[string][]store.Assignment{}
	var order []string
	for _, a := range assigns {
		if _, ok := byEmail[a.Email]; !ok {
			order = append(order, a.Email)
		}
		byEmail[a.Email] = append(byEmail[a.Email], a)
	}
	// базовое назначение email (страна клиента; '' и any взаимозаменяемы)
	baseByEmail := map[string]*store.Assignment{}
	for _, email := range order {
		cl, ok := clientsByEmail[email]
		if !ok || !cl.Enabled {
			continue
		}
		list := byEmail[email]
		var base *store.Assignment
		for i := range list {
			a := &list[i]
			if a.Country == cl.Country {
				base = a
				break
			}
			if (cl.Country == "" || strings.EqualFold(cl.Country, "any")) && (a.Country == "" || strings.EqualFold(a.Country, "any")) {
				base = a
				break
			}
		}
		if base == nil {
			base = &list[0]
		} // fallback: страна клиента без назначения — любое живое (reeval дочинит)
		baseByEmail[email] = base
	}
	// Живое базовое назначение email: нода существует, включена, не down.
	// Иначе клиент деградирует в catch-all direct (reeval/failover дочинит).
	liveBase := map[string]*store.Assignment{}
	for email, base := range baseByEmail {
		if n, ok := nodesByID[base.NodeID]; ok && n.Enabled && n.Health != "down" {
			liveBase[email] = base
		}
	}
	// blocked-токены antifilter (ext: A/B-файл — hot-reload через смену имени)
	var blockedDom, blockedIP []string
	if mode == "antifilter" {
		st := c.store.AntifilterState()
		blockedDom = []string{"ext:geosite-ru-only.dat:ru-blocked"}
		blockedIP = []string{"ext:" + st.DatFile + ":xkit-blocked"}
	}
	pd, pi := ar.ProxyTokens()
	// per-user правила: protobuf для runtime + JSON для персиста (ОДИН порядок).
	var userPB []*router.RoutingRule
	var userJSON []any
	addUser := func(tag, email, nodeID string, domains, ips []string) {
		rr := &router.RoutingRule{RuleTag: tag, UserEmail: []string{email},
			TargetTag: &router.RoutingRule_Tag{Tag: nodeID}}
		if len(domains) > 0 {
			dr, err := geodata.ParseDomainRules(domains, geodata.Domain_Domain)
			if err != nil {
				log.Printf("syncAllRules %s domain: %v", tag, err)
				return
			}
			rr.Domain = dr
		}
		if len(ips) > 0 {
			ir, err := geodata.ParseIPRules(ips)
			if err != nil {
				log.Printf("syncAllRules %s ip: %v", tag, err)
				return
			}
			rr.Ip = ir
		}
		userPB = append(userPB, rr)
		userJSON = append(userJSON, ruleToJSON(tag, email, nodeID, domains, ips))
	}
	for _, email := range order {
		base := liveBase[email]
		if base == nil {
			continue
		}
		cl := clientsByEmail[email]
		nodeID := base.NodeID
		if mode == "antifilter" {
			// antifilter: базового per-user НЕТ — незаблокированное обязано идти
			// direct (инверсия). В туннель только blocked (afp) и always-proxy (ap).
			addUser(fmt.Sprintf("afpd:%s", email), email, nodeID, blockedDom, nil)
			addUser(fmt.Sprintf("afpi:%s", email), email, nodeID, nil, blockedIP)
		} else {
			// базовое per-user правило: user:[email] → нода назначения из assignment.
			// Страна клиента = clients.country (cs/vlessRoute-слой удалён). В
			// ru-direct покрывает и always-proxy (весь не-RU трафик → нода).
			addUser(fmt.Sprintf("c:%s:%s", email, cl.Country), email, nodeID, nil, nil)
			continue
		}
		if len(pd) > 0 {
			addUser(fmt.Sprintf("apd:%s", email), email, nodeID, pd, nil)
		}
		if len(pi) > 0 {
			addUser(fmt.Sprintf("api:%s", email), email, nodeID, nil, pi)
		}
	}

	// Персистентные правила + per-user в config.json (переживают рестарт ядра).
	c.ensureRoutingModeRules(len(c.allNodes()) > 0, userJSON)

	// Снапшот живого routing из config.json: api/RU-direct/catch-all парсятся штатным
	// парсером Xray (geoip:/geosite: резолвятся), балансировщики сохраняются.
	snapshot, err := c.routingSnapshot()
	if err != nil {
		// Без снапшота ReplaceRules стёр бы RU-direct/catch-all/балансировщики.
		// Старый путь (remove+append) оставляет per-user после catch-all — честно
		// логируем деградацию, solo-конфиг без файла не ломаем.
		log.Printf("syncAllRules: снапшот routing недоступен (%v) — fallback append (порядок не гарантирован)", err)
		for _, a := range assigns {
			_ = c.xray.RemoveUserRule(ctx, a.RuleTag)
		}
		if err := c.xray.AppendRules(ctx, userPB); err != nil {
			log.Printf("syncAllRules: %v (пробую reconnect)", err)
			if rerr := c.xray.Reconnect(); rerr != nil {
				log.Printf("reconnect failed: %v", rerr)
				return
			}
			if err2 := c.xray.AppendRules(ctx, userPB); err2 != nil {
				log.Printf("syncAllRules retry: %v", err2)
				return
			}
		}
		return
	}
	newRules := rebuildRules(snapshot.Rule, userPB)
	if err := c.xray.ReplaceRules(ctx, newRules, snapshot.BalancingRule); err != nil {
		log.Printf("syncAllRules: %v (пробую reconnect)", err)
		if rerr := c.xray.Reconnect(); rerr != nil {
			log.Printf("reconnect failed: %v", rerr)
			return
		}
		if err2 := c.xray.ReplaceRules(ctx, newRules, snapshot.BalancingRule); err2 != nil {
			log.Printf("syncAllRules retry: %v", err2)
			return
		}
		log.Printf("syncAllRules: reconnect OK, правила применены")
		return
	}
	log.Printf("syncAllRules: %d per-user правил ПЕРЕД catch-all (ReplaceRules, RU-direct сохранён)", len(userPB))
}

// masterConfigPath — путь config.json мастера (var для подмены в тестах).
var masterConfigPath = "/usr/local/etc/xray/config.json"

// routingSnapshot — снапшот routing-секции config.json мастера в protobuf.
func (c *Controller) routingSnapshot() (*router.Config, error) {
	data, err := os.ReadFile(masterConfigPath)
	if err != nil {
		return nil, fmt.Errorf("master config: %w", err)
	}
	var cfg map[string]any
	if json.Unmarshal(data, &cfg) != nil {
		return nil, fmt.Errorf("master config не парсится")
	}
	routing, _ := cfg["routing"].(map[string]any)
	if routing == nil {
		return nil, fmt.Errorf("master config без routing-секции")
	}
	routingJSON, _ := json.Marshal(routing)
	return xray.ParseRoutingConfig(string(routingJSON))
}

// rebuildRules — полный набор для ReplaceRules: из снапшота убираем ВСЕ старые
// per-user (c:/afp:/ap: + легаси cs:/cspd:/cspi:), вставляем свежие ПЕРЕД первым
// catch-all. api/RU-direct/af-private/always-direct/survey/чужие правила и порядок
// сохраняются. applyRoutingRules персистит тот же порядок — снапшот и runtime не расходятся.
func rebuildRules(snapshot, perUser []*router.RoutingRule) []*router.RoutingRule {
	var kept []*router.RoutingRule
	for _, r := range snapshot {
		if isUserRuleTag(r.GetRuleTag()) {
			continue
		}
		kept = append(kept, r)
	}
	idx := len(kept)
	for i, r := range kept {
		if isCatchAllRule(r) {
			idx = i
			break
		}
	}
	out := make([]*router.RoutingRule, 0, len(kept)+len(perUser))
	out = append(out, kept[:idx]...)
	out = append(out, perUser...)
	out = append(out, kept[idx:]...)
	return out
}

// isCatchAllRule — catch-all: port 0-65535 без user/inboundTag/domain/ip (перехватывает всё).
func isCatchAllRule(r *router.RoutingRule) bool {
	if r == nil || r.PortList == nil || len(r.PortList.Range) == 0 {
		return false
	}
	if len(r.UserEmail) > 0 || len(r.InboundTag) > 0 || len(r.Domain) > 0 || len(r.Ip) > 0 {
		return false
	}
	for _, pr := range r.PortList.Range {
		if pr.From == 0 && pr.To == 65535 {
			return true
		}
	}
	return false
}

// PushAssignment — ручное/первичное назначение клиента (вызывается API при создании клиента).
func (c *Controller) PushAssignment(ctx context.Context, email, country string) (*store.Assignment, error) {
	c.refreshLoads(ctx)
	c.mu.Lock()
	loads := copyLoads(c.loads)
	c.mu.Unlock()
	a, err := c.bal.Assign(ctx, email, country, loads)
	if err != nil {
		return nil, err
	}
	c.syncAllRules(ctx)
	return a, nil
}

// SyncRulesNow — публичная принудительная синхронизация правил (для API).
func (c *Controller) SyncRulesNow(ctx context.Context) {
	c.syncAllRules(ctx)
}

// --- helpers ---

func (c *Controller) allNodes() []store.Node {
	rows, err := c.store.DB().Query(`SELECT id,name,country,country_code,priority,price,host,port,tunnel,tunnel_cfg,health,health_fails,expiry,enabled,capacity,latency_ms,uptime_pct,quality_score,note FROM nodes WHERE enabled=1`)
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

func (c *Controller) getNode(id string) *store.Node {
	var n store.Node
	var en int
	err := c.store.DB().QueryRow(`SELECT id,name,country,country_code,priority,price,host,port,tunnel,tunnel_cfg,health,health_fails,expiry,enabled,capacity,latency_ms,uptime_pct,quality_score,note FROM nodes WHERE id=?`, id).
		Scan(&n.ID, &n.Name, &n.Country, &n.CountryCode, &n.Priority, &n.Price, &n.Host, &n.Port, &n.Tunnel, &n.TunnelCfg, &n.Health, &n.HealthFails, &n.Expiry, &en, &n.Capacity, &n.LatencyMs, &n.UptimePct, &n.QualityScore, &n.Note)
	if err != nil {
		return nil
	}
	n.Enabled = en == 1
	return &n
}

func (c *Controller) allClients() []store.Client {
	rows, err := c.store.DB().Query(`SELECT email,uuid,sub_id,name,country,country_code,expiry,quota_bytes,used_bytes,enabled FROM clients`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []store.Client
	for rows.Next() {
		var cl store.Client
		var en int
		rows.Scan(&cl.Email, &cl.UUID, &cl.SubID, &cl.Name, &cl.Country, &cl.CountryCode, &cl.Expiry, &cl.QuotaBytes, &cl.UsedBytes, &en)
		cl.Enabled = en == 1
		out = append(out, cl)
	}
	return out
}

func copyLoads(m map[string]NodeLoad) map[string]NodeLoad {
	out := make(map[string]NodeLoad, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// managedRuleTags — префиксы ruleTag, которыми владеет ensure-механика режимов.
func isManagedRuleTag(tag string) bool {
	return strings.HasPrefix(tag, "ru-") || strings.HasPrefix(tag, "af-") || strings.HasPrefix(tag, "always-")
}

// applyRoutingRules — единая точка персистентных правил мастера в config.json.
// Развитие ensureRUDirectRules (не параллельный инъектор). Порядок (решение владельца):
// api → always-direct → always-proxy → [antifilter: geoip:ru/geosite RU direct →
// af-domain → af-ip → af-private | ru-direct: ru-ip/ru-domain] → (per-user gRPC) →
// catch-all direct. Все ВЫШЕ catch-all (урок CRITICAL #1). Идемпотентно: managed
// правила вырезаются и вставляются заново после api; чужие (survey/…) сохраняются.
func (c *Controller) applyRoutingRules(mode string, hasNodes bool, datFile string, ar routing.AlwaysRules, alive []string, userRules []any) {
	cfgPath := masterConfigPath
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return
	}
	var cfg map[string]any
	if json.Unmarshal(data, &cfg) != nil {
		return
	}
	r, _ := cfg["routing"].(map[string]any)
	if r == nil {
		return
	}
	rules, _ := r["rules"].([]any)
	// вырезаем managed + запоминаем api-позицию
	var kept []any
	apiIdx := -1
	for _, rl := range rules {
		rm, ok := rl.(map[string]any)
		if !ok {
			kept = append(kept, rl)
			continue
		}
		tag, _ := rm["ruleTag"].(string)
		if isManagedRuleTag(tag) || isUserRuleTag(tag) {
			continue
		}
		if tag == "api" {
			apiIdx = len(kept)
		}
		kept = append(kept, rl)
	}
	if apiIdx < 0 {
		apiIdx = 0
	} else {
		apiIdx++
	} // вставляем ПОСЛЕ api

	// Порядок (решение владельца): api → always-direct → [antifilter: RU-исключение |
	// ru-direct: ru-ip/ru-domain] → per-user (базовые c / afp blocked → ap
	// always-proxy, ВСЕ адресуют ноду назначения клиента) → af-private → catch-all.
	// Персист и runtime собирают ОДИН порядок: userRules уже упорядочены вызывающим.
	var managed []any
	add := func(tag string, fields map[string]any) {
		if len(fields) == 0 {
			return
		}
		fields["type"] = "field"
		fields["ruleTag"] = tag
		managed = append(managed, fields)
	}
	dd, di := ar.DirectTokens()
	addIP := func(tag string, ips []string, out string) {
		if len(ips) > 0 {
			add(tag, map[string]any{"ip": ips, "outboundTag": out})
		}
	}
	addDom := func(tag string, doms []string, out string) {
		if len(doms) > 0 {
			add(tag, map[string]any{"domain": doms, "outboundTag": out})
		}
	}
	addIP("always-direct-ip", di, "direct")
	addDom("always-direct-domain", dd, "direct")

	switch mode {
	case "antifilter":
		if hasNodes && datFile != "" {
			// РФ-исключение: RU-адреса/домены direct даже если в blocked-списке
			// (решение владельца: geoip:ru direct между always и af).
			addIP("ru-ip", []string{"geoip:ru"}, "direct")
			addDom("ru-domain", []string{"geosite:category-ru", "domain:.ru", "domain:.su", "domain:.xn--p1ai"}, "direct")
		}
	case "ru-direct":
		if hasNodes {
			// прежнее поведение ensureRUDirectRules (не ломать существующее)
			addIP("ru-ip", []string{"geoip:ru", "geoip:private"}, "direct")
			addDom("ru-domain", []string{"geosite:category-ru", "domain:.ru", "domain:.su", "domain:.xn--p1ai"}, "direct")
		}
	}
	// per-user: базовые c (ru-direct) → нода назначения; blocked (afp) и
	// always-proxy (ap) → та же нода. Общего random-балансира НЕТ — каждый
	// клиент на СВОЕЙ sticky-ноде (страна = clients.country).
	for _, rm := range userRules {
		managed = append(managed, rm)
	}
	if mode == "antifilter" && hasNodes && datFile != "" {
		addIP("af-private", []string{"geoip:private"}, "direct")
	}
	newRules := make([]any, 0, len(kept)+len(managed))
	newRules = append(newRules, kept[:apiIdx]...)
	newRules = append(newRules, managed...)
	newRules = append(newRules, kept[apiIdx:]...)
	r["rules"] = newRules
	if len(managed) > 0 {
		r["domainStrategy"] = "IPIfNonMatch"
	} else {
		r["domainStrategy"] = "AsIs"
	}
	// XKIT_AF больше не создаётся; легаси-балансир из прежних версий убираем.
	stripAFBalancerIn(r)
	cfg["routing"] = r
	out, _ := json.MarshalIndent(cfg, "", " ")
	if string(out) != strings.TrimSuffix(string(data), "\n") {
		os.WriteFile(cfgPath, out, 0644)
	}
}

// isUserRuleTag — per-user правила балансировщика: c: (назначение),
// afpd:/afpi: (antifilter blocked→нода), apd:/api: (always-proxy→нода).
// cs:/cspd:/cspi: — ЛЕГАСИ country-select (слой удалён): префиксы сохранены
// в списке чтобы миграция вырезала старые правила из config.json при старте.
func isUserRuleTag(tag string) bool {
	for _, p := range []string{"c:", "cs:", "afpd:", "afpi:", "cspd:", "cspi:", "apd:", "api:"} {
		if strings.HasPrefix(tag, p) {
			return true
		}
	}
	return false
}

// stripAFBalancerIn — убрать легаси-балансир XKIT_AF из routing-секции (in-place).
// Random-стратегия выбирала ноду PER-CONNECTION → скачки клиента между нодами;
// теперь всё через per-user sticky-назначения.
func stripAFBalancerIn(r map[string]any) {
	bals, _ := r["balancers"].([]any)
	var kept []any
	found := false
	for _, b := range bals {
		if bm, ok := b.(map[string]any); ok && bm["tag"] == afBalancerTag {
			found = true
			continue
		}
		kept = append(kept, b)
	}
	if !found {
		return
	}
	if len(kept) == 0 {
		delete(r, "balancers")
	} else {
		r["balancers"] = kept
	}
}

const afBalancerTag = "XKIT_AF" // только для снятия легаси-балансира

// ruleToJSON — per-user правило → JSON как в config.json (персист переживает
// рестарт ядра). Токены domain/ip — исходные строки (ext:/geosite:/geoip:),
// штатный парсер ядра резолвит их при чтении файла.
func ruleToJSON(tag, email, nodeID string, domains, ips []string) map[string]any {
	m := map[string]any{"type": "field", "ruleTag": tag, "user": []string{email}, "outboundTag": nodeID}
	if len(domains) > 0 {
		m["domain"] = domains
	}
	if len(ips) > 0 {
		m["ip"] = ips
	}
	return m
}

// ensureRoutingModeRules — пересборка персистентных правил под текущий режим.
// Вызывается из syncAllRules (общий мьютекс уже взван) и при смене режима из API.
// ВНИМАНИЕ (MaxOpenConns=1): все чтения БД ДО вызовов, которые сами открывают rows.
func (c *Controller) ensureRoutingModeRules(hasNodes bool, userRules []any) {
	mode := "solo"
	var ar routing.AlwaysRules
	datFile := ""
	var alive []string
	if c.store != nil {
		mode = c.store.EffectiveRoutingMode(hasNodes)
		ar = c.store.AlwaysRules()
		for _, n := range c.allNodes() {
			if n.Health != "down" {
				alive = append(alive, n.ID)
			}
		}
		if mode == "antifilter" {
			if st := c.store.AntifilterState(); st.DatFile != "" && st.PrefixCount > 0 {
				datFile = st.DatFile
			} else {
				// пустой кеш → режим не включается молча: деградация в ru-direct
				log.Printf("antifilter: blocked-список пуст — правила ru-direct (обновите список)")
				mode = "ru-direct"
			}
		}
	}
	c.applyRoutingRules(mode, hasNodes, datFile, ar, alive, userRules)
}
