// Package balancer — assignment-движок XKIT Panel (control plane).
// Алгоритм владельца: нода = приоритет + цена. Первичное подключение → лучшая живая
// незагруженная нода страны; загружена → следующая по приоритету; отвал → failover на
// живую ноду ТОЙ ЖЕ страны; все ноды страны мертвы → fallback другая страна.
// Sticky: assignment детерминирован → все соединения клиента на одной ноде.
// Применение через Xray gRPC per-user rules (горячо, без обрыва чужих сессий).
package balancer

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/xray"
)

const (
	FailsToDown    = 3    // неудач подряд → нода down (паттерн Kitsune, гистерезис)
	LoadThreshold  = 0.80 // загрузка >80% → нода считается загруженной, идём дальше
	StatusSticky   = "sticky"
	StatusFailover = "failover"
)

type Balancer struct {
	store *store.Store
	xray  *xray.Client
	// настраиваемые параметры (из store settings, админ вкладка Балансировщик)
	LoadThreshold   float64
	FailsToDown     int
	SelectByQuality bool // выбирать ноду по quality-score (latency/uptime/load), а не только priority
}

func New(s *store.Store, x *xray.Client) *Balancer {
	bs := s.BalancerSettings()
	return &Balancer{store: s, xray: x, LoadThreshold: bs.LoadThreshold, FailsToDown: bs.FailsToDown, SelectByQuality: bs.SelectByQuality}
}

// ReloadSettings — перечитать настройки балансировщика (после изменения админом).
func (b *Balancer) ReloadSettings() {
	bs := b.store.BalancerSettings()
	b.LoadThreshold = bs.LoadThreshold
	b.FailsToDown = bs.FailsToDown
	b.SelectByQuality = bs.SelectByQuality
}

// NodeLoad — загрузка ноды (доля 0..1) + число онлайн-клиентов.
type NodeLoad struct {
	NodeID  string
	Load    float64
	Clients int
}

// PickNode выбирает лучшую ноду страны для клиента: priority ASC, price ASC,
// пропускает down и загруженные (>LoadThreshold). Если все загружены — берёт наименее
// загруженную живую (лучше работать чем拒绝). Возвращает nil если живых нод страны нет.
// PickNode выбирает ноду страны. country=="" или "any" → лучшая среди ВСЕХ живых нод
// (режим Any: балансировщик сам выбирает по качеству/приоритету/загрузке).
func (b *Balancer) PickNode(country string, loads map[string]NodeLoad) (*store.Node, error) {
	var nodes []store.Node
	var err error
	if country == "" || strings.EqualFold(country, "any") {
		nodes, err = b.allEnabledNodes()
	} else {
		nodes, err = b.store.NodesByCountry(country)
	}
	if err != nil {
		return nil, err
	}
	var alive []store.Node
	for _, n := range nodes {
		if n.Health == "down" {
			continue
		}
		alive = append(alive, n)
	}
	if len(alive) == 0 {
		return nil, nil
	}
	// сначала незагруженные: по качеству (если включено) или по приоритету
	var candidates []store.Node
	for _, n := range alive {
		if loads[n.ID].Load < b.LoadThreshold {
			candidates = append(candidates, n)
		}
	}
	if len(candidates) > 0 {
		if b.SelectByQuality {
			// лучшая по quality-score (latency/uptime/load); при равенстве — priority
			sort.SliceStable(candidates, func(i, j int) bool {
				qi, qj := candidates[i].QualityScore, candidates[j].QualityScore
				if qi != qj {
					return qi > qj
				}
				return candidates[i].Priority < candidates[j].Priority
			})
		}
		return &candidates[0], nil
	}
	// все загружены → наименее загруженная живая (по quality среди равных, затем priority)
	sort.SliceStable(alive, func(i, j int) bool {
		li, lj := loads[alive[i].ID].Load, loads[alive[j].ID].Load
		if li != lj {
			return li < lj
		}
		if b.SelectByQuality && alive[i].QualityScore != alive[j].QualityScore {
			return alive[i].QualityScore > alive[j].QualityScore
		}
		return alive[i].Priority < alive[j].Priority
	})
	return &alive[0], nil
}

// allEnabledNodes — все включённые ноды (режим Any: выбор среди всех стран).
func (b *Balancer) allEnabledNodes() ([]store.Node, error) {
	rows, err := b.store.DB().Query(`SELECT id,name,country,country_code,priority,price,host,port,tunnel,tunnel_cfg,health,health_fails,expiry,enabled,capacity,latency_ms,uptime_pct,quality_score,note
		FROM nodes WHERE enabled=1 ORDER BY priority ASC, price ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Node
	for rows.Next() {
		var n store.Node
		var en int
		if err := rows.Scan(&n.ID, &n.Name, &n.Country, &n.CountryCode, &n.Priority, &n.Price, &n.Host, &n.Port, &n.Tunnel, &n.TunnelCfg, &n.Health, &n.HealthFails, &n.Expiry, &en, &n.Capacity, &n.LatencyMs, &n.UptimePct, &n.QualityScore, &n.Note); err != nil {
			return nil, err
		}
		n.Enabled = en == 1
		out = append(out, n)
	}
	return out, rows.Err()
}

// Assign назначает клиента на ноду страны и пушит per-user rule в Xray горячо.
// Если все ноды страны мертвы → fallback на другую страну (решение владельца).
// Базовое правило: user:[email] → нода назначения, БЕЗ vlessRoute (страна =
// clients.country, cs-слой удалён — один UUID на все протоколы).
func (b *Balancer) Assign(ctx context.Context, email, country string, loads map[string]NodeLoad) (*store.Assignment, error) {
	node, err := b.PickNode(country, loads)
	if err != nil {
		return nil, err
	}
	status := StatusSticky
	failoverFrom := ""
	actualCountry := country
	if node == nil {
		// все ноды страны мертвы → fallback другая страна
		fb, fbCountry, err := b.fallbackCountry(country, loads)
		if err != nil {
			return nil, err
		}
		if fb == nil {
			return nil, fmt.Errorf("no alive node for country %s and no fallback", country)
		}
		node = fb
		actualCountry = fbCountry
		status = StatusFailover
		failoverFrom = country
		b.store.AddEvent("failover", "warn", fmt.Sprintf("все ноды %s мертвы → %s", country, fbCountry), fmt.Sprintf(`{"email":%q,"from":%q,"to":%q}`, email, country, fbCountry))
	}

	ruleTag := fmt.Sprintf("c:%s:%s", email, country) // ключ по ЗАПРОШЕННОЙ стране
	rule := xray.UserRule{
		RuleTag:     ruleTag,
		Email:       email,
		OutboundTag: node.ID,
	}
	// swap: add нового → remove старого (без микрозазора)
	old, _ := b.store.GetAssignment(email, country)
	if old != nil && old.RuleTag != ruleTag {
		if err := b.xray.SwapUserRule(ctx, old.RuleTag, rule); err != nil {
			return nil, err
		}
	} else {
		// УРОК (QA BUG-4): тот же ruleTag (повторный assign / та же нода) —
		// идемпотентный remove+add: параллельный syncAllRules мог уже добавить
		// правило, голый AddRule падал duplicate ruleTag → 500.
		_ = b.xray.RemoveUserRule(ctx, ruleTag) // not found = ещё не добавлено, ок
		if err := b.xray.AddUserRule(ctx, rule); err != nil {
			return nil, err
		}
	}

	a := store.Assignment{
		Email: email, Country: country, NodeID: node.ID,
		RuleTag: ruleTag, Status: status, FailoverFrom: failoverFrom,
	}
	if err := b.store.SetAssignment(a); err != nil {
		return nil, err
	}
	b.store.AddEvent("assign", "info", fmt.Sprintf("%s → %s (%s)", email, node.ID, actualCountry), fmt.Sprintf(`{"email":%q,"node":%q,"country":%q,"status":%q}`, email, node.ID, actualCountry, status))
	return &a, nil
}

// fallbackCountry ищет живую ноду в ДРУГОЙ стране (по приоритету стран).
func (b *Balancer) fallbackCountry(exclude string, loads map[string]NodeLoad) (*store.Node, string, error) {
	// все страны из нод, кроме exclude
	rows, err := b.store.DB().Query(`SELECT DISTINCT country FROM nodes WHERE enabled=1 AND country!=? ORDER BY country`, exclude)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var countries []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, "", err
		}
		countries = append(countries, c)
	}
	for _, c := range countries {
		if n, err := b.PickNode(c, loads); err == nil && n != nil {
			return n, c, nil
		}
	}
	return nil, "", nil
}

// FailoverNode вызывается когда нода умерла (health down). Переназначает ВСЕХ её
// клиентов на живую ноду ТОЙ ЖЕ страны (или fallback другая страна). Чужие сессии не рвутся.
func (b *Balancer) FailoverNode(ctx context.Context, nodeID string, loads map[string]NodeLoad) (int, error) {
	assigns, err := b.store.AssignmentsByNode(nodeID)
	if err != nil {
		return 0, err
	}
	moved := 0
	for _, a := range assigns {
		if _, err := b.Assign(ctx, a.Email, a.Country, loads); err != nil {
			b.store.AddEvent("failover_error", "error", fmt.Sprintf("%s: %v", a.Email, err), "{}")
			continue
		}
		moved++
	}
	b.store.AddEvent("failover", "warn", fmt.Sprintf("нода %s down → перенесено %d клиентов", nodeID, moved), fmt.Sprintf(`{"node":%q,"moved":%d}`, nodeID, moved))
	return moved, nil
}

// RecordProbe записывает результат health-пробы ноды. N=3 подряд неудач → down.
// Восстановление с гистерезисом: одна удачная проба → alive (но sticky не дёргаем автоматически).
func (b *Balancer) RecordProbe(ctx context.Context, nodeID string, ok bool) (becameDown bool, err error) {
	var health string
	var fails int
	err = b.store.DB().QueryRow(`SELECT health,health_fails FROM nodes WHERE id=?`, nodeID).Scan(&health, &fails)
	if err != nil {
		return false, err
	}
	if ok {
		if health == "down" {
			b.store.AddEvent("node_up", "ok", fmt.Sprintf("нода %s восстановилась", nodeID), fmt.Sprintf(`{"node":%q}`, nodeID))
		}
		return false, b.store.SetNodeHealth(nodeID, "alive", 0)
	}
	fails++
	if fails >= b.FailsToDown && health != "down" {
		if err := b.store.SetNodeHealth(nodeID, "down", fails); err != nil {
			return false, err
		}
		b.store.AddEvent("node_down", "error", fmt.Sprintf("нода %s недоступна (%d проб)", nodeID, fails), fmt.Sprintf(`{"node":%q}`, nodeID))
		return true, nil
	}
	return false, b.store.SetNodeHealth(nodeID, health, fails)
}
