package balancer

import (
	"context"
	"fmt"
	"log"
	"time"
)

// collectNodeTraffic — трафик нод для биллинг-бюджета (P1 #5, Remnawave nodes.md).
// УРОК: NL-ноды с лимитом 20TB — спасает от счетов-сюрпризов хостера.
// Читаем outbound>>>nodeID>>>traffic>>>uplink/downlink (reset=true → дельта за окно),
// накапливаем в nodes.traffic_used_bytes. Сброс по billing_reset_day. Алерт 90% админу.
// Вызывается в enforce (раз в минуту) — reset=true даёт дельту с прошлого вызова.
func (c *Controller) collectNodeTraffic(ctx context.Context, now int64) {
	if c.xray == nil {
		return
	}
	// сброс биллинг-периода если наступил день
	due, _ := c.store.NodesDueForBillingReset(now)
	for _, id := range due {
		if err := c.store.ResetNodeBillingPeriod(id, now); err == nil {
			c.store.AddEvent("node_billing", "ok", fmt.Sprintf("нода %s: новый биллинг-период, трафик сброшен", id), "{}")
		}
	}
	nodes := c.allNodes()
	for _, n := range nodes {
		var upDelta, downDelta int64
		for _, dir := range []string{"uplink", "downlink"} {
			pattern := fmt.Sprintf("outbound>>>%s>>>traffic>>>%s", n.ID, dir)
			stats, err := c.xray.QueryStats(ctx, pattern, true) // reset=true → дельта
			if err != nil {
				continue // счётчик может отсутствовать (нода не использовалась)
			}
			for _, st := range stats {
				if dir == "uplink" { upDelta += st.GetValue() } else { downDelta += st.GetValue() }
			}
		}
		delta := upDelta + downDelta
		if delta > 0 {
			if err := c.store.AddNodeTraffic(n.ID, delta); err != nil {
				log.Printf("collectNodeTraffic %s: %v", n.ID, err)
			}
			// lifetime-накопитель ноды: та же дельта, отдельный учёт за всё время
			// (биллинг-период сбрасывается, lifetime — нет). Один источник дельты
			// на оба счётчика → задвоения нет.
			if err := c.store.AddTrafficDelta("node", n.ID, upDelta, downDelta); err != nil {
				log.Printf("collectNodeTraffic lifetime %s: %v", n.ID, err)
			}
		}
		// алерт 90% админу (раз на период)
		b := c.store.GetNodeBilling(n.ID)
		if b.LimitGB > 0 && !b.AlertSent && b.Pct() >= float64(c.store.BalancerSettings().AlertPct) {
			msg := fmt.Sprintf("⚠️ Нода %s (%s): трафик %.0f%% от лимита (%d GB). Скоро превышение — проверьте биллинг хостера.", n.Name, n.Country, b.Pct(), b.LimitGB)
			c.store.AddEvent("node_billing", "warn", msg, fmt.Sprintf(`{"node":%q}`, n.ID))
			if c.NotifyAdmin != nil {
				if c.NotifyAdmin(ctx, msg) == nil {
					c.store.MarkNodeAlert(n.ID)
				}
			} else {
				c.store.MarkNodeAlert(n.ID) // нет бота — Отметим чтобы не спамить event
			}
		}
	}
}

var _ = time.Now