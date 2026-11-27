package balancer

// Напоминания админу об истечении аренды нод (7/3/1 день) + уведомление об отключении.
// УРОК XKIT (expiry set/list/check): напоминания раз в сутки на окно, не спам.
// Идемпотентность через client_notifications (email="node:<id>", kind, ref).

import (
	"context"
	"fmt"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

// processNodeExpiryNotifications — вызывается в enforce (раз в минуту).
// Окна: 7д (168ч), 3д (72ч), 1д (24ч) — шлём раз на окно; истёк → раз.
func (c *Controller) processNodeExpiryNotifications(ctx context.Context, now int64) {
	if c.NotifyAdmin == nil {
		return // бот не настроен
	}
	nodes, err := c.store.AllNodes()
	if err != nil {
		return
	}
	for _, n := range nodes {
		if n.Expiry <= 0 || !n.Enabled {
			continue // бессрочная или уже отключена (отключение уведомит disableNode)
		}
		key := "node:" + n.ID
		hoursLeft := float64(n.Expiry-now) / 3600
		name := n.Name
		if name == "" {
			name = n.ID
		}
		date := time.Unix(n.Expiry, 0).Format("02.01.2006")
		for _, win := range []struct {
			h     int
			label string
		}{{168, "7 дней"}, {72, "3 дня"}, {24, "1 день"}} {
			// окно: hoursLeft в (win-1, win] — раз на окно (ref фиксирует expiry)
			if hoursLeft <= float64(win.h) && hoursLeft > float64(win.h)-1 {
				ref := fmt.Sprintf("rent_%d_%d", win.h, n.Expiry)
				if !c.store.NodeNotificationSent(key, "node_rent", ref) {
					msg := fmt.Sprintf("⏰ <b>Аренда ноды %s (%s)</b> истекает через %s (%s).\nПродлите у хостера, иначе нода отключится и клиенты переедут на другие.", name, n.Country, win.label, date)
					if c.NotifyAdmin(ctx, msg) == nil {
						c.store.MarkNodeNotification(key, "node_rent", ref)
					}
				}
			}
		}
	}
}

// notifyNodeDisabled — уведомление админу при отключении ноды (аренда/ручное).
func (c *Controller) notifyNodeDisabled(ctx context.Context, n store.Node, reason string, moved int) {
	if c.NotifyAdmin == nil {
		return
	}
	key := "node:" + n.ID
	ref := "disabled_" + reason
	if c.store.NodeNotificationSent(key, "node_disabled", ref) {
		return
	}
	msg := fmt.Sprintf("🔴 <b>Нода %s (%s) отключена</b>: %s.\nКлиентов переведено на другие ноды: %d.", n.Name, n.Country, reason, moved)
	if c.NotifyAdmin(ctx, msg) == nil {
		c.store.MarkNodeNotification(key, "node_disabled", ref)
	}
}