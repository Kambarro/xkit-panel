package balancer

import (
	"context"
	"fmt"
	"time"
)

// processNotifications — проактивные уведомления клиенту в TG (P0 #3, panels-research).
// УРОК (Remnawave EXPIRATION_NOTIFICATIONS / Marzban NOTIFY_* / 3x-ui expireDiff):
// retention-машина коммерции. Истечение [-72,-48,-24ч], остаток квоты 90%, «не подключался 24ч».
// Идемпотентность: client_notifications (email,kind,ref) — не слать повторно.
// Вызывается в enforce (раз в минуту), но ref-окна делают отправку разовой на окно.
func (c *Controller) processNotifications(ctx context.Context, now int64) {
	if c.NotifyClient == nil {
		return // бот не настроен — уведомления выключены
	}
	rows, err := c.store.DB().Query(`SELECT email,name,expiry,quota_bytes,used_bytes,tg_chat_id FROM clients WHERE enabled=1 AND tg_chat_id>0`)
	if err != nil {
		return
	}
	defer rows.Close()
	type cl struct {
		email, name string
		expiry, quota, used, chat int64
	}
	var clients []cl
	for rows.Next() {
		var x cl
		if err := rows.Scan(&x.email, &x.name, &x.expiry, &x.quota, &x.used, &x.chat); err == nil {
			clients = append(clients, x)
		}
	}
	rows.Close()

	alertPct := float64(c.store.BalancerSettings().AlertPct)
	for _, x := range clients {
		name := x.name
		if name == "" { name = x.email }
		// истечение срока: окна -72/-48/-24ч (ref = окно, чтобы слать раз на окно)
		if x.expiry > 0 {
			hoursLeft := float64(x.expiry-now) / 3600
			for _, win := range []struct{ h int; label string }{{72, "72"}, {48, "48"}, {24, "24"}} {
				// окно: hoursLeft в (win-1, win] — попал в час перед порогом
				if hoursLeft <= float64(win.h) && hoursLeft > float64(win.h)-1 {
					ref := fmt.Sprintf("expiry_%s_%d", win.label, x.expiry)
					if !c.store.NotificationSent(x.email, "expiry", ref) {
						msg := fmt.Sprintf("⏳ <b>%s</b>, срок подписки истекает через %s ч.\nПродлите заранее, чтобы не потерять доступ.", name, win.label)
						if c.NotifyClient(ctx, x.chat, msg) == nil {
							c.store.MarkNotification(x.email, "expiry", ref)
						}
					}
				}
			}
			// уже истёк (но ещё enabled — напр. grace): уведомить раз
			if x.expiry <= now {
				ref := fmt.Sprintf("expired_%d", x.expiry)
				if !c.store.NotificationSent(x.email, "expired", ref) {
					if c.NotifyClient(ctx, x.chat, fmt.Sprintf("🔴 <b>%s</b>, срок подписки истёк. Продлите для восстановления доступа.", name)) == nil {
						c.store.MarkNotification(x.email, "expired", ref)
					}
				}
			}
		}
		// квота 90% (ref = порог, раз на клиента пока не сбросят)
		if x.quota > 0 {
			pct := float64(x.used) / float64(x.quota) * 100
			if pct >= alertPct {
				ref := fmt.Sprintf("quota%d_%d", int(alertPct), x.quota)
				if !c.store.NotificationSent(x.email, "quota", ref) {
					msg := fmt.Sprintf("📊 <b>%s</b>, использовано %.0f%% трафика (%s из %s).\nСкоро лимит — продлите или увеличьте квоту.", name, pct, humanBytes(x.used), humanBytes(x.quota))
					if c.NotifyClient(ctx, x.chat, msg) == nil {
						c.store.MarkNotification(x.email, "quota", ref)
					}
				}
			}
		}
	}
}

func humanBytes(n int64) string {
	if n <= 0 { return "0 B" }
	const unit = 1024
	if n < unit { return fmt.Sprintf("%d B", n) }
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit { div *= unit; exp++ }
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

var _ = time.Now