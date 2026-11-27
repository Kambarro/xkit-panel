package balancer

import (
	"context"
	"fmt"
	"time"
)

// enforceIPLimits — IP-лимит per-client (P1 #11, 3x-ui ipLimit).
// УРОК: HWID не спасает от шаринга с одним UA — считаем уникальные source IP
// через Xray gRPC GetStatsOnlineIpList. IP свежий если timestamp в окне (90с).
// Превышение → событие + уведомление (не блокируем автоматически жёстко —
// IP могут быть динамическими/NAT; владелец решает). Логируем превышение.
func (c *Controller) enforceIPLimits(ctx context.Context) {
	clients, err := c.store.EnabledClients()
	if err != nil {
		return
	}
	now := time.Now().Unix()
	bs := c.store.BalancerSettings()
	ipWindow := int64(bs.IPWindowSec) // окно свежести IP (настраиваемое)
	cooldown := time.Duration(bs.NotifyCooldownMin) * time.Minute
	for _, cl := range clients {
		limit := c.store.ClientIPLimit(cl.Email)
		if limit <= 0 {
			continue
		}
		ips, err := c.xray.OnlineIPs(ctx, cl.Email)
		if err != nil || len(ips) == 0 {
			continue
		}
		// считаем свежие уникальные IP
		active := 0
		var ipList []string
		for ip, ts := range ips {
			if now-ts <= ipWindow {
				active++
				ipList = append(ipList, ip)
			}
		}
		if active > limit {
			// дедуп: не спамим событием каждый цикл (раз в 5 мин)
			key := "iplimit:" + cl.Email
			if c.shouldNotify(key, cooldown) {
				c.store.AddEvent("ip_limit", "warn",
					fmt.Sprintf("клиент %s: %d IP > лимит %d (%v)", cl.Email, active, limit, ipList), "{}")
				var chat int64
				c.store.DB().QueryRow(`SELECT tg_chat_id FROM clients WHERE email=?`, cl.Email).Scan(&chat)
				if c.NotifyClient != nil && chat != 0 {
					c.NotifyClient(ctx, chat, fmt.Sprintf("⚠️ Превышен лимит IP-адресов: %d из %d. Возможно подписка используется на слишком многих сетях.", active, limit))
				}
			}
		}
	}
}

// shouldNotify — дедуп уведомлений по ключу с окном (простой map в памяти).
func (c *Controller) shouldNotify(key string, window time.Duration) bool {
	c.notifyMu.Lock()
	defer c.notifyMu.Unlock()
	if c.lastNotify == nil {
		c.lastNotify = map[string]time.Time{}
	}
	if t, ok := c.lastNotify[key]; ok && time.Since(t) < window {
		return false
	}
	c.lastNotify[key] = time.Now()
	return true
}