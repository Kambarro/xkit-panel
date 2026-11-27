package api

// Детект ВНЕШНЕГО рестарта xray (наблюдение Ops 2026-11-26): systemctl restart
// xray мимо панели сносит горячие preset-inbound и per-user routing — подписки
// битые, клиенты DIRECT. Панель триггерила RestoreInbounds только на свой старт
// и свои рестарты. Здесь штатный health-watch: раз в 30с лёгкая gRPC-проба;
// смена состояния соединения (даун→ап ИЛИ просто оборванное соединение при
// живом API = процесс перезапущен) → Reconnect + RestoreInbounds.

import (
	"context"
	"time"

	proxycmd "github.com/xtls/xray-core/app/proxyman/command"
)

// xrayInboundExists — жив ли inbound с тегом (handler not found = снесён рестартом).
func (s *Server) xrayInboundExists(ctx context.Context, tag string) bool {
	_, err := s.xray.Handler.GetInboundUsersCount(ctx, &proxycmd.GetInboundUserRequest{Tag: tag})
	return err == nil
}

// hotInboundMissing — ЛЮБОЙ enabled preset-inbound из БД отсутствует в живом xray.
// Детект состояния (не события): переживает сверхбыстрый рестарт между тиками.
// УРОК (Ops b737b05): первый по порту — персистентный config.json inbound
// (vless-reality), рестарт его НЕ сносит → проверять ВСЕ, а не «репрезентативный».
func (s *Server) hotInboundMissing(ctx context.Context) bool {
	ibs, _ := s.store.AllInbounds()
	for _, ib := range ibs {
		if !ib.Enabled || ib.Tag == "api-in" || ib.Tag == "api" || !userProto(ib.Protocol) {
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		missing := !s.xrayInboundExists(pctx, ib.Tag)
		cancel()
		if missing {
			return true
		}
	}
	return false
}

// WatchXrayRestart — публичная точка запуска детекта внешнего рестарта xray.
func (s *Server) WatchXrayRestart(ctx context.Context) { s.watchXrayRestart(ctx) }

// watchXrayRestart — цикл детекта. Возвращается при отмене ctx (shutdown панели).
func (s *Server) watchXrayRestart(ctx context.Context) {
	s.watchXrayRestartEvery(ctx, 30*time.Second)
}

func (s *Server) watchXrayRestartEvery(ctx context.Context, interval time.Duration) {
	if s.xray == nil {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	var lastErr bool
	haveLast := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := s.xray.OnlineUsers(pctx)
		cancel()
		failed := err != nil
		// триггер: был даун → ожил, ИЛИ соединение оборвалось (рестарт процесса
		// рвёт gRPC даже если API уже снова слушает — missed-downtime окно),
		// ИЛИ горячий preset-inbound из БД пропал (сверхбыстрый рестарт, который
		// gRPC keepalive замаскировал до тика — состояние важнее события).
		restarted := false
		if haveLast && !failed {
			restarted = lastErr || s.xray.ConnBroken()
			if !restarted {
				restarted = s.hotInboundMissing(ctx)
			}
		}
		haveLast, lastErr = true, failed
		if !restarted {
			continue
		}
		s.store.AddEvent("xray_watch", "ok", "xray перезапущен извне — восстановление inbound/routing", "{}")
		_ = s.xray.Reconnect()
		s.RestoreInbounds()
	}
}
