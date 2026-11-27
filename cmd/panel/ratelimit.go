package main

// ratelimit.go — SEC-06: защита логина от перебора (5 попыток/IP/минуту,
// экспоненциальный backoff при повторных превышениях).

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	loginMaxAttempts = 5
	loginWindow      = time.Minute
	loginMaxBackoff  = 15 * time.Minute
)

type loginAttemptState struct {
	windowStart time.Time
	count       int
	strikes     int
	blockedTill time.Time
	lastSeen    time.Time
}

// loginLimiter — per-IP лимит попыток логина. allow() вызывается ДО проверки пароля.
type loginLimiter struct {
	mu sync.Mutex
	m  map[string]*loginAttemptState
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{m: make(map[string]*loginAttemptState)}
}

// allow — true если попытка разрешена. При превышении лимита блокировка
// 1мин → 2мин → 4мин … (экспоненциально, потолок loginMaxBackoff).
// retryAfter — сколько секунд ждать до следующей попытки (для Retry-After).
func (l *loginLimiter) allow(ip string) (bool, time.Duration) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// периодическая чистка устаревших записей (анти-разрастание map)
	if len(l.m) > 1024 {
		for k, st := range l.m {
			if now.Sub(st.lastSeen) > time.Hour {
				delete(l.m, k)
			}
		}
	}
	st := l.m[ip]
	if st == nil {
		st = &loginAttemptState{windowStart: now}
		l.m[ip] = st
	}
	st.lastSeen = now
	if now.Before(st.blockedTill) {
		return false, st.blockedTill.Sub(now)
	}
	if now.Sub(st.windowStart) >= loginWindow {
		st.windowStart = now
		st.count = 0
	}
	st.count++
	if st.count > loginMaxAttempts {
		st.strikes++
		shift := st.strikes - 1
		if shift > 10 {
			shift = 10
		}
		backoff := loginWindow << shift
		if backoff > loginMaxBackoff {
			backoff = loginMaxBackoff
		}
		st.blockedTill = now.Add(backoff)
		return false, backoff
	}
	return true, 0
}

// clientIP — IP клиента для лимитера. Панель за nginx (X-Real-IP от camo-конфига);
// без заголовка — RemoteAddr. Заголовок берём только если это валидный IP.
func clientIP(r *http.Request) string {
	if rip := strings.TrimSpace(r.Header.Get("X-Real-IP")); rip != "" {
		if net.ParseIP(rip) != nil {
			return rip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}