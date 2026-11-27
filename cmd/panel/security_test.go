package main

// SEC-06/SEC-03 регрессии: rate limit логина и tunnel_uuid без хардкода.

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestLoginLimiterFivePerMinute(t *testing.T) {
	l := newLoginLimiter()
	for i := 0; i < 5; i++ {
		if ok, _ := l.allow("1.2.3.4"); !ok {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	ok, wait := l.allow("1.2.3.4")
	if ok {
		t.Fatal("6th attempt within a minute must be blocked")
	}
	if wait < 50*time.Second {
		t.Fatalf("backoff too short: %v", wait)
	}
	// другой IP не блокируется
	if ok, _ := l.allow("5.6.7.8"); !ok {
		t.Fatal("different IP must not be blocked")
	}
}

func TestLoginLimiterExponentialBackoff(t *testing.T) {
	l := newLoginLimiter()
	ip := "9.9.9.9"
	var waits []time.Duration
	for strike := 0; strike < 3; strike++ {
		for i := 0; i < 5; i++ {
			l.allow(ip)
		}
		ok, wait := l.allow(ip)
		if ok {
			t.Fatalf("strike %d: expected block", strike)
		}
		waits = append(waits, wait)
		// эмулируем истечение блокировки и окна
		l.mu.Lock()
		st := l.m[ip]
		st.blockedTill = time.Now().Add(-time.Second)
		st.windowStart = time.Now().Add(-2 * time.Minute)
		st.count = 0
		l.mu.Unlock()
	}
	if !(waits[1] > waits[0] && waits[2] > waits[1]) {
		t.Fatalf("backoff must grow exponentially: %v", waits)
	}
}

func TestTunnelUUIDFromEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tunnel.env")
	os.WriteFile(p, []byte("TUNNEL_UUID=abc-123\n"), 0600)
	if got := tunnelUUIDFromEnv(p); got != "abc-123" {
		t.Fatalf("uppercase key: got %q", got)
	}
	os.WriteFile(p, []byte("# comment\ntunnel_uuid=\"def-456\"\n"), 0600)
	if got := tunnelUUIDFromEnv(p); got != "def-456" {
		t.Fatalf("lowercase key: got %q", got)
	}
	if got := tunnelUUIDFromEnv(filepath.Join(dir, "missing.env")); got != "" {
		t.Fatalf("missing file: got %q", got)
	}
}

func TestRandUUIDv4(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		u := randUUIDv4()
		if !re.MatchString(u) {
			t.Fatalf("not a UUIDv4: %q", u)
		}
		if u == "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d" {
			t.Fatal("hardcoded audit UUID must never be generated")
		}
		if seen[u] {
			t.Fatalf("duplicate UUID: %q", u)
		}
		seen[u] = true
	}
}