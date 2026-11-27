package antifilter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBlockedListsForSubscriptions — наборы для клиентских подписок читаются из
// ТЕХ ЖЕ файлов, что матчит ядро (active dat + geosite-ru-only): клиент и сервер
// не спорят о составе. ETag-поллинг клиента работает (304).
func TestBlockedListsForSubscriptions(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// ip txt
	ipTxt, err := e.m.BlockedIPText()
	if err != nil || !strings.Contains(ipTxt, "/") {
		t.Fatalf("ip text: %q %v", ipTxt, err)
	}
	// ip json (sing-box source rule-set)
	ipJSON, err := e.m.BlockedIPJSON()
	if err != nil {
		t.Fatal(err)
	}
	var rs struct {
		Version int `json:"version"`
		Rules   []struct {
			IPCIDR []string `json:"ip_cidr"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(ipJSON), &rs); err != nil || rs.Version != 1 || len(rs.Rules) != 1 || len(rs.Rules[0].IPCIDR) == 0 {
		t.Fatalf("ip rule-set json invalid: %v %s", err, ipJSON[:min(200, len(ipJSON))])
	}
	// domains: clash text ОБЯЗАН нести '+.'-префикс (AF-BUG-4: голый домен
	// в mihomo domain-behavior = точный матч, www.youtube.com утекал в DIRECT)
	domTxt, err := e.m.BlockedDomainText()
	if err != nil || !strings.Contains(domTxt, "+.youtube.com") {
		t.Fatalf("domain text must use '+.' suffix syntax: %q %v", domTxt, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(domTxt), "\n") {
		if !strings.HasPrefix(line, "+.") {
			t.Fatalf("bare domain in clash payload (subdomain leak): %q", line)
		}
	}
	// sing-box JSON остаётся БЕЗ '+.' — domain_suffix сам покрывает поддомены
	domJSON, err := e.m.BlockedDomainJSON()
	if err != nil || !strings.Contains(domJSON, `"domain_suffix"`) {
		t.Fatalf("domain json: %v", err)
	}
	if strings.Contains(domJSON, "+.") {
		t.Fatal("sing-box domain_suffix must stay bare ('+.' не его синтаксис)")
	}
	// HTTP + ETag 304
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x/blocked-ip.txt", nil)
	e.m.ServeBlocked(rec, req, "blocked-ip.txt")
	if rec.Code != 200 {
		t.Fatalf("serve: %d %s", rec.Code, rec.Body.String())
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/x/blocked-ip.txt", nil)
	req2.Header.Set("If-None-Match", etag)
	e.m.ServeBlocked(rec2, req2, "blocked-ip.txt")
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("304 expected, got %d", rec2.Code)
	}
	// неизвестный kind → 404
	rec3 := httptest.NewRecorder()
	e.m.ServeBlocked(rec3, httptest.NewRequest("GET", "/x/nope", nil), "nope")
	if rec3.Code != 404 {
		t.Fatalf("unknown kind: %d", rec3.Code)
	}
}

func min(a, b int) int { if a < b { return a }; return b }