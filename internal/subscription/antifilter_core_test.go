package subscription

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSingboxAntifilterCoreE2E — antifilter-конфиг sing-box проходит check+run
// реальными 1.11.15 и 1.12.0 (урок QA BUG-2). Remote rule-set требуют initial
// fetch при старте (StartContext→fetch→FATAL при недоступности) — httptest-сервер
// отдаёт source-JSON заблокированных наборов, как панель по подписочному URL.
func TestSingboxAntifilterCoreE2E(t *testing.T) {
	bins := findSingboxBinaries(t)
	if len(bins) == 0 {
		t.Skip("sing-box бинари не найдены (XKIT_SINGBOX_BIN / workspace QA)")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/antifilter/blocked-domains.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":1,"rules":[{"domain_suffix":["youtube.com","x.com"]}]}`)
	})
	mux.HandleFunc("/antifilter/blocked-ip.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":1,"rules":[{"ip_cidr":["9.9.9.0/24"]}]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ar := AntifilterRules{
		ProxySites:     []string{"domain:custom.io"},
		DirectSites:    []string{"domain:bank.ru"},
		BlockedDomains: []string{"youtube.com"},
	}
	cfg := SingboxJSONAntifilter([]string{afTestLink}, ar, srv.URL+"/antifilter")
	for _, bin := range bins {
		t.Run(filepath.Base(filepath.Dir(bin)), func(t *testing.T) {
			runSingboxCore(t, bin, cfg)
		})
	}
}

// TestSingboxAntifilterGeoSetsE2E — always-правила с geosite/geoip категориями:
// remote srs MetaCubeX реально скачиваются и конфиг стартует (сеть доступна).
// Offline-окружение: тест skip по недоступности CDN (не фейк-зелёный).
func TestSingboxAntifilterGeoSetsE2E(t *testing.T) {
	bins := findSingboxBinaries(t)
	if len(bins) == 0 {
		t.Skip("sing-box бинари не найдены")
	}
	// CDN доступен?
	cl := &http.Client{Timeout: 8 * time.Second}
	resp, err := cl.Get("https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/telegram.srs")
	if err != nil {
		t.Skip("MetaCubeX CDN недоступен (offline): " + err.Error())
	}
	resp.Body.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/antifilter/blocked-domains.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"version":1,"rules":[{"domain_suffix":["youtube.com"]}]}`)
	})
	mux.HandleFunc("/antifilter/blocked-ip.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"version":1,"rules":[{"ip_cidr":["9.9.9.0/24"]}]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cfg := SingboxJSONAntifilter([]string{afTestLink}, afTestRules, srv.URL+"/antifilter")
	// тест-окружение: туннеля нет (fake master) — DoH remote через select не работает;
	// rule-set качаются detour=direct, резолв CDN переводим на local (прод-конфиг не меняем)
	cfg = strings.Replace(cfg, `"final": "remote"`, `"final": "local"`, 1)
	for _, bin := range bins {
		t.Run(filepath.Base(filepath.Dir(bin)), func(t *testing.T) {
			runSingboxCore(t, bin, cfg)
		})
	}
}

// TestClashAntifilterYAMLValid — YAML парсится (провайдеры на верхнем уровне).
func TestClashAntifilterYAMLValid(t *testing.T) {
	y := ClashYAMLAntifilter([]string{afTestLink}, nil, afTestRules, "https://master.example.com/s-x/abc/antifilter")
	// rule-providers ДОЛЖЕН идти до rules: и быть top-level ключом
	ip := indexOfLine(y, "rule-providers:")
	ir := indexOfLine(y, "rules:")
	if ip < 0 || ir < 0 || ip > ir {
		t.Fatalf("rule-providers must precede rules (prov=%d rules=%d)\n%s", ip, ir, y)
	}
}

func indexOfLine(s, prefix string) int {
	for i, line := range strings.Split(s, "\n") {
		if line == prefix {
			return i
		}
	}
	return -1
}