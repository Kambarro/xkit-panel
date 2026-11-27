package api

// Регрессии QA antifilter-гейта 2026-11-26:
//   - AF-BUG-3 (LOW): GET /api/rules печатал outbound:'' для balancerTag-правил —
//     gRPC ListRule отдаёт только outboundTag; обогащаем balancerTag из
//     персистентного снапшота config.json по ruleTag.
//   - AF-BUG-2 (API-часть): POST margin сразу пересобирает набор (RefreshNow),
//     не ждём 30-мин тика.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"

	"github.com/kambarro/xkit-panel/internal/antifilter"
	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/xray"
)

// TestLiveRulesBalancerTag — balancerTag-правила видны в debug-ответе /api/rules.
func TestLiveRulesBalancerTag(t *testing.T) {
	writeClientGeoFiles(t) // geoip/geosite для снапшота ядра
	s := testStoreAPI(t)
	xc := startTestXray(t)
	srv := NewServer(s, xc, "test", "test.local")

	// персистентный снапшот как в antifilter: af-ip на балансир XKIT_AF
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	cfg := `{"routing":{"domainStrategy":"IPIfNonMatch","rules":[
		{"type":"field","inboundTag":["api-in"],"outboundTag":"api","ruleTag":"api"},
		{"type":"field","ip":["geoip:ru"],"outboundTag":"direct","ruleTag":"ru-ip"},
		{"type":"field","ip":["geoip:private"],"balancerTag":"XKIT_AF","ruleTag":"af-ip"},
		{"type":"field","port":"0-65535","outboundTag":"direct"}
	],"balancers":[{"tag":"XKIT_AF","selector":["node-nl-1"],"strategy":{"type":"random"}}]}}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	old := masterConfigPath
	masterConfigPath = cfgPath
	t.Cleanup(func() { masterConfigPath = old })

	// применяем тот же снапшот в живое ядро (balancerTag → BalancingRule)
	var top struct {
		Routing json.RawMessage `json:"routing"`
	}
	json.Unmarshal([]byte(cfg), &top)
	snap, err := xray.ParseRoutingConfig(string(top.Routing))
	if err != nil {
		t.Fatal(err)
	}
	if err := xc.ReplaceRules(t.Context(), snap.Rule, snap.BalancingRule); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	srv.liveRules(w, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	if w.Code != 200 {
		t.Fatalf("liveRules: %d %s", w.Code, w.Body.String())
	}
	var rules []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rules); err != nil {
		t.Fatal(err)
	}
	var afIP map[string]any
	for _, r := range rules {
		if r["ruleTag"] == "af-ip" {
			afIP = r
		}
	}
	if afIP == nil {
		t.Fatalf("af-ip не найден: %s", w.Body.String())
	}
	if afIP["balancerTag"] != "XKIT_AF" {
		t.Errorf("af-ip balancerTag=%v want XKIT_AF (AF-BUG-3)", afIP["balancerTag"])
	}
	// outbound-правило не получает чужой balancerTag
	for _, r := range rules {
		if r["ruleTag"] == "ru-ip" {
			if bt, has := r["balancerTag"]; has {
				t.Errorf("ru-ip: лишний balancerTag=%v", bt)
			}
			if r["outbound"] != "direct" {
				t.Errorf("ru-ip outbound=%v", r["outbound"])
			}
		}
	}
}

// TestMarginPostTriggersRefresh — смена margin в POST сразу обновляет состояние
// antifilter (httptest-источники): OFF после ON сужает sources без ручного Refresh.
func TestMarginPostTriggersRefresh(t *testing.T) {
	s := testStoreAPI(t)
	srv := NewServer(s, nil, "test", "test.local")

	// httptest-источники: точные + allyouneed (после первого fetch — 304)
	mux := http.NewServeMux()
	etagHit := map[string]int{}
	for name, spec := range map[string]struct {
		count int
		base  string
	}{
		"ipresolve": {60000, "10.0.0"}, "subnet": {69, "10.200.0"}, "community": {934, "10.201.0"},
		"allyouneed": {16557, "30.0.0"},
	} {
		body := genIPsAPI(spec.count, spec.base)
		etag := `"` + name + `-v1"`
		mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) {
			etagHit[r.URL.Path]++
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			fmt.Fprint(w, body)
		})
	}
	srvHTTP := httptest.NewServer(mux)
	defer srvHTTP.Close()
	old := []string{antifilter.URLIPResolve, antifilter.URLSubnet, antifilter.URLCommunity, antifilter.URLAllYouNeed}
	antifilter.URLIPResolve = srvHTTP.URL + "/ipresolve"
	antifilter.URLSubnet = srvHTTP.URL + "/subnet"
	antifilter.URLCommunity = srvHTTP.URL + "/community"
	antifilter.URLAllYouNeed = srvHTTP.URL + "/allyouneed"
	t.Cleanup(func() {
		antifilter.URLIPResolve, antifilter.URLSubnet, antifilter.URLCommunity, antifilter.URLAllYouNeed = old[0], old[1], old[2], old[3]
	})
	// geosite: живой файл не нужен для sources-проверки, но Refresh его дёргает —
	// отдаём валидный dat (иначе st.Error, не влияет на sources)
	gs := &geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{Code: "RU-BLOCKED", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "youtube.com"}}},
	}}
	gsb, _ := proto.Marshal(gs)
	gmux := http.NewServeMux()
	gmux.HandleFunc("/geosite", func(w http.ResponseWriter, r *http.Request) { w.Write(gsb) })
	gsrv := httptest.NewServer(gmux)
	defer gsrv.Close()
	oldGS, oldGSCDN := antifilter.URLGeositeRaw, antifilter.URLGeositeCDN
	antifilter.URLGeositeRaw, antifilter.URLGeositeCDN = gsrv.URL+"/geosite", gsrv.URL+"/geosite"
	t.Cleanup(func() { antifilter.URLGeositeRaw, antifilter.URLGeositeCDN = oldGS, oldGSCDN })

	m := antifilter.NewManager(s, filepath.Join(t.TempDir(), "cache"), filepath.Join(t.TempDir(), "asset"))
	srv.SetAntifilterManager(m)

	post := func(body string) map[string]any {
		w := httptest.NewRecorder()
		srv.routingMode(w, httptest.NewRequest(http.MethodPost, "/api/routing/mode", strings.NewReader(body)))
		if w.Code != 200 {
			t.Fatalf("post %s: %d %s", body, w.Code, w.Body.String())
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		return resp
	}

	// ON: sources 4 сразу в ответе POST (refresh встроен)
	resp := post(`{"margin":true}`)
	af, _ := resp["antifilter"].(map[string]any)
	srcs, _ := af["sources"].([]any)
	if len(srcs) != 4 {
		t.Fatalf("ON: sources=%v (refresh не отработал в POST)", srcs)
	}
	// OFF при всех-304: sources 3 в том же ответе (корень AF-BUG-2)
	resp = post(`{"margin":false}`)
	af, _ = resp["antifilter"].(map[string]any)
	srcs, _ = af["sources"].([]any)
	if len(srcs) != 3 {
		t.Fatalf("OFF: sources=%v — allyouneed-кеш не исключён (AF-BUG-2)", srcs)
	}
	// повторный POST без смены флага не ломает состояние
	resp = post(`{"margin":false}`)
	af, _ = resp["antifilter"].(map[string]any)
	srcs, _ = af["sources"].([]any)
	if len(srcs) != 3 {
		t.Fatalf("повторный OFF: sources=%v", srcs)
	}
	var _ = store.AntifilterState{}
}

func genIPsAPI(count int, base string) string {
	var b strings.Builder
	var a, c, d int
	fmt.Sscanf(base, "%d.%d.%d", &a, &c, &d)
	start := a<<16 | c<<8 | d
	for i := 0; i < count; i++ {
		n := start + i
		fmt.Fprintf(&b, "%d.%d.%d.%d\n", (n>>16)&255, (n>>8)&255, n&255, 1+i%250)
	}
	return b.String()
}
