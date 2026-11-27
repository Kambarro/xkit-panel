package balancer

// Регрессия QA AF-BUG-2 (MEDIUM) на живом ядре: margin OFF обязан сузить
// ЖИВОЙ af-ip маршрут обратно — allyouneed-only IP больше не через ноду,
// без рестарта xray (A/B-файл + ReplaceRules). ON расширяет обратно.
// Полный цикл: реальный antifilter.Manager (httptest-источники, все-304 после
// первого fetch) → dat → контроллер → TestRoute живого in-process ядра.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	routercmd "github.com/xtls/xray-core/app/router/command"
	xnet "github.com/xtls/xray-core/common/net"

	"github.com/kambarro/xkit-panel/internal/antifilter"
)

// afMarginSrc — источник с ETag: после первого fetch отвечает 304 (как прод
// при «застывших» upstream-списках — корень AF-BUG-2).
type afMarginSrc struct {
	body string
	etag string
	hits atomic.Int64
}

func (f *afMarginSrc) handler(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	if r.Header.Get("If-None-Match") == f.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", f.etag)
	fmt.Fprint(w, f.body)
}

func afGenIPs(count int, base string) string {
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

// TestAntifilterMarginToggleLiveRouteE2E — ON→OFF→ON при всех-304: живой
// af-ip маршрут сужается/расширяется без рестарта ядра; allyouneed-only IP
// (1.2.3.1 — проба QA) после OFF идёт direct.
func TestAntifilterMarginToggleLiveRouteE2E(t *testing.T) {
	dir := writeTestGeoFiles(t)
	writeTestBlockedFiles(t, dir) // geosite-ru-only.dat для af-domain
	s := testStore(t)
	if err := s.SetRoutingMode("antifilter"); err != nil {
		t.Fatal(err)
	}
	// per-user af-правила требуют назначения клиента (sticky-переделка)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAssignment(storeAssignment("client@example.com", "NL", "node-nl-1")); err != nil {
		t.Fatal(err)
	}

	// httptest-источники antifilter (точные 10.x, allyouneed-only 1.2.3.x — как проба QA)
	srcs := map[string]*afMarginSrc{}
	mux := http.NewServeMux()
	for name, spec := range map[string]struct {
		count int
		base  string
	}{
		"ipresolve": {60000, "10.0.0"}, "subnet": {69, "10.200.0"}, "community": {934, "10.201.0"},
		"allyouneed": {16557, "1.2.3"},
	} {
		f := &afMarginSrc{body: afGenIPs(spec.count, spec.base), etag: `"` + name + `-v1"`}
		srcs[name] = f
		mux.HandleFunc("/"+name, f.handler)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	old := []string{antifilter.URLIPResolve, antifilter.URLSubnet, antifilter.URLCommunity, antifilter.URLAllYouNeed}
	antifilter.URLIPResolve = srv.URL + "/ipresolve"
	antifilter.URLSubnet = srv.URL + "/subnet"
	antifilter.URLCommunity = srv.URL + "/community"
	antifilter.URLAllYouNeed = srv.URL + "/allyouneed"
	t.Cleanup(func() {
		antifilter.URLIPResolve, antifilter.URLSubnet, antifilter.URLCommunity, antifilter.URLAllYouNeed = old[0], old[1], old[2], old[3]
	})
	// geosite: штатный файл уже в dir; сеть не трогаем — подменяем URL на локальный
	gsData, _ := os.ReadFile(filepath.Join(dir, "geosite-ru-only.dat"))
	gs := &afMarginSrc{body: string(gsData), etag: `"gs1"`}
	gmux := http.NewServeMux()
	gmux.HandleFunc("/geosite", gs.handler)
	gsrv := httptest.NewServer(gmux)
	defer gsrv.Close()
	oldGS, oldGSCDN := antifilter.URLGeositeRaw, antifilter.URLGeositeCDN
	antifilter.URLGeositeRaw, antifilter.URLGeositeCDN = gsrv.URL+"/geosite", gsrv.URL+"/geosite"
	t.Cleanup(func() { antifilter.URLGeositeRaw, antifilter.URLGeositeCDN = oldGS, oldGSCDN })

	m := antifilter.NewManager(s, t.TempDir(), dir)

	routingJSON := `{"domainStrategy":"AsIs","rules":[
		{"type":"field","inboundTag":["api-in"],"outboundTag":"api","ruleTag":"api"},
		{"type":"field","port":"0-65535","outboundTag":"direct"}
	]}`
	xc := startXrayAPI(t, routingJSON)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(cfgPath, []byte(`{"routing":`+routingJSON+`}`), 0644)
	oldPath := masterConfigPath
	masterConfigPath = cfgPath
	t.Cleanup(func() { masterConfigPath = oldPath })
	c := NewController(s, xc)

	sync := func() {
		if _, err := m.RefreshNow(context.Background()); err != nil {
			t.Fatalf("refresh: %v", err)
		}
		c.SyncRulesNow(t.Context())
	}
	routeIP := func(ip string) string {
		resp, err := xc.Routing.TestRoute(t.Context(), &routercmd.TestRouteRequest{RoutingContext: &routercmd.RoutingContext{
			InboundTag: "vless-in", User: "client@example.com", TargetPort: 443, TargetIPs: [][]byte{xnet.ParseAddress(ip).IP()},
		}})
		if err != nil {
			t.Fatalf("TestRoute %s: %v", ip, err)
		}
		return resp.GetOutboundTag()
	}

	// OFF baseline: точный набор, allyouneed-only IP direct
	sync()
	st := s.AntifilterState()
	if len(st.Sources) != 3 {
		t.Fatalf("baseline sources: %v", st.Sources)
	}
	if got := routeIP("1.2.3.1"); got != "direct" {
		t.Fatalf("baseline: allyouneed-only 1.2.3.1 → %q, want direct", got)
	}
	if got := routeIP("10.0.0.1"); got == "direct" {
		t.Fatal("baseline: точный blocked 10.0.0.1 обязан идти через ноду")
	}

	// ON: расширение, 1.2.3.1 через ноду
	s.SetAntifilterMargin(true)
	sync()
	stOn := s.AntifilterState()
	if len(stOn.Sources) != 4 {
		t.Fatalf("ON sources: %v err=%q aynHits=%d", stOn.Sources, stOn.Error, srcs["allyouneed"].hits.Load())
	}
	if got := routeIP("1.2.3.1"); got == "direct" {
		t.Fatal("ON: allyouneed-only 1.2.3.1 должен идти через ноду")
	}

	// OFF при ВСЕХ-304 (корень AF-BUG-2): живой маршрут обязан сузиться
	hitsBefore := srcs["ipresolve"].hits.Load()
	s.SetAntifilterMargin(false)
	sync()
	stOff := s.AntifilterState()
	if len(stOff.Sources) != 3 {
		t.Fatalf("OFF sources: %v (allyouneed остался в юнионе)", stOff.Sources)
	}
	if stOff.DatFile == stOn.DatFile {
		t.Fatal("OFF: dat не пересобран — ядро держит расширенный matcher")
	}
	if got := routeIP("1.2.3.1"); got != "direct" {
		t.Fatalf("OFF при 304: 1.2.3.1 всё ещё → %q (AF-BUG-2: кеш не исключён)", got)
	}
	if got := routeIP("10.0.0.1"); got == "direct" {
		t.Fatal("OFF: точный blocked-трафик сломан")
	}
	if srcs["ipresolve"].hits.Load() == hitsBefore {
		t.Fatal("OFF: источники не опрошены")
	}

	// OFF→ON обратно при 304: снова через ноду
	s.SetAntifilterMargin(true)
	sync()
	if got := routeIP("1.2.3.1"); got == "direct" {
		t.Fatal("ON после OFF при 304: 1.2.3.1 не вернулся через ноду")
	}

	// РЕСТАРТ ПАНЕЛИ (новый Manager+Controller на тех же БД/asset) при margin OFF:
	// суженный набор персистентен, живой маршрут после sync — direct
	s.SetAntifilterMargin(false)
	sync()
	m2 := antifilter.NewManager(s, m.CacheDir, dir)
	if _, err := m2.RefreshNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	c2 := NewController(s, xc)
	c2.SyncRulesNow(t.Context())
	if got := routeIP("1.2.3.1"); got != "direct" {
		t.Fatalf("после рестарта панели: 1.2.3.1 → %q, want direct", got)
	}
	if len(s.AntifilterState().Sources) != 3 {
		t.Fatalf("после рестарта: sources=%v", s.AntifilterState().Sources)
	}
	_ = time.Second
}
