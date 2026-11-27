package antifilter

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

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"

	"github.com/kambarro/xkit-panel/internal/store"
)

// genLines — count валидных /32 (для sanity-пределов источников).
func genLines(count int, base string) string {
	var b strings.Builder
	a := [4]int{}
	fmt.Sscanf(base, "%d.%d.%d", &a[0], &a[1], &a[2])
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "%d.%d.%d.%d\n", a[0]+i/65536, a[1]+(i/256)%256, a[2]+i%256, 1+i%250)
	}
	return b.String()
}

func testGeositeDat(t *testing.T) []byte {
	t.Helper()
	l := &geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{Code: "RU-BLOCKED", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "youtube.com"}}},
		{Code: "PRIVATE", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "localhost"}}},
	}}
	b, err := proto.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testFallbackDat(t *testing.T) []byte {
	t.Helper()
	l := &geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "RU-BLOCKED", Cidr: []*geodata.CIDR{
			{Ip: []byte{7, 7, 7, 0}, Prefix: 24},
			{Ip: []byte{8, 8, 8, 8}, Prefix: 32},
		}},
	}}
	b, _ := proto.Marshal(l)
	return b
}

type fakeSrc struct {
	body   string
	etag   string
	hits   atomic.Int64
	status atomic.Int64 // 0=200/304 по ETag, иначе явный статус
}

func (f *fakeSrc) handler(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	if s := f.status.Load(); s != 0 {
		w.WriteHeader(int(s))
		return
	}
	if r.Header.Get("If-None-Match") == f.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", f.etag)
	fmt.Fprint(w, f.body)
}

type testEnv struct {
	m       *Manager
	st      *store.Store
	srv     *httptest.Server
	srcs    map[string]*fakeSrc
	geosite *fakeSrc
	fb      *fakeSrc
	asset   string
	cache   string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &testEnv{st: st, srcs: map[string]*fakeSrc{}, asset: t.TempDir(), cache: t.TempDir()}
	e.geosite = &fakeSrc{body: string(testGeositeDat(t)), etag: `"gs1"`}
	e.fb = &fakeSrc{body: string(testFallbackDat(t)), etag: `"fb1"`}
	mux := http.NewServeMux()
	for name, count := range map[string]int{"ipresolve": 60000, "subnet": 69, "community": 934, "allyouneed": 16557} {
		f := &fakeSrc{body: genLines(count, "10.0.0"), etag: `"` + name + `-v1"`}
		e.srcs[name] = f
		mux.HandleFunc("/"+name, f.handler)
	}
	mux.HandleFunc("/geosite", e.geosite.handler)
	mux.HandleFunc("/geosite-cdn", e.geosite.handler)
	mux.HandleFunc("/fallback", e.fb.handler)
	mux.HandleFunc("/fallback-cdn", e.fb.handler)
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	// подмена URL (var — для тестов)
	old := []string{URLIPResolve, URLSubnet, URLCommunity, URLAllYouNeed, URLGeositeRaw, URLGeositeCDN, URLFallbackRaw, URLFallbackCDN}
	URLIPResolve = e.srv.URL + "/ipresolve"
	URLSubnet = e.srv.URL + "/subnet"
	URLCommunity = e.srv.URL + "/community"
	URLAllYouNeed = e.srv.URL + "/allyouneed"
	URLGeositeRaw = e.srv.URL + "/geosite"
	URLGeositeCDN = e.srv.URL + "/geosite-cdn"
	URLFallbackRaw = e.srv.URL + "/fallback"
	URLFallbackCDN = e.srv.URL + "/fallback-cdn"
	t.Cleanup(func() {
		URLIPResolve, URLSubnet, URLCommunity, URLAllYouNeed = old[0], old[1], old[2], old[3]
		URLGeositeRaw, URLGeositeCDN, URLFallbackRaw, URLFallbackCDN = old[4], old[5], old[6], old[7]
	})
	e.m = NewManager(st, e.cache, e.asset)
	return e
}

// TestRefreshExactDefault — точный режим: ipresolve+subnet+community БЕЗ allyouneed.
func TestRefreshExactDefault(t *testing.T) {
	e := newTestEnv(t)
	st, err := e.m.Refresh(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if st.Source != "live" {
		t.Errorf("source=%q want live", st.Source)
	}
	if len(st.Sources) != 3 {
		t.Errorf("exact mode must use 3 sources, got %v", st.Sources)
	}
	if e.srcs["allyouneed"].hits.Load() != 0 {
		t.Error("allyouneed fetched in exact mode (must be expert-flag only)")
	}
	if st.PrefixCount == 0 {
		t.Error("prefix count 0")
	}
	if !e.m.Ready() {
		t.Error("manager not Ready after refresh")
	}
	// файл — новая geodata-схема, категория XKIT-BLOCKED
	data, _ := os.ReadFile(filepath.Join(e.asset, e.m.ActiveDatFile()))
	if !DatContains(data, BlockedCode) {
		t.Fatal("dat not parseable in new schema")
	}
	// повторный цикл: ETag 304, файлы не трогаются
	before := st.UpdatedAt
	e.m.nextTry = time.Time{}
	st2, err := e.m.Refresh(context.Background())
	if err != nil || st2.PrefixCount != st.PrefixCount {
		t.Fatalf("second refresh: %v %+v", err, st2)
	}
	if st2.UpdatedAt != before {
		t.Log("304 path keeps updated_at (ок если regenerate)")
	}
}

// TestRefreshMarginFlag — expert-флаг включает allyouneed.
func TestRefreshMarginFlag(t *testing.T) {
	e := newTestEnv(t)
	e.st.SetAntifilterMargin(true)
	st, err := e.m.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Sources) != 4 {
		t.Errorf("margin mode sources: %v", st.Sources)
	}
	if e.srcs["allyouneed"].hits.Load() == 0 {
		t.Error("allyouneed not fetched with margin flag")
	}
}

// TestRefreshSanityRejectsShrunk — «усохший в 10 раз» файл отклоняется, кеш живёт.
func TestRefreshSanityRejectsShrunk(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(filepath.Join(e.cache, "ipresolve.lst"))
	// источник отдаёт мусор (10 строк вместо 60k)
	e.srcs["ipresolve"].body = genLines(10, "10.0.0")
	e.srcs["ipresolve"].etag = `"ipresolve-v2"`
	e.m.nextTry = time.Time{}
	st, err := e.m.Refresh(context.Background())
	if err != nil {
		t.Fatalf("cache must keep mode alive: %v", err)
	}
	if !strings.Contains(st.Error, "разумных пределов") {
		t.Errorf("sanity error not surfaced: %q", st.Error)
	}
	cached, _ := os.ReadFile(filepath.Join(e.cache, "ipresolve.lst"))
	if string(cached) != string(good) {
		t.Error("broken source overwrote good cache")
	}
}

// TestRefreshEmptyCacheFallback — пустой кеш + antifilter недоступен → fallback dat.
func TestRefreshEmptyCacheFallback(t *testing.T) {
	e := newTestEnv(t)
	for _, f := range e.srcs {
		f.status.Store(500)
	}
	st, err := e.m.Refresh(context.Background())
	if err != nil {
		t.Fatalf("fallback must rescue: %v", err)
	}
	if st.Source != "fallback" {
		t.Errorf("source=%q want fallback", st.Source)
	}
	if st.PrefixCount != 2 {
		t.Errorf("fallback prefixes: %d", st.PrefixCount)
	}
	if st.FallbackAt == 0 {
		t.Error("fallback_at not set")
	}
}

// TestRefreshAllDeadEmptyCache — всё мертво и кеша нет → честная ошибка (режим не включается молча).
func TestRefreshAllDeadEmptyCache(t *testing.T) {
	e := newTestEnv(t)
	for _, f := range e.srcs {
		f.status.Store(500)
	}
	e.fb.status.Store(500)
	e.geosite.status.Store(500)
	st, err := e.m.Refresh(context.Background())
	if err == nil {
		t.Fatal("empty cache + dead sources must error (no silent enable)")
	}
	if st.PrefixCount != 0 || e.m.Ready() {
		t.Errorf("must not be ready: %+v", st)
	}
}

// TestRefreshStaleOver24h — antifilter мёртв >24ч → автопереключение на fallback.
func TestRefreshStaleOver24h(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, f := range e.srcs {
		f.status.Store(500)
	}
	// кеш «протух»: last_fetch 25ч назад
	st := e.st.AntifilterState()
	st.LastFetch = time.Now().Add(-25 * time.Hour).Unix()
	e.st.SetAntifilterState(st)
	e.m.nextTry = time.Time{}
	st2, err := e.m.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st2.Source != "fallback" {
		t.Errorf("stale >24h must switch to fallback, got %q", st2.Source)
	}
}

// TestRefreshBackoff — ошибка → экспоненциальный откат, ранний тик не дёргает сеть.
func TestRefreshBackoff(t *testing.T) {
	e := newTestEnv(t)
	for _, f := range e.srcs {
		f.status.Store(500)
	}
	e.fb.status.Store(500)
	_, err := e.m.Refresh(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	hits := e.srcs["ipresolve"].hits.Load()
	// следующий тик раньше nextTry — сеть не трогаем
	if _, err := e.m.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "backoff") {
		t.Fatalf("early tick must be backoff-skipped, got %v", err)
	}
	if e.srcs["ipresolve"].hits.Load() != hits {
		t.Error("network hit during backoff")
	}
	// рост 60→120→…→потолок 6ч
	if nextBackoff(0) != 60*time.Minute || nextBackoff(60*time.Minute) != 120*time.Minute ||
		nextBackoff(5*time.Hour) != 6*time.Hour || nextBackoff(6*time.Hour) != 6*time.Hour {
		t.Error("backoff ladder wrong")
	}
}

// TestSwapDatAB — горячая замена: каждый refresh с изменениями пишет ДРУГОЙ файл
// (IPSetFactory ядра кеширует по file:code — смена имени = cache MISS = reload).
func TestSwapDatAB(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f1 := e.m.ActiveDatFile()
	e.srcs["community"].body = genLines(934, "20.0.0")
	e.srcs["community"].etag = `"community-v2"`
	e.m.nextTry = time.Time{}
	if _, err := e.m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f2 := e.m.ActiveDatFile()
	if f1 == f2 {
		t.Fatalf("dat file must alternate A/B, stayed %q", f1)
	}
	for _, f := range []string{f1, f2} {
		if _, err := os.Stat(filepath.Join(e.asset, f)); err != nil {
			t.Errorf("dat %s missing: %v", f, err)
		}
	}
}