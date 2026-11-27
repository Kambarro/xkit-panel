// Package antifilter — фоновое обновление blocked-списков для режима antifilter.
// ETag-поллинг antifilter.download (30 мин), кеш+backoff, fallback runetfreedom,
// генерация xkit-blocked.dat (geodata-схема 26.11.x — инвариант версии ядра).
package antifilter

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"

	"github.com/kambarro/xkit-panel/internal/store"
)

// Источники (замеры и ETag-механика проверены живьём 2026-11-26, research §1).
// var (не const): тесты подменяют на httptest-сервер.
var (
	URLIPResolve  = "https://antifilter.download/list/ipresolve.lst"
	URLSubnet     = "https://antifilter.download/list/subnet.lst"
	URLCommunity  = "https://community.antifilter.download/list/community.lst"
	URLAllYouNeed = "https://antifilter.download/list/allyouneed.lst"
	// geosite RU-BLOCKED (re:filter+community, содержит youtube/x.com/chatgpt — antifilter domains их НЕ имеет)
	URLGeositeRaw = "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geosite/release/geosite-ru-only.dat"
	URLGeositeCDN = "https://cdn.jsdelivr.net/gh/runetfreedom/russia-blocked-geosite@release/geosite-ru-only.dat"
	// fallback IP-dat (охват уже́: ipresolve+subnet+telegram, без /24) — лестница §5.2
	URLFallbackRaw = "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/dat/ru-blocked.dat"
	URLFallbackCDN = "https://cdn.jsdelivr.net/gh/runetfreedom/russia-blocked-geoip@release/dat/ru-blocked.dat"
)

// Файлы в asset-каталоге Xray (правила ссылаются через ext:<file>:<code>).
// A/B-чередование dat-файлов: IPSetFactory ядра кеширует matcher по ключу
// file:code (weak cache) — перезапись ТОГО ЖЕ файла не перечитывается без GC.
// Смена имени файла = гарантированный cache MISS = детерминированный hot-reload.
const (
	DatFileA     = "xkit-blocked.dat"
	DatFileB     = "xkit-blocked-2.dat"
	GeositeFile  = "geosite-ru-only.dat"
	FallbackCode = "RU-BLOCKED"
)

// Manager — кеш + поллинг + генерация. Все пути инъектируются (тестируемость).
type Manager struct {
	CacheDir string // кеш lst (переживает рестарт панели)
	AssetDir string // /usr/local/share/xray — dat для ядра
	Store    *store.Store
	HTTP     *http.Client
	Now      func() time.Time

	mu      sync.Mutex
	backoff time.Duration // 30м→60м→120м… потолок 6ч (при ошибке источников)
	nextTry time.Time
}

func NewManager(st *store.Store, cacheDir, assetDir string) *Manager {
	return &Manager{
		CacheDir: cacheDir, AssetDir: assetDir, Store: st,
		HTTP: &http.Client{Timeout: 60 * time.Second},
		Now:  time.Now,
	}
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// lstSource — один polled-файл. name = имя кеша и ключ sanity/ETag.
type lstSource struct {
	name string
	url  string
}

func (m *Manager) lstSources() []lstSource {
	src := []lstSource{
		{"ipresolve", URLIPResolve},
		{"subnet", URLSubnet},
		{"community", URLCommunity},
	}
	if m.Store != nil && m.Store.AntifilterMargin() {
		src = append(src, lstSource{"allyouneed", URLAllYouNeed})
	}
	return src
}

// fetchETag — GET с If-None-Match. 304 → (nil, etag, nil); 200 → тело.
func (m *Manager) fetchETag(ctx context.Context, url, etag string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, "", err
	}
	return body, resp.Header.Get("ETag"), nil
}

// RefreshNow — принудительный цикл (кнопка UI): сбрасывает backoff.
func (m *Manager) RefreshNow(ctx context.Context) (store.AntifilterState, error) {
	m.mu.Lock()
	m.nextTry = time.Time{}
	m.mu.Unlock()
	return m.Refresh(ctx)
}

// StartLoop — фоновый цикл 30 мин (паттерн probeAllNodes/collectTraffic).
// Первичный Refresh сразу: кеш прошлого запуска применяется без ожидания тика.
func (m *Manager) StartLoop(ctx context.Context, onChanged func()) {
	go func() {
		if _, err := m.Refresh(ctx); err != nil {
			log.Printf("antifilter: стартовое обновление: %v", err)
		} else if onChanged != nil {
			onChanged()
		}
		t := time.NewTicker(30 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st, err := m.Refresh(ctx)
				if err != nil {
					log.Printf("antifilter: обновление: %v", err)
					continue
				}
				if onChanged != nil {
					onChanged() // горячая пересборка af-ip правила (A/B-файл мог смениться)
				}
				_ = st
			}
		}
	}()
}

// Refresh — один цикл обновления (тик 30 мин или принудительно из API).
// Возвращает итоговое состояние; ошибка = все источники недоступны И кеш пуст.
func (m *Manager) Refresh(ctx context.Context) (store.AntifilterState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.now().Before(m.nextTry) {
		st := m.Store.AntifilterState()
		return st, fmt.Errorf("backoff: следующая попытка через %s", m.nextTry.Sub(m.now()).Round(time.Minute))
	}
	st := m.Store.AntifilterState()
	if st.ETags == nil {
		st.ETags = map[string]string{}
	}
	now := m.now().Unix()

	// 1. Поллинг lst (ETag). Ошибка одного источника не роняет остальные — работаем на кеше.
	var fetchErrs []string
	changed := false
	for _, src := range m.lstSources() {
		body, etag, err := m.fetchETag(ctx, src.url, st.ETags[src.name])
		if err != nil {
			fetchErrs = append(fetchErrs, src.name+": "+err.Error())
			continue
		}
		if body == nil { // 304 — кеш актуален
			continue
		}
		ps, err := ParseCIDRLines(body)
		if err != nil {
			fetchErrs = append(fetchErrs, src.name+": "+err.Error())
			continue
		}
		if err := SanityCheck(src.name, len(ps)); err != nil {
			fetchErrs = append(fetchErrs, err.Error())
			continue
		}
		if err := WriteAtomic(m.cachePath(src.name), body); err != nil {
			fetchErrs = append(fetchErrs, src.name+": cache write: "+err.Error())
			continue
		}
		st.ETags[src.name] = etag
		changed = true
	}

	// 2. Юнион из кеша → dat. Кеш пуст → fallback-лестница.
	var prefixes []netip.Prefix
	var sources []string
	for _, src := range m.lstSources() {
		data, err := os.ReadFile(m.cachePath(src.name))
		if err != nil {
			continue
		}
		ps, err := ParseCIDRLines(data)
		if err != nil || SanityCheck(src.name, len(ps)) != nil {
			continue // битый кеш не используем
		}
		prefixes = append(prefixes, ps...)
		sources = append(sources, src.name)
	}
	// QA AF-BUG-2: смена margin в ЛЮБУЮ сторону меняет состав юниона — форсируем
	// регенерацию даже при всех-304: применённый набор (st.Sources, переживает
	// рестарт панели) разошёлся с тем, что даёт текущий набор источников+кеш.
	sourcesChanged := (st.Source == "live" || st.Source == "cache") && !sameSourceSet(st.Sources, sources)
	if len(prefixes) > 0 {
		_, statErr := os.Stat(filepath.Join(m.AssetDir, m.ActiveDatFile()))
		// регенерация при изменениях/смене набора источников/отсутствии файла/возврате из fallback
		if changed || sourcesChanged || statErr != nil || st.Source == "fallback" {
			collapsed := Collapse(prefixes)
			data, err := GenerateDat(collapsed)
			if err == nil && DatContains(data, BlockedCode) {
				name, err := m.swapDat(data, st.DatFile)
				if err == nil {
					st.DatFile = name
					st.Source = "live"
					if len(fetchErrs) > 0 {
						st.Source = "cache" // часть источников недоступна — набор из кеша
					}
					st.PrefixCount = len(collapsed)
					st.Sources = sources
					st.UpdatedAt = now
					if len(fetchErrs) == 0 {
						st.LastFetch = now
						m.backoff = 0
						m.nextTry = time.Time{}
					}
				} else {
					fetchErrs = append(fetchErrs, "dat write: "+err.Error())
				}
			}
		} else if len(fetchErrs) == 0 {
			st.LastFetch = now // 304: источники проверены, данные не менялись
			m.backoff = 0
			m.nextTry = time.Time{}
		}
	}

	// 3. Fallback §5.2: antifilter недоступен >24ч (или кеш пуст) → runetfreedom dat.
	needFallback := len(prefixes) == 0 ||
		(st.LastFetch > 0 && now-st.LastFetch > 24*3600 && len(fetchErrs) > 0) ||
		(st.LastFetch == 0 && len(fetchErrs) > 0)
	if needFallback {
		if err := m.applyFallback(ctx, &st, now); err != nil {
			fetchErrs = append(fetchErrs, "fallback: "+err.Error())
		}
	}

	// 4. geosite-ru-only.dat (6ч источник, ETag; raw → CDN).
	if err := m.refreshGeosite(ctx, &st, now); err != nil {
		fetchErrs = append(fetchErrs, "geosite: "+err.Error())
	}

	// 5. Итог: пустой кеш + все ошибки = режим НЕ включается молча.
	st.Error = strings.Join(fetchErrs, "; ")
	st.Stale = st.LastFetch > 0 && now-st.LastFetch > 48*3600
	if len(fetchErrs) > 0 {
		m.backoff = nextBackoff(m.backoff)
		m.nextTry = m.now().Add(m.backoff)
	}
	m.Store.SetAntifilterState(st)
	if st.PrefixCount == 0 {
		return st, fmt.Errorf("blocked-список пуст: %s", st.Error)
	}
	return st, nil
}

func nextBackoff(cur time.Duration) time.Duration {
	if cur == 0 {
		return 60 * time.Minute
	}
	cur *= 2
	if cur > 6*time.Hour {
		cur = 6 * time.Hour
	}
	return cur
}

func (m *Manager) cachePath(name string) string {
	return filepath.Join(m.CacheDir, name+".lst")
}

// sameSourceSet — равенство наборов имён источников (порядок не важен).
func sameSourceSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			return false
		}
	}
	return true
}

// swapDat — A/B-запись: пишем НЕактивный файл, возвращаем его имя.
// Ядро держит старый matcher до пересборки правила (ext-ссылка меняется на новый файл).
func (m *Manager) swapDat(data []byte, active string) (string, error) {
	next := DatFileA
	if active == DatFileA {
		next = DatFileB
	}
	if err := WriteAtomic(filepath.Join(m.AssetDir, next), data); err != nil {
		return "", err
	}
	return next, nil
}

// ActiveDatFile — имя активного dat для правила (по умолчанию A).
func (m *Manager) ActiveDatFile() string {
	if f := m.Store.AntifilterState().DatFile; f != "" {
		return f
	}
	return DatFileA
}

// applyFallback — runetfreedom ru-blocked.dat → перегенерация в XKIT-BLOCKED.
func (m *Manager) applyFallback(ctx context.Context, st *store.AntifilterState, now int64) error {
	var data []byte
	var err error
	for _, url := range []string{URLFallbackRaw, URLFallbackCDN} {
		data, _, err = m.fetchETag(ctx, url, "")
		if err == nil && len(data) > 0 {
			break
		}
	}
	if err != nil || len(data) == 0 {
		if err == nil {
			err = fmt.Errorf("пустой ответ")
		}
		return err
	}
	ps, err := ParseDatPrefixes(data, FallbackCode)
	if err != nil {
		return err
	}
	collapsed := Collapse(ps)
	out, err := GenerateDat(collapsed)
	if err != nil {
		return err
	}
	name, err := m.swapDat(out, st.DatFile)
	if err != nil {
		return err
	}
	st.DatFile = name
	st.Source = "fallback"
	st.PrefixCount = len(collapsed)
	st.Sources = []string{"runetfreedom/ru-blocked"}
	st.UpdatedAt = now
	st.FallbackAt = now
	return nil
}

// refreshGeosite — geosite-ru-only.dat по ETag (raw → CDN при ошибке).
func (m *Manager) refreshGeosite(ctx context.Context, st *store.AntifilterState, now int64) error {
	path := filepath.Join(m.AssetDir, GeositeFile)
	body, etag, err := m.fetchETag(ctx, URLGeositeRaw, st.ETags["geosite"])
	if err != nil {
		body, etag, err = m.fetchETag(ctx, URLGeositeCDN, st.ETags["geosite"])
		if err != nil {
			// файл на диске остаётся working (§5.2 п.3)
			if _, serr := os.Stat(path); serr == nil {
				return nil
			}
			return err
		}
	}
	if body == nil {
		return nil // 304
	}
	if !geositeHasRuBlocked(body) {
		return fmt.Errorf("geosite dat без категории RU-BLOCKED (повреждён?)")
	}
	if err := WriteAtomic(path, body); err != nil {
		return err
	}
	st.ETags["geosite"] = etag
	st.GeositeAt = now
	return nil
}

// geositeHasRuBlocked — sanity geosite dat: категория RU-BLOCKED присутствует.
func geositeHasRuBlocked(data []byte) bool {
	var list geodata.GeoSiteList
	if proto.Unmarshal(data, &list) != nil {
		return false
	}
	for _, e := range list.Entry {
		if strings.EqualFold(e.Code, "RU-BLOCKED") && len(e.Domain) > 0 {
			return true
		}
	}
	return false
}

// Ready — оба файла на месте (условие включения режима, не молчаливое).
func (m *Manager) Ready() bool {
	if _, err := os.Stat(filepath.Join(m.AssetDir, m.ActiveDatFile())); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(m.AssetDir, GeositeFile)); err != nil {
		return false
	}
	return m.Store.AntifilterState().PrefixCount > 0
}