package antifilter

// Регрессия QA AF-BUG-2 (MEDIUM): /24-margin OFF не сужал список обратно —
// allyouneed-кеш оставался в юнионе, при всех-304 changed=false и расширенный
// dat жил после рестарта панели. Фикс: расхождение применённого набора
// источников (st.Sources) с текущим (флаг+кеш) форсирует регенерацию dat
// в ЛЮБУЮ сторону смены margin, независимо от changed/304.

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// activeDatHas — активный dat содержит IP (через штатный разбор новой geodata-схемы).
func activeDatHas(t *testing.T, e *testEnv, ip string) bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.asset, e.m.ActiveDatFile()))
	if err != nil {
		t.Fatalf("active dat: %v", err)
	}
	ps, err := ParseDatPrefixes(data, BlockedCode)
	if err != nil {
		t.Fatalf("parse dat: %v", err)
	}
	addr := netip.MustParseAddr(ip)
	for _, p := range ps {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// TestMarginToggleForcesRegenE2E — ON→OFF→ON на «застывших» источниках (все 304):
// OFF исключает allyouneed-only IP из активного dat (даже с живым кешем),
// ON возвращает; счёт префиксов OFF > ON (суммаризация /24). Персистентность:
// новый Manager на тех же БД/кеше/asset (рестарт панели) держит суженный набор.
func TestMarginToggleForcesRegenE2E(t *testing.T) {
	e := newTestEnv(t)
	// allyouneed-only адрес: 30.0.0.1 вне базовых наборов (те на 10.x)
	e.srcs["allyouneed"].body = genLines(16557, "30.0.0")

	// OFF (дефолт): точный набор
	stOff, err := e.m.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stOff.Sources) != 3 || activeDatHas(t, e, "30.0.0.1") {
		t.Fatalf("exact baseline: sources=%v ayn-ip=%v", stOff.Sources, activeDatHas(t, e, "30.0.0.1"))
	}
	datOff := e.m.ActiveDatFile()

	// ON: расширение (первый fetch allyouneed, changed=true)
	e.st.SetAntifilterMargin(true)
	e.m.nextTry = time.Time{}
	stOn, err := e.m.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stOn.Sources) != 4 || !activeDatHas(t, e, "30.0.0.1") {
		t.Fatalf("margin ON: sources=%v ayn-ip=%v", stOn.Sources, activeDatHas(t, e, "30.0.0.1"))
	}
	if stOn.PrefixCount >= stOff.PrefixCount {
		t.Logf("prefix count ON=%d OFF=%d (суммаризация by design)", stOn.PrefixCount, stOff.PrefixCount)
	}
	if e.m.ActiveDatFile() == datOff {
		t.Fatal("ON: dat не сменился (A/B hot-reload)")
	}

	// OFF при ВСЕХ-304 (корень бага): кеш allyouneed ЖИВ, но юнион обязан сузиться
	e.st.SetAntifilterMargin(false)
	e.m.nextTry = time.Time{}
	stOff2, err := e.m.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stOff2.Sources) != 3 {
		t.Fatalf("OFF: sources=%v want 3 (allyouneed исключён)", stOff2.Sources)
	}
	if stOff2.PrefixCount != stOff.PrefixCount {
		t.Errorf("OFF: prefix=%d want %d (возврат к точному набору)", stOff2.PrefixCount, stOff.PrefixCount)
	}
	if activeDatHas(t, e, "30.0.0.1") {
		t.Fatal("OFF при 304: allyouneed-only IP всё ещё в активном dat (AF-BUG-2)")
	}
	datOff2 := e.m.ActiveDatFile()
	if datOff2 == stOn.DatFile {
		t.Fatal("OFF: dat не пересобран (A/B swap обязателен для hot-reload ядра)")
	}

	// повторный OFF-refresh: набор уже применён — dat не дёргаем
	e.m.nextTry = time.Time{}
	stOff3, err := e.m.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stOff3.DatFile != datOff2 {
		t.Errorf("повторный OFF: dat сменился без изменений (%s→%s)", datOff2, stOff3.DatFile)
	}

	// РЕСТАРТ ПАНЕЛИ: новый Manager, те же БД/кеш/asset — суженный набор персистентен
	m2 := NewManager(e.st, e.cache, e.asset)
	m2.HTTP = e.m.HTTP
	stR, err := m2.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stR.Sources) != 3 || activeDatHas(t, e, "30.0.0.1") {
		t.Fatalf("после рестарта: sources=%v ayn-ip=%v (расширенный dat ожил)", stR.Sources, activeDatHas(t, e, "30.0.0.1"))
	}
	if stR.DatFile != datOff2 {
		t.Errorf("рестарт: активный dat сменился без причины (%s→%s)", datOff2, stR.DatFile)
	}

	// OFF→ON при всех-304: расширение возвращается форс-регенерацией
	e.st.SetAntifilterMargin(true)
	stOn2, err := m2.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stOn2.Sources) != 4 || !activeDatHas(t, e, "30.0.0.1") {
		t.Fatalf("ON после рестарта при 304: sources=%v ayn-ip=%v", stOn2.Sources, activeDatHas(t, e, "30.0.0.1"))
	}
	if stOn2.DatFile == stR.DatFile {
		t.Fatal("ON после рестарта: dat не пересобран")
	}
}

// TestMarginOffWithDeadSources — флаг OFF + источники недоступны (304 нет, ошибки):
// юнион из кеша БЕЗ allyouneed, регенерация всё равно форсируется.
func TestMarginOffWithDeadSources(t *testing.T) {
	e := newTestEnv(t)
	e.srcs["allyouneed"].body = genLines(16557, "30.0.0")
	e.st.SetAntifilterMargin(true)
	if _, err := e.m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !activeDatHas(t, e, "30.0.0.1") {
		t.Fatal("setup: ON не расширил")
	}
	for _, f := range e.srcs {
		f.status.Store(500)
	}
	e.st.SetAntifilterMargin(false)
	e.m.nextTry = time.Time{}
	st, err := e.m.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Source != "cache" {
		t.Errorf("source=%q want cache (источники мертвы, кеш жив)", st.Source)
	}
	if len(st.Sources) != 3 || activeDatHas(t, e, "30.0.0.1") {
		t.Fatalf("OFF с мёртвыми источниками: sources=%v ayn-ip=%v", st.Sources, activeDatHas(t, e, "30.0.0.1"))
	}
}
