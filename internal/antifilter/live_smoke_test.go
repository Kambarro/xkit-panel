package antifilter

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

// TestLiveSourcesSmoke — живая проверка РЕАЛЬНЫХ источников (не httptest):
// ETag-поллинг antifilter.download/community + runetfreedom geosite, генерация
// dat новой схемы из настоящего юниона. Запуск: XKIT_AF_LIVE=1 go test -run Live.
// CI/офлайн — skip (не фейк-зелёный). Sanity-пределы сверяются с живыми counts.
func TestLiveSourcesSmoke(t *testing.T) {
	if os.Getenv("XKIT_AF_LIVE") != "1" {
		t.Skip("живой смоук только по XKIT_AF_LIVE=1 (сеть к antifilter.download)")
	}
	st, err := store.Open(t.TempDir() + "/live.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	m := NewManager(st, t.TempDir(), t.TempDir())
	m.HTTP.Timeout = 90 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	state, err := m.Refresh(ctx)
	if err != nil {
		t.Fatalf("live refresh: %v (state=%+v)", err, state)
	}
	if state.Source != "live" {
		t.Errorf("source=%q want live (fallback сработал?)", state.Source)
	}
	// замеры research 2026-11-26: ipresolve 154k + subnet 69 + community 934 →
	// после collapse десятки тысяч префиксов; нижняя граница sanity
	if state.PrefixCount < 50000 {
		t.Errorf("prefix count suspiciously low: %d", state.PrefixCount)
	}
	if !m.Ready() {
		t.Fatal("manager not ready after live refresh")
	}
	// сгенерированный файл — новая geodata-схема, читается парсером ядра
	data, err := os.ReadFile(m.AssetDir + "/" + m.ActiveDatFile())
	if err != nil || !DatContains(data, BlockedCode) {
		t.Fatalf("generated dat invalid: %v", err)
	}
	// blocked-наборы для подписок непустые
	if txt, err := m.BlockedIPText(); err != nil || len(txt) < 10000 {
		t.Errorf("blocked ip text: %v len=%d", err, len(txt))
	}
	ds, err := m.BlockedDomains()
	if err != nil || len(ds) < 50000 {
		t.Errorf("blocked domains: %v len=%d (ожидалось ~73k)", err, len(ds))
	}
	found := false
	for _, d := range ds {
		if d == "youtube.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("youtube.com отсутствует в RU-BLOCKED (главная ловушка antifilter domains)")
	}
	t.Logf("LIVE OK: %d префиксов, %d доменов, источники %v", state.PrefixCount, len(ds), state.Sources)
	// повторный цикл — ETag 304 (не качает повторно)
	state2, err := m.Refresh(ctx)
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if state2.UpdatedAt != state.UpdatedAt {
		t.Logf("данные изменились между циклами (нормально для живого antifilter)")
	}
}