package balancer

// E2E базовой модели (cs-слой удалён) на РЕАЛЬНОМ xray 26.11.9 (XKIT_XRAY_BIN):
//   - базовое per-user: клиент → нода страны из clients.country, БЕЗ cs-правил;
//   - смена страны (clients.country + PushAssignment, как API подписки/бот) →
//     горячо другая нода, UUID тот же;
//   - нода/страна умерла → failover на живую ДРУГУЮ страну без cs-дыры
//     (клиент ничего не делал);
//   - родная страна ожила + reconnect (offline по OnlineUsers) → возврат;
//   - mid-session no-jumps: живая сессия не дёргается при смене score.

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/xray"
)

// baseRoute — TestRoute базового UUID клиента (без страновых профилей).
func baseRoute(t *testing.T, xc *xray.Client, email string) string {
	t.Helper()
	resp, err := xc.TestRoute(t.Context(), "vless-in", email)
	if err != nil {
		t.Fatalf("TestRoute: %v", err)
	}
	return resp.GetOutboundTag()
}

// baseSetup — стенд базовой модели: ru-direct (дефолт), 2 NL-ноды + DE/US,
// реальный xray, quality-выбор. Возврат как afStickySetup.
func baseSetup(t *testing.T) (*store.Store, *xray.Client, *Controller, int, string, string) {
	t.Helper()
	s, xc, c, vlessPort, cfgPath, bin := afStickySetup(t)
	if err := s.SetRoutingMode(""); err != nil { // авто: ru-direct с нодами
		t.Fatal(err)
	}
	return s, xc, c, vlessPort, cfgPath, bin
}

// assertNoCSRules — в ядре нет cs:/cspd:/cspi: правил, базовое per-user ровно одно.
func assertNoCSRules(t *testing.T, xc *xray.Client, email string) {
	t.Helper()
	rules, err := xc.ListRules(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	base := 0
	for _, r := range rules {
		if strings.HasPrefix(r.RuleTag, "cs:") || strings.HasPrefix(r.RuleTag, "cspd:") || strings.HasPrefix(r.RuleTag, "cspi:") {
			t.Fatalf("cs-правило в ядре (слой удалён): %s", r.RuleTag)
		}
		if strings.HasPrefix(r.RuleTag, "c:"+email+":") {
			base++
		}
	}
	if base != 1 {
		t.Fatalf("базовых per-user правил %d, want 1", base)
	}
}

// TestBaseCountryChangeHotE2E — базовое per-user + смена страны через API-путь
// (clients.country + PushAssignment): горячо другая нода, UUID тот же, cs нет.
func TestBaseCountryChangeHotE2E(t *testing.T) {
	s, xc, c, vlessPort, cfgPath, bin := baseSetup(t)
	// канон country_codes (в живой БД его ставит миграция 034; testStore — нет)
	s.DB().Exec(`INSERT OR REPLACE INTO country_codes(country,code) VALUES('NL',2),('DE',1),('US',3)`)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatal(err)
	}
	s.SetNodeQuality("node-nl-1", 50, 99, 60)
	s.SetNodeQuality("node-nl-2", 10, 100, 95)
	if _, err := c.PushAssignment(t.Context(), "client@example.com", "NL"); err != nil {
		t.Fatal(err)
	}
	if got := baseRoute(t, xc, "client@example.com"); got != "node-nl-2" {
		t.Fatalf("старт: маршрут %q, want node-nl-2 (лучшая NL)", got)
	}
	targetPort, closeTarget := afTargetServer(t)
	defer closeTarget()
	req := []byte("GET / HTTP/1.1\r\nHost: youtube.com\r\nConnection: close\r\n\r\n")
	// реальный трафик базового UUID через NL-ноду (ru-direct: всё не-RU → нода)
	if out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req); err != nil || !bytes.Contains(out, []byte("200-OK")) {
		t.Fatalf("трафик до смены: %v %.40q", err, out)
	}

	// смена страны как PublicClientCountry: единая store-точка + PushAssignment
	if _, err := s.ChangeClientCountry("client@example.com", "US", 10, "subscription"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PushAssignment(t.Context(), "client@example.com", "US"); err != nil {
		t.Fatal(err)
	}
	if got := baseRoute(t, xc, "client@example.com"); got != "node-us-1" {
		t.Fatalf("после смены: маршрут %q, want node-us-1 (горячо)", got)
	}
	assertNoCSRules(t, xc, "client@example.com")
	// тот же UUID клиента — трафик сразу через US-ноду, пересоздания не было
	for i := 0; i < 3; i++ {
		if out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req); err != nil || !bytes.Contains(out, []byte("200-OK")) {
			t.Fatalf("после смены conn#%d: %v %.40q", i, err, out)
		}
		if got := baseRoute(t, xc, "client@example.com"); got != "node-us-1" {
			t.Fatalf("после смены conn#%d маршрут %q", i, got)
		}
	}
	// персистентный конфиг: базовое c:-правило, cs/vlessRoute отсутствуют
	cfgData, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(cfgData), `"vlessRoute"`) || strings.Contains(string(cfgData), `"cs:`) {
		t.Fatal("cs/vlessRoute в персистентном config.json")
	}
	if !strings.Contains(string(cfgData), "c:client@example.com:US") {
		t.Fatal("базовое per-user правило не персистится")
	}
	if out, err := afRunTest(t, bin, cfgPath, os.Getenv("xray.location.asset")); err != nil {
		t.Fatalf("run -test: %v\n%s", err, out)
	}
}

// TestBaseFailoverCountryDownE2E — вся страна клиента умерла → fallback на живую
// ДРУГУЮ страну без cs-дыры (клиент ничего не делал); родная ожила + reconnect
// (offline) → возврат на лучшую родной страны.
func TestBaseFailoverCountryDownE2E(t *testing.T) {
	s, xc, c, vlessPort, _, _ := baseSetup(t)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatal(err)
	}
	s.SetNodeQuality("node-nl-1", 50, 99, 60)
	s.SetNodeQuality("node-nl-2", 10, 100, 95)
	s.SetNodeQuality("node-de-1", 20, 100, 80)
	s.SetNodeQuality("node-us-1", 30, 100, 70)
	if _, err := c.PushAssignment(t.Context(), "client@example.com", "NL"); err != nil {
		t.Fatal(err)
	}
	targetPort, closeTarget := afTargetServer(t)
	defer closeTarget()
	req := []byte("GET / HTTP/1.1\r\nHost: youtube.com\r\nConnection: close\r\n\r\n")
	if out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req); err != nil || !bytes.Contains(out, []byte("200-OK")) {
		t.Fatalf("до failover: %v %.40q", err, out)
	}

	// ОБЕ NL-ноды умерли (3 неудачных пробы каждая — гистерезис) → failover
	for _, node := range []string{"node-nl-1", "node-nl-2"} {
		for i := 0; i < 3; i++ {
			if _, err := c.bal.RecordProbe(t.Context(), node, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	moved, err := c.bal.FailoverNode(t.Context(), "node-nl-2", map[string]NodeLoad{})
	if err != nil {
		t.Fatal(err)
	}
	// nl-1 тоже down: её assignment (если остался) дочинивает reevaluate-fallback
	c.SyncRulesNow(t.Context())
	c.reevaluate(t.Context())
	a, _ := s.GetAssignment("client@example.com", "NL")
	if a == nil || a.NodeID == "node-nl-1" || a.NodeID == "node-nl-2" {
		t.Fatalf("после смерти страны назначение %+v (want живая другая страна), moved=%d", a, moved)
	}
	if a.Status != StatusFailover {
		t.Fatalf("статус %q, want failover", a.Status)
	}
	got := baseRoute(t, xc, "client@example.com")
	if got != a.NodeID {
		t.Fatalf("маршрут %q ≠ назначение %q (cs-дыра: клиент в catch-all?)", got, a.NodeID)
	}
	// клиент НИЧЕГО не делал: тот же UUID сразу работает через fallback-ноду
	for i := 0; i < 3; i++ {
		if out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req); err != nil || !bytes.Contains(out, []byte("200-OK")) {
			t.Fatalf("fallback conn#%d: %v %.40q (обрыв без cs!)", i, err, out)
		}
	}
	assertNoCSRules(t, xc, "client@example.com")

	// родная NL ожила (проба ok) + клиент offline → reevaluate возвращает на лучшую NL
	if _, err := c.bal.RecordProbe(t.Context(), "node-nl-2", true); err != nil {
		t.Fatal(err)
	}
	afWaitOnline(t, xc, "client@example.com", false) // все соединения закрыты (Connection: close)
	c.reevaluate(t.Context())
	a, _ = s.GetAssignment("client@example.com", "NL")
	if a == nil || a.NodeID != "node-nl-2" {
		t.Fatalf("возврат: назначение %+v, want node-nl-2 (родная ожила, лучшая)", a)
	}
	if got := baseRoute(t, xc, "client@example.com"); got != "node-nl-2" {
		t.Fatalf("возврат: маршрут %q, want node-nl-2", got)
	}
	if out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req); err != nil || !bytes.Contains(out, []byte("200-OK")) {
		t.Fatalf("после возврата: %v %.40q", err, out)
	}
}

// TestBaseNoJumpsMidSessionE2E — живая сессия + смена score → клиент НЕ дёргается
// (mid-session sticky базовой модели); offline → лучшая сейчас.
func TestBaseNoJumpsMidSessionE2E(t *testing.T) {
	s, xc, c, vlessPort, _, _ := baseSetup(t)
	if err := s.UpsertClient(testClient("client@example.com", "NL", 2)); err != nil {
		t.Fatal(err)
	}
	s.SetNodeQuality("node-nl-1", 50, 99, 60)
	s.SetNodeQuality("node-nl-2", 10, 100, 95)
	if _, err := c.PushAssignment(t.Context(), "client@example.com", "NL"); err != nil {
		t.Fatal(err)
	}
	targetPort, closeTarget := afTargetServer(t)
	defer closeTarget()
	req := []byte("GET / HTTP/1.1\r\nHost: youtube.com\r\nConnection: close\r\n\r\n")

	// живая сессия (online) + score перевернулся → маршрут НЕ меняется
	closeSession := afOpenSession(t, vlessPort, targetPort)
	afWaitOnline(t, xc, "client@example.com", true)
	s.SetNodeQuality("node-nl-1", 5, 100, 99)
	s.SetNodeQuality("node-nl-2", 80, 90, 30)
	c.reevaluate(t.Context())
	if got := baseRoute(t, xc, "client@example.com"); got != "node-nl-2" {
		t.Fatalf("mid-session скачок: %q (online-клиент обязан остаться)", got)
	}
	// 5 параллельных коротких соединений — все на той же ноде (no-jumps)
	for i := 0; i < 5; i++ {
		if out, err := afVlessFetchDomain(t, vlessPort, "youtube.com", targetPort, req); err != nil || !bytes.Contains(out, []byte("200-OK")) {
			t.Fatalf("mid-session conn#%d: %v %.40q", i, err, out)
		}
		if got := baseRoute(t, xc, "client@example.com"); got != "node-nl-2" {
			t.Fatalf("mid-session conn#%d скачок на %q", i, got)
		}
	}
	// offline → лучшая сейчас (nl-1)
	closeSession()
	afWaitOnline(t, xc, "client@example.com", false)
	c.reevaluate(t.Context())
	if got := baseRoute(t, xc, "client@example.com"); got != "node-nl-1" {
		t.Fatalf("reconnect: маршрут %q, want node-nl-1 (лучшая сейчас)", got)
	}
}