package api

// E2E детекта внешнего рестарта xray: in-process ядро закрывается (аналог
// systemctl restart мимо панели) → watch обязан заметить и RestoreInbounds
// восстановить горячий preset-inbound на новом ядре.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/xray"
)

// startRestartableXray — ядро на фиксированном loopback-порту, можно закрыть и
// поднять заново на том же порту (как systemctl restart xray). extraInbounds —
// JSON-массив inbound'ов, ПЕРСИСТЕНТНЫХ в конфиг-файле (переживают рестарт, как
// vless-reality на живом мастере).
func startRestartableXray(t *testing.T, addr string, extraInbounds ...map[string]any) *core.Instance {
	t.Helper()
	inbounds := []any{map[string]any{"tag": "api-in", "listen": "127.0.0.1", "port": 0, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}}}
	for _, ib := range extraInbounds {
		inbounds = append(inbounds, ib)
	}
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "error"},
		"api":       map[string]any{"tag": "api", "listen": addr, "services": []string{"HandlerService", "RoutingService", "StatsService"}},
		"inbounds":  inbounds,
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "api", "protocol": "freedom"}},
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "inboundTag": []string{"api-in"}, "outboundTag": "api"}}},
	}
	cfgJSON, _ := json.Marshal(cfg)
	pbCfg, err := serial.LoadJSONConfig(strings.NewReader(string(cfgJSON)))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	inst, err := core.New(pbCfg)
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	return inst
}

func TestWatchXrayExternalRestartE2E(t *testing.T) {
	s := testStoreAPI(t)
	// порт фиксируем ДО старта ядра
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	inst := startRestartableXray(t, addr)
	defer inst.Close()
	xc, err := xray.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { xc.Close() })
	srv := NewServer(s, xc, "test", "test.local")

	// preset-inbound в БД (trojan — без hy2-пересоздания, чистый AddInbound путь)
	ib := store.Inbound{
		Tag: "preset-trojan", Protocol: "trojan", Port: 18446, Listen: "127.0.0.1",
		Network: "tcp", Security: "none", Enabled: true,
		Settings: `{"clients":[]}`, Stream: `{"network":"tcp","security":"none"}`,
	}
	if err := s.UpsertInbound(ib); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := xc.AddInbound(ctx, buildInboundJSON(ib)); err != nil {
		t.Fatalf("AddInbound: %v", err)
	}
	if !srv.xrayInboundExists(ctx, "preset-trojan") {
		t.Fatal("inbound должен жить до рестарта")
	}

	// watch с быстрым тиком; ждём первый сэмпл ДО рестарта (иначе haveLast=false
	// и быстрый рестарт между тиками не детектится — как и в проде с 30с тиком)
	wctx, wcancel := context.WithCancel(context.Background())
	defer wcancel()
	go srv.watchXrayRestartEvery(wctx, 100*time.Millisecond)
	time.Sleep(300 * time.Millisecond)

	// ВНЕШНИЙ рестарт: закрыть ядро, поднять новое на том же addr (панель не уведомлена)
	inst.Close()
	inst2 := startRestartableXray(t, addr)
	defer inst2.Close()

	// ждём: watch заметил → Reconnect + RestoreInbounds → inbound снова жив
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		pctx, pcancel := context.WithTimeout(context.Background(), 2*time.Second)
		ok := srv.xrayInboundExists(pctx, "preset-trojan")
		pcancel()
		if ok {
			return // восстановлено
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("inbound НЕ восстановлен после внешнего рестарта xray (watch не сработал)")
}

// TestWatchXrayExternalRestartPersistentRealityE2E — кейс живого Ops b737b05:
// config.json несёт ПЕРСИСТЕНТНЫЙ vless-reality :низкий порт — он ПЕРВЫЙ в
// AllInbounds (ORDER BY port) и переживает рестарт. Старый детект брал первый
// enabled inbound «репрезентативным» → всегда false, горячие preset (hy2/xhttp/ws)
// оставались мёртвыми до рестарта панели. Теперь проверяются ВСЕ preset из БД.
func TestWatchXrayExternalRestartPersistentRealityE2E(t *testing.T) {
	s := testStoreAPI(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	// свободный блок портов НИЖЕ эфемерного диапазона: reality первым в ORDER BY port
	base := 0
	for p := 11000; p < 30000; p += 4 {
		ok := true
		var lns []net.Listener
		for i := 0; i < 4; i++ {
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p+i))
			if err != nil {
				ok = false
				break
			}
			lns = append(lns, l)
		}
		for _, l := range lns {
			l.Close()
		}
		if ok {
			base = p
			break
		}
	}
	if base == 0 {
		t.Fatal("нет свободного блока портов")
	}
	// персистентный reality: минимальный валидный vless-tcp без security
	// (для детекта важен только факт «переживает рестарт и первый по порту»)
	persistent := map[string]any{
		"tag": "vless-reality", "listen": "127.0.0.1", "port": base, "protocol": "vless",
		"settings": map[string]any{"clients": []any{}, "decryption": "none"},
		"streamSettings": map[string]any{"network": "tcp", "security": "none"},
	}
	inst := startRestartableXray(t, addr, persistent)
	defer inst.Close()
	xc, err := xray.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { xc.Close() })
	srv := NewServer(s, xc, "test", "test.local")

	// персистентный inbound есть и в БД — enabled, низкий порт = ПЕРВЫЙ в ORDER BY port
	if err := s.UpsertInbound(store.Inbound{
		Tag: "vless-reality", Protocol: "vless", Port: base, Listen: "127.0.0.1",
		Network: "tcp", Security: "none", Enabled: true,
		Settings: `{"clients":[],"decryption":"none"}`, Stream: `{"network":"tcp","security":"none"}`,
	}); err != nil {
		t.Fatal(err)
	}
	cert, key := testCertPEM(t)
	certJSON, _ := json.Marshal([]string{cert})
	keyJSON, _ := json.Marshal([]string{key})
	// горячие preset как на живом: hy2 (auth+salamander), xhttp, ws — НЕ в config.json
	presets := []store.Inbound{
		{
			Tag: "preset-hysteria2", Protocol: "hysteria2", Port: base + 1, Listen: "127.0.0.1",
			Network: "hysteria", Security: "tls", Enabled: true,
			Settings: `{"version":2,"clients":[{"auth":"watch-auth-uuid","email":"client@example.com","level":0}]}`,
			Stream: fmt.Sprintf(`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2},"tlsSettings":{"serverName":"test.local","alpn":["h3"],"certificates":[{"certificate":%s,"key":%s}]},"finalmask":{"udp":[{"type":"salamander","settings":{"password":"watchobfs"}}]}}`, certJSON, keyJSON),
		},
		{
			Tag: "preset-xhttp", Protocol: "vless", Port: base + 2, Listen: "127.0.0.1",
			Network: "xhttp", Security: "none", Enabled: true,
			Settings: `{"clients":[],"decryption":"none"}`,
			Stream:   `{"network":"xhttp","security":"none","xhttpSettings":{"path":"/xh","mode":"auto"}}`,
		},
		{
			Tag: "preset-ws-tls", Protocol: "vless", Port: base + 3, Listen: "127.0.0.1",
			Network: "ws", Security: "none", Enabled: true,
			Settings: `{"clients":[],"decryption":"none"}`,
			Stream:   `{"network":"ws","security":"none","wsSettings":{"path":"/ws"}}`,
		},
	}
	// ws — hideable: RestoreInbounds спрячет его за dispatcher; dispatcher-серт
	// в проде LE-файл, здесь его нет — заранее помечаем hidden, чтобы restore
	// шёл чистым AddInbound (masking-поведение вне скоупа этого теста).
	presets[2].Hidden = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, ib := range presets {
		if err := s.UpsertInbound(ib); err != nil {
			t.Fatal(err)
		}
		if err := xc.AddInbound(ctx, buildInboundJSON(ib)); err != nil {
			t.Fatalf("AddInbound %s: %v", ib.Tag, err)
		}
	}
	for _, ib := range presets {
		if !srv.xrayInboundExists(ctx, ib.Tag) {
			t.Fatalf("%s должен жить до рестарта", ib.Tag)
		}
	}
	// состояние детекта до рестарта: всё на месте → false
	if srv.hotInboundMissing(ctx) {
		t.Fatal("hotInboundMissing=true до рестарта")
	}

	// ВНЕШНИЙ рестарт с ТЕМ ЖЕ config.json: reality персистентен и снова первый.
	// Watch ещё НЕ запущен: на живом даун-окно (~1с) короче тика (30с), gRPC
	// реконнектится сам — событийные триггеры (lastErr/ConnBroken) не срабатывают.
	inst.Close()
	inst2 := startRestartableXray(t, addr, persistent)
	defer inst2.Close()
	// ждём готовности API нового ядра (gRPC реконнектится сам, без панели)
	apiUp := false
	for i := 0; i < 50; i++ {
		pctx, pcancel := context.WithTimeout(context.Background(), 1*time.Second)
		_, err := xc.OnlineUsers(pctx)
		pcancel()
		if err == nil {
			apiUp = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !apiUp {
		t.Fatal("API нового ядра не поднялся")
	}
	// ДЕТЕРМИНИРОВАННАЯ регрессия бага Ops: первый по порту (персистентный
	// reality) жив, но горячие preset пропали — детект обязан вернуть true.
	// Старый код брал первый inbound «репрезентативным» → false → watch мёртв.
	if !srv.hotInboundMissing(ctx) {
		t.Fatal("hotInboundMissing=false при пропавших preset: персистентный reality маскирует рестарт (баг Ops)")
	}

	// watch стартует ПОСЛЕ рестарта (как панель, пережившая даун-окно между
	// тиками): детект состояния обязан восстановить preset без событий дауна
	wctx, wcancel := context.WithCancel(context.Background())
	defer wcancel()
	go srv.watchXrayRestartEvery(wctx, 100*time.Millisecond)

	// ждём восстановления ВСЕХ горячих preset (не только первого по порту)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		for _, ib := range presets {
			pctx, pcancel := context.WithTimeout(context.Background(), 2*time.Second)
			ok := srv.xrayInboundExists(pctx, ib.Tag)
			pcancel()
			if !ok {
				all = false
				break
			}
		}
		if all {
			// событие watch зафиксировано (на живом Ops их было 0)
			var cnt int
			s.DB().QueryRow(`SELECT COUNT(*) FROM events WHERE kind='xray_watch'`).Scan(&cnt)
			if cnt == 0 {
				t.Fatal("preset восстановлены, но события xray_watch нет")
			}
			// персистентный reality жив (рестарт его не сносил)
			pctx, pcancel := context.WithTimeout(context.Background(), 2*time.Second)
			ok := srv.xrayInboundExists(pctx, "vless-reality")
			pcancel()
			if !ok {
				t.Fatal("персистентный vless-reality пропал")
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("горячие preset (hy2/xhttp/ws) НЕ восстановлены: персистентный reality маскирует рестарт (баг Ops)")
}
