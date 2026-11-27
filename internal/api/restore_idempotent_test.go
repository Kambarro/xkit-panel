package api

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/kambarro/xkit-panel/internal/store"
)

// TestRestoreInboundsIdempotentNoWarn — BUG-9 (LOW, QA): двойной рестарт панели
// давал 20 warn «existing tag found» — RestoreInbounds не проверял наличие
// inbound в живом xray перед AddInbound. Функционально идемпотентен, но журнал
// замусорен. Второй Restore по живым inbound не должен плодить warn-события.
func TestRestoreInboundsIdempotentNoWarn(t *testing.T) {
	s := testStoreAPI(t)
	xc := startTestXray(t)
	srv := NewServer(s, xc, "test", "test.local")
	cert, key := testCertPEM(t)
	certJSON, _ := json.Marshal([]string{cert})
	keyJSON, _ := json.Marshal([]string{key})
	ib := store.Inbound{
		Tag: "preset-hysteria2", Protocol: "hysteria2", Port: 18461, Listen: "127.0.0.1",
		Network: "hysteria", Security: "tls", Enabled: true,
		Settings: `{"version":2,"clients":[]}`,
		Stream: fmt.Sprintf(`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2},"tlsSettings":{"serverName":"test.local","alpn":["h3"],"certificates":[{"certificate":%s,"key":%s}]}}`, certJSON, keyJSON),
	}
	if err := s.UpsertInbound(ib); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertClient(store.Client{Email: "client@example.com", UUID: "u1", SubID: "s1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// первый restore создаёт inbound (как первый старт панели)
	if err := xc.AddInbound(context.Background(), buildInboundJSON(ib)); err != nil {
		t.Fatal(err)
	}
	srv.RestoreInbounds()
	var warns1 int
	s.DB().QueryRow(`SELECT COUNT(*) FROM events WHERE kind='inbound_restore' AND severity='warn'`).Scan(&warns1)
	// второй restore по уже живому inbound — без warn «existing tag found»
	srv.RestoreInbounds()
	var warns2 int
	s.DB().QueryRow(`SELECT COUNT(*) FROM events WHERE kind='inbound_restore' AND severity='warn'`).Scan(&warns2)
	if warns2 > warns1 {
		t.Fatalf("второй RestoreInbounds добавил warn-событий: %d → %d (BUG-9: existing tag found)", warns1, warns2)
	}
}