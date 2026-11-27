package balancer

// Тест напоминаний аренды нод: окна 7/3/1 день, идемпотентность, отключение.
// testStore(t) уже содержит 4 ноды (expiry=0, бессрочные) — они не уведомляются.

import (
	"context"
	"testing"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

func TestNodeExpiryNotifications(t *testing.T) {
	st := testStore(t)
	c := &Controller{store: st}
	var sent []string
	c.NotifyAdmin = func(ctx context.Context, text string) error {
		sent = append(sent, text)
		return nil
	}
	now := time.Now().Unix()
	// нода с арендой через ~3 дня (71.5ч) — окно "3 дня" (72ч)
	st.UpsertNode(store.Node{ID: "n-exp-3d", Name: "TestNode", Country: "DE", CountryCode: 1, Host: "x.test", Health: "alive", Enabled: true, Expiry: now + 72*3600 - 1800})
	c.processNodeExpiryNotifications(context.Background(), now)
	if len(sent) != 1 {
		t.Fatalf("ожидалось 1 уведомление (окно 3 дня), got %d: %v", len(sent), sent)
	}
	// повторный вызов — идемпотентность
	c.processNodeExpiryNotifications(context.Background(), now)
	if len(sent) != 1 {
		t.Fatalf("идемпотентность нарушена: %d уведомлений", len(sent))
	}
	// нода через 10 дней — вне окна 7д (168ч), не слать
	st.UpsertNode(store.Node{ID: "n-exp-far", Name: "FarNode", Country: "DE", CountryCode: 1, Host: "y.test", Health: "alive", Enabled: true, Expiry: now + 240*3600})
	c.processNodeExpiryNotifications(context.Background(), now)
	if len(sent) != 1 {
		t.Fatalf("далёкая нода не должна уведомляться: %d", len(sent))
	}
	// отключённая нода с близким expiry — не слать (отключение уведомит отдельно)
	st.UpsertNode(store.Node{ID: "n-exp-off", Name: "OffNode", Country: "DE", CountryCode: 1, Host: "z.test", Health: "down", Enabled: false, Expiry: now + 3600})
	c.processNodeExpiryNotifications(context.Background(), now)
	if len(sent) != 1 {
		t.Fatalf("отключённая нода не должна уведомляться: %d", len(sent))
	}
}

func TestNotifyNodeDisabled(t *testing.T) {
	st := testStore(t)
	c := &Controller{store: st}
	var sent []string
	c.NotifyAdmin = func(ctx context.Context, text string) error {
		sent = append(sent, text)
		return nil
	}
	n := store.Node{ID: "n-dead", Name: "DeadNode", Country: "DE"}
	c.notifyNodeDisabled(context.Background(), n, "истёк срок аренды", 3)
	if len(sent) != 1 {
		t.Fatalf("ожидалось уведомление об отключении, got %d", len(sent))
	}
	c.notifyNodeDisabled(context.Background(), n, "истёк срок аренды", 3)
	if len(sent) != 1 {
		t.Fatalf("идемпотентность отключения нарушена: %d", len(sent))
	}
}