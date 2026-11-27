package notify

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

// Webhook-уведомления (P1 #14, Remnawave/Marzban webhook с подписью + ретраи).
// УРОК (panels-research): интеграции — свой бот магазина, Uptime-Kuma, биллинг.
// Панель шлёт POST JSON на webhook_url с HMAC-SHA256 подписью в заголовке X-XKIT-Signature.
// События фильтруются по webhook_events (CSV kind'ов, пусто = все). Ретраи 3× с backoff.
// Асинхронно (не блокирует control loop), ошибки не глушатся — пишутся в events.

type Webhook struct {
	store  *store.Store
	client *http.Client
	mu     sync.Mutex
	queue  chan payload
	once   sync.Once
}

type payload struct {
	Event     string `json:"event"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Meta      string `json:"meta,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

func NewWebhook(s *store.Store) *Webhook {
	return &Webhook{
		store:  s,
		client: &http.Client{Timeout: 10 * time.Second},
		queue:  make(chan payload, 256),
	}
}

// Start запускает воркер отправки (один раз).
func (w *Webhook) Start() {
	w.once.Do(func() {
		go w.worker()
	})
}

// Emit ставит событие в очередь (вызывается из AddEvent-обёртки/control loop).
func (w *Webhook) Emit(kind, severity, message, meta string) {
	url := w.store.GetSetting("webhook_url", "")
	if url == "" {
		return
	}
	// фильтр по kind'ам
	events := w.store.GetSetting("webhook_events", "")
	if events != "" {
		ok := false
		for _, k := range strings.Split(events, ",") {
			if strings.TrimSpace(k) == kind || strings.TrimSpace(k) == "*" {
				ok = true
				break
			}
		}
		if !ok {
			return
		}
	}
	select {
	case w.queue <- payload{Event: kind, Severity: severity, Message: message, Meta: meta, Timestamp: time.Now().Unix()}:
	default:
		// очередь полна — не блокируем, логируем потерю
		w.store.AddEvent("webhook", "warn", "очередь webhook полна, событие пропущено: "+kind, "{}")
	}
}

func (w *Webhook) worker() {
	for p := range w.queue {
		w.send(p)
	}
}

func (w *Webhook) send(p payload) {
	url := w.store.GetSetting("webhook_url", "")
	if url == "" {
		return
	}
	secret := w.store.GetSetting("webhook_secret", "")
	body, _ := json.Marshal(p)
	// ретраи 3× с backoff (1s, 2s, 4s)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<attempt) * time.Second)
		}
		req, err := http.NewRequest("POST", url, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "XKIT-Panel-Webhook/1.0")
		if secret != "" {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(body)
			req.Header.Set("X-XKIT-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
		resp, err := w.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return // успех
		}
		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	w.store.AddEvent("webhook", "error", fmt.Sprintf("webhook не доставлен после 3 попыток: %v", lastErr), "{}")
}

// Test отправляет тестовое событие (из UI «Проверить webhook»).
func (w *Webhook) Test() error {
	url := w.store.GetSetting("webhook_url", "")
	if url == "" {
		return fmt.Errorf("webhook_url не задан")
	}
	w.Emit("webhook_test", "ok", "Тестовое событие XKIT Panel", "{}")
	return nil
}