package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/kambarro/xkit-panel/internal/bot"
	"github.com/kambarro/xkit-panel/internal/store"
)

// BotManager — управляет жизненным циклом Telegram-бота из API (меню в UI).
// УРОК XKIT (для не-технарей): бот добавляется через форму в настройках (токен+admin),
// без терминала. Токен хранится в settings, бот перезапускается при смене без рестарта панели.
type BotManager struct {
	mu     sync.Mutex
	bot    *bot.Bot
	cancel context.CancelFunc
	store  *store.Store
	domain string
	// countryChange — горячее переназначение после смены страны кнопкой бота
	// (ctrl.PushAssignment из main.go). Пробрасывается в каждый новый bot.Bot.
	countryChange func(ctx context.Context, email, country string) error
}

func NewBotManager(st *store.Store, domain string) *BotManager {
	return &BotManager{store: st, domain: domain}
}

// SetCountryChange — колбэк горячего переназначения (🌍 Страна в клиентском меню).
func (m *BotManager) SetCountryChange(fn func(ctx context.Context, email, country string) error) {
	m.mu.Lock()
	m.countryChange = fn
	b := m.bot
	m.mu.Unlock()
	if b != nil {
		b.SetCountryChange(fn)
	}
}

// Start запускает бота если токен задан в settings (или env при первом старте).
func (m *BotManager) Start(ctx context.Context, envToken, envAdmin string) {
	token := m.store.GetSetting("tg_token", envToken)
	admin := m.store.GetSetting("tg_admin", envAdmin)
	m.Restart(ctx, token, admin)
}

// Restart — останавливает старого бота и запускает нового (если токен задан).
func (m *BotManager) Restart(ctx context.Context, token, admin string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	if m.bot != nil {
		m.bot.Stop()
		m.bot = nil
	}
	if token == "" {
		return
	}
	adminID, _ := strconv.ParseInt(admin, 10, 64)
	b := bot.New(token, adminID, m.store, m.domain)
	if m.countryChange != nil {
		b.SetCountryChange(m.countryChange)
	}
	bctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.bot = b
	b.Start(bctx)
}

// Running — запущен ли бот.
func (m *BotManager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bot != nil
}

// Transport — канал доставки TG (direct / tunnel + нода).
func (m *BotManager) Transport() (mode, node string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bot == nil {
		return "", ""
	}
	return m.bot.TransportStatus()
}

// SendFile — отправить файл через текущего бота (бэкапы). Ошибка если бот не запущен.
func (m *BotManager) SendFile(ctx context.Context, path string) error {
	m.mu.Lock()
	b := m.bot
	m.mu.Unlock()
	if b == nil {
		return fmt.Errorf("бот не запущен")
	}
	return b.SendFile(ctx, path)
}

// SendText — отправить текст произвольному chat (уведомления клиентам, P0 #3).
func (m *BotManager) SendText(ctx context.Context, chat int64, text string) error {
	m.mu.Lock()
	b := m.bot
	m.mu.Unlock()
	if b == nil {
		return fmt.Errorf("бот не запущен")
	}
	return b.SendText(ctx, chat, text)
}

// SendAdmin — уведомление админу (биллинг-алерты нод P1 #5). adminID из settings.
func (m *BotManager) SendAdmin(ctx context.Context, text string) error {
	adminStr := m.store.GetSetting("tg_admin", "0")
	adminID, _ := strconv.ParseInt(adminStr, 10, 64)
	if adminID == 0 {
		return fmt.Errorf("admin не настроен")
	}
	return m.SendText(ctx, adminID, text)
}

// botStatus — GET /api/bot: статус бота + настроен ли токен (без раскрытия токена).
func (s *Server) botStatus(w http.ResponseWriter, r *http.Request) {
	token := s.store.GetSetting("tg_token", "")
	admin := s.store.GetSetting("tg_admin", "")
	configured := token != ""
	running := false
	if s.botMgr != nil {
		running = s.botMgr.Running()
	}
	// токен НЕ раскрываем полностью — только маска (последние 4 символа)
	masked := ""
	if configured && len(token) > 8 {
		masked = "…" + token[len(token)-4:]
	}
	trMode, trNode := "", ""
	if s.botMgr != nil {
		trMode, trNode = s.botMgr.Transport()
	}
	writeJSON(w, map[string]any{
		"configured": configured,
		"running":    running,
		"admin":      admin,
		"token_mask": masked,
		"transport":  trMode,
		"transport_node": trNode,
	})
}

// botRestart — POST /api/bot/restart: перезапустить бота с текущими настройками.
func (s *Server) botRestart(w http.ResponseWriter, r *http.Request) {
	if s.botMgr == nil {
		http.Error(w, "бот не настроен", 400)
		return
	}
	token := s.store.GetSetting("tg_token", "")
	admin := s.store.GetSetting("tg_admin", "0")
	if token == "" {
		http.Error(w, "бот не настроен (токен пуст)", 400)
		return
	}
	s.botMgr.Restart(r.Context(), token, admin)
	s.store.AddEvent("bot", "ok", "бот перезапущен", "{}")
	writeJSON(w, map[string]any{"ok": true})
}

// botConfigure — POST /api/bot: сохранить токен+admin, перезапустить бота.
// УРОК: валидация на границе доверия, ошибки не глушим.
func (s *Server) botConfigure(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
		Admin string `json:"admin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	body.Token = strings.TrimSpace(body.Token)
	body.Admin = strings.TrimSpace(body.Admin)
	// пустой токен = отключить бота
	if body.Token == "" {
		s.store.SetSetting("tg_token", "")
		s.store.SetSetting("tg_admin", "")
		if s.botMgr != nil {
			s.botMgr.Restart(r.Context(), "", "")
		}
		s.store.AddEvent("bot", "info", "Telegram-бот отключён", "{}")
		writeJSON(w, map[string]any{"ok": true, "running": false})
		return
	}
	// валидация токена: формат 123456:ABC-DEF... (digits:alnum)
	if !validBotToken(body.Token) {
		http.Error(w, "неверный формат токена (ожидается 123456789:AA... от @BotFather)", 400)
		return
	}
	// admin должен быть числом (chat id)
	if body.Admin != "" {
		if _, err := strconv.ParseInt(body.Admin, 10, 64); err != nil {
			http.Error(w, "admin должен быть числом (ваш Telegram chat id, узнать у @userinfobot)", 400)
			return
		}
	}
	s.store.SetSetting("tg_token", body.Token)
	s.store.SetSetting("tg_admin", body.Admin)
	if s.botMgr != nil {
		s.botMgr.Restart(r.Context(), body.Token, body.Admin)
	}
	s.store.AddEvent("bot", "ok", "Telegram-бот настроен и запущен", "{}")
	writeJSON(w, map[string]any{"ok": true, "running": s.botMgr != nil && s.botMgr.Running()})
}

// validBotToken — формат Telegram bot token: <digits>:<alnum_- >.
func validBotToken(t string) bool {
	i := strings.Index(t, ":")
	if i < 5 || i > 20 {
		return false
	}
	id, secret := t[:i], t[i+1:]
	if len(secret) < 20 {
		return false
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return false
		}
	}
	for _, r := range secret {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}