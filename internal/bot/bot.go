// Package bot — Telegram-бот XKIT Panel (альтернативный пульт без терминала).
// УРОКИ main XKIT (references/xkit-panel-lessons.md), чтобы баги НЕ повторились:
//  1. Crash-loop кнопок: каждый обработчик callback обёрнут в recover() — одна плохая
//     кнопка не роняет весь бот-процесс (systemd restart-loop = тот же симптом что
//     _rest unbound в main). Парсинг callback_data защитный (SplitN + проверка len).
//  2. Куча сообщений подписки: ОДНО HTML-сообщение, каждая ссылка в <pre> блоке
//     (Telegram даёт кнопку «копировать» на каждый блок — чистый URL).
//  3. Пошаговый мастер создания (для не-технарей): кнопка → email → дни кнопками →
//     ГБ кнопками → результат. НЕ требовать точную команду «/adduser email days gb».
//  4. Молчаливые ошибки: ошибка создания → понятный текст пользователю, не «создан».
package bot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

// Bot — Telegram-бот панели. Long-polling getUpdates, inline-меню.
type Bot struct {
	token   string
	adminID int64 // разрешённый админ (chat id)
	store   *store.Store
	domain  string
	client  *http.Client
	tr      *transport // direct / SSH-туннель через ноду (авто)

	mu     sync.Mutex
	states map[int64]*addState // пошаговый мастер создания (chat → state)
	offset int64
	stopCh chan struct{}
	wg     sync.WaitGroup

	// countryChange — горячее переназначение после смены страны клиентом (🌍).
	// Ставится из BotManager (ctrl.PushAssignment). nil = только запись в БД.
	countryChange func(ctx context.Context, email, country string) error
}

// addState — состояние мастера создания пользователя (шаги email→days→gb).
type addState struct {
	Step  string // email / days / gb
	Email string
	Days  int
}

// New создаёт бота. token пуст → бот не запускается (опционален).
func New(token string, adminID int64, st *store.Store, domain string) *Bot {
	b := &Bot{
		token:   token,
		adminID: adminID,
		store:   st,
		domain:  domain,
		client:  &http.Client{Timeout: 40 * time.Second},
		states:  make(map[int64]*addState),
		stopCh:  make(chan struct{}),
	}
	// транспорт: живой SSH-ключ нод → включаем авто-туннель через ноду при блокировке TG
	key := "/var/lib/xkit-panel/node_key"
	b.tr = newTransport(key, func() []tunnelNode {
		ns, err := st.AllNodes()
		if err != nil {
			return nil
		}
		var out []tunnelNode
		for _, n := range ns {
			if n.Enabled && n.Health == "alive" && n.Host != "" {
				out = append(out, tunnelNode{ID: n.ID, Host: n.Host})
			}
		}
		return out
	})
	return b
}

// Start запускает polling-цикл (если токен задан).
func (b *Bot) Start(ctx context.Context) {
	if b.token == "" {
		log.Println("bot: токен не задан — бот не запущен (опционален)")
		return
	}
	// автоопределение username бота (getMe) → settings tg_bot_username (для invite-link P0 #4)
	go b.detectUsername(ctx)
	// транспорт-монитор: direct → SSH-туннель через ноду при блокировке TG (авто-восстановление)
	b.tr.start(ctx)
	b.wg.Add(1)
	go b.loop(ctx)
	log.Println("bot: Telegram-бот запущен (inline-меню, пошаговый мастер, авто-транспорт через ноду)")
}

// detectUsername — getMe → сохранит username в settings (claim-link строит t.me/<username>?start=).
// УРОК: первый getMe может упасть (транспорт ещё direct, TG заблокирован) — ретраи,
// пока туннель не поднимется. Иначе username пуст навсегда.
func (b *Bot) detectUsername(ctx context.Context) {
	for i := 0; i < 30; i++ {
		res, err := b.api(ctx, "getMe", url.Values{})
		if err == nil {
			var me struct{ Username string `json:"username"` }
			if json.Unmarshal(res, &me) == nil && me.Username != "" {
				b.store.SetSetting("tg_bot_username", me.Username)
				log.Printf("bot: username @%s (invite-link готов)", me.Username)
				return
			}
		}
		select {
		case <-b.stopCh:
			return
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (b *Bot) Stop() {
	close(b.stopCh)
	b.wg.Wait()
	if b.tr != nil {
		b.tr.stop()
	}
}

// TransportStatus — текущий канал доставки (direct / tunnel + нода). Для UI/статуса.
func (b *Bot) TransportStatus() (mode, node string) {
	if b.tr == nil {
		return "direct", ""
	}
	return b.tr.status()
}

func (b *Bot) loop(ctx context.Context) {
	defer b.wg.Done()
	for {
		select {
		case <-b.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}
		if err := b.pollOnce(ctx); err != nil {
			// УРОК: не паниковать при сбое сети — пауза и повтор (не crash-loop).
			log.Printf("bot: poll: %v", err)
			select {
			case <-b.stopCh:
				return
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// --- Telegram API ---

func (b *Bot) api(ctx context.Context, method string, params url.Values) (json.RawMessage, error) {
	u := fmt.Sprintf("https://api.telegram.org/bot%s/%s", b.token, method)
	req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.tr.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Desc   string          `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	if !r.OK {
		return nil, fmt.Errorf("telegram %s: %s", method, r.Desc)
	}
	return r.Result, nil
}

func (b *Bot) pollOnce(ctx context.Context) error {
	params := url.Values{}
	params.Set("offset", strconv.FormatInt(b.offset+1, 10))
	params.Set("timeout", "25")
	params.Set("allowed_updates", `["message","callback_query"]`)
	res, err := b.api(ctx, "getUpdates", params)
	if err != nil {
		return err
	}
	var updates []struct {
		UpdateID int64 `json:"update_id"`
		Message  *struct {
			Chat struct{ ID int64 `json:"id"` } `json:"chat"`
			Text string `json:"text"`
		} `json:"message"`
		CallbackQuery *struct {
			ID   string `json:"id"`
			From struct{ ID int64 `json:"id"` } `json:"from"`
			Message struct {
				Chat struct{ ID int64 `json:"id"` } `json:"chat"`
			} `json:"message"`
			Data string `json:"data"`
		} `json:"callback_query"`
	}
	if err := json.Unmarshal(res, &updates); err != nil {
		return err
	}
	for _, up := range updates {
		if up.UpdateID > b.offset {
			b.offset = up.UpdateID
		}
		if up.CallbackQuery != nil {
			b.handleCallback(ctx, up.CallbackQuery.ID, up.CallbackQuery.From.ID, up.CallbackQuery.Message.Chat.ID, up.CallbackQuery.Data)
		} else if up.Message != nil {
			b.handleMessage(ctx, up.Message.Chat.ID, up.Message.Text)
		}
	}
	return nil
}

// sendMessage — одно сообщение (HTML parse_mode). УРОК: подписка = ОДНО сообщение.
func (b *Bot) sendMessage(ctx context.Context, chat int64, text string, kb string) {
	params := url.Values{}
	params.Set("chat_id", strconv.FormatInt(chat, 10))
	params.Set("text", text)
	params.Set("parse_mode", "HTML")
	params.Set("disable_web_page_preview", "true")
	if kb != "" {
		params.Set("reply_markup", kb)
	}
	if _, err := b.api(ctx, "sendMessage", params); err != nil {
		log.Printf("bot: sendMessage %d: %v", chat, err)
	}
}

// SendText — публичная отправка текста произвольному chat (уведомления клиентам, P0 #3).
// УРОК: ошибка возвращается (не глушится). HTML parse_mode.
func (b *Bot) SendText(ctx context.Context, chat int64, text string) error {
	if b.token == "" {
		return fmt.Errorf("бот не настроен")
	}
	params := url.Values{}
	params.Set("chat_id", strconv.FormatInt(chat, 10))
	params.Set("text", text)
	params.Set("parse_mode", "HTML")
	params.Set("disable_web_page_preview", "true")
	if _, err := b.api(ctx, "sendMessage", params); err != nil {
		return fmt.Errorf("sendMessage %d: %w", chat, err)
	}
	return nil
}

func (b *Bot) answerCallback(ctx context.Context, cbID string) {
	params := url.Values{}
	params.Set("callback_query_id", cbID)
	b.api(ctx, "answerCallbackQuery", params)
}

// SendFile — отправка файла админу в Telegram (бэкапы). УРОК: ошибка возвращается.
func (b *Bot) SendFile(ctx context.Context, path string) error {
	if b.token == "" || b.adminID == 0 {
		return fmt.Errorf("бот не настроен")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("chat_id", strconv.FormatInt(b.adminID, 10))
	mw.WriteField("caption", "💾 Бэкап XKIT Panel "+time.Now().Format("02.01.2006 15:04"))
	fw, err := mw.CreateFormFile("document", filepath.Base(path))
	if err != nil {
		return err
	}
	if _, err := io.Copy(fw, f); err != nil {
		return err
	}
	mw.Close()
	u := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", b.token)
	req, err := http.NewRequestWithContext(ctx, "POST", u, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := b.tr.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var r struct {
		OK   bool   `json:"ok"`
		Desc string `json:"description"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	if !r.OK {
		return fmt.Errorf("telegram sendDocument: %s", r.Desc)
	}
	return nil
}

// --- клавиатуры ---

func kb(rows [][][2]string) string {
	type btn struct {
		Text string `json:"text"`
		Data string `json:"callback_data"`
	}
	var out [][]btn
	for _, row := range rows {
		var r []btn
		for _, c := range row {
			r = append(r, btn{Text: c[0], Data: c[1]})
		}
		out = append(out, r)
	}
	j, _ := json.Marshal(map[string]any{"inline_keyboard": out})
	return string(j)
}

func mainMenu() string {
	return kb([][][2]string{
		{{"👥 Пользователи", "m:users"}, {"🖥 Ноды", "m:nodes"}},
		{{"📊 Статус", "m:status"}, {"🔗 Подписки", "m:subs"}},
	})
}

// --- обработчики (УРОК: recover от panic, защитный парсинг) ---

func (b *Bot) handleCallback(ctx context.Context, cbID string, fromID, chat int64, data string) {
	b.answerCallback(ctx, cbID)
	// клиентские кнопки (cl:*) — для привязанных клиентов (P0 #4), не только админ.
	if strings.HasPrefix(data, "cl:") {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("bot: client callback panic recovered: %v", r)
			}
		}()
		if !b.isLinkedClient(chat) { return }
		rest := strings.TrimPrefix(data, "cl:")
		switch {
		case rest == "status": b.clientStatus(ctx, chat)
		case rest == "sub": b.clientSub(ctx, chat)
		case rest == "help": b.clientHelp(ctx, chat)
		case rest == "country": b.clientCountryMenu(ctx, chat)
		case rest == "menu": b.sendMessage(ctx, chat, "🏠 Меню подписки XKIT:", clientMenuKB())
		case strings.HasPrefix(rest, "cc:"): b.clientCountrySet(ctx, chat, strings.TrimPrefix(rest, "cc:"))
		}
		return
	}
	if fromID != b.adminID && chat != b.adminID {
		return // не админ — молча
	}
	// УРОК XKIT (crash-loop): recover чтобы одна плохая кнопка не роняла бот.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("bot: callback panic recovered (data=%q): %v", data, r)
			b.sendMessage(ctx, chat, "⚠️ Внутренняя ошибка кнопки. Попробуйте /menu.", mainMenu())
		}
	}()
	// защитный парсинг: prefix:rest
	prefix, rest := splitCallback(data)
	switch prefix {
	case "m":
		b.handleMenu(ctx, chat, rest)
	case "u":
		b.userCard(ctx, chat, rest)
	case "sub":
		b.userSubscription(ctx, chat, rest)
	case "au":
		b.handleAddUser(ctx, chat, rest)
	case "del":
		b.confirmDelete(ctx, chat, rest)
	case "yes":
		b.doDelete(ctx, chat, rest)
	case "no":
		b.sendMessage(ctx, chat, "Отменено.", mainMenu())
	default:
		b.sendMessage(ctx, chat, "Неизвестное действие. /menu", mainMenu())
	}
}

// splitCallback — защитный разбор callback_data (УРОК: не паниковать на малформ).
func splitCallback(data string) (prefix, rest string) {
	i := strings.Index(data, ":")
	if i < 0 {
		return data, ""
	}
	return data[:i], data[i+1:]
}

func (b *Bot) handleMenu(ctx context.Context, chat int64, action string) {
	switch action {
	case "main", "":
		b.sendMessage(ctx, chat, "🏠 Главное меню XKIT Panel:", mainMenu())
	case "users":
		b.usersList(ctx, chat)
	case "nodes":
		b.nodesList(ctx, chat)
	case "status":
		b.status(ctx, chat)
	case "subs":
		b.usersList(ctx, chat)
	default:
		b.sendMessage(ctx, chat, "🏠 Главное меню:", mainMenu())
	}
}

func (b *Bot) handleMessage(ctx context.Context, chat int64, text string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("bot: message panic recovered: %v", r)
		}
	}()
	text = strings.TrimSpace(text)
	// INVITE-LINK самопривязки (P0 #4): /start <claim-token> — НЕ только админ.
	// УРОК (panels-research 3x-ui Invite Link): админ шлёт ссылку t.me/<bot>?start=<token>,
	// первый открывший привязан к клиенту. Killer-UX: родственник сам смотрит трафик/срок/QR.
	if strings.HasPrefix(text, "/start ") {
		token := strings.TrimSpace(strings.TrimPrefix(text, "/start "))
		if token != "" {
			b.handleClaim(ctx, chat, token)
			return
		}
	}
	// привязанный клиент (не админ): клиентское меню (трафик/срок/подписка)
	if chat != b.adminID {
		if b.isLinkedClient(chat) {
			b.clientMenu(ctx, chat, text)
		}
		return // не привязан и не админ — игнор (защита от посторонних)
	}
	// УРОК: если идёт мастер создания (step=email) — текст = email, не команда.
	b.mu.Lock()
	st := b.states[chat]
	b.mu.Unlock()
	if st != nil && st.Step == "email" && !strings.HasPrefix(text, "/") {
		b.addUserEmail(ctx, chat, text)
		return
	}
	switch {
	case text == "/start" || text == "/menu" || text == "/help":
		b.sendMessage(ctx, chat, "🏠 Главное меню XKIT Panel:", mainMenu())
	case text == "/status":
		b.status(ctx, chat)
	case text == "/users":
		b.usersList(ctx, chat)
	case text == "/adduser":
		b.addUserStart(ctx, chat)
	default:
		b.sendMessage(ctx, chat, "🏠 Главное меню XKIT Panel:", mainMenu())
	}
}