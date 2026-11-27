package bot

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

func esc(s string) string { return html.EscapeString(s) }

// --- статус / списки ---

func (b *Bot) status(ctx context.Context, chat int64) {
	var clients, nodes, alive int
	b.store.DB().QueryRow(`SELECT COUNT(*) FROM clients WHERE enabled=1`).Scan(&clients)
	b.store.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE enabled=1`).Scan(&nodes)
	b.store.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE enabled=1 AND health='alive'`).Scan(&alive)
	msg := fmt.Sprintf("📊 <b>Статус XKIT Panel</b>\n\n👥 Клиентов: %d\n🖥 Нод: %d (живых: %d)\n🌐 Мастер: %s", clients, nodes, alive, esc(b.domain))
	b.sendMessage(ctx, chat, msg, mainMenu())
}

func (b *Bot) usersList(ctx context.Context, chat int64) {
	clients, err := b.store.EnabledClients()
	if err != nil || len(clients) == 0 {
		b.sendMessage(ctx, chat, "Пользователей нет. Создайте первого:", kb([][][2]string{
			{{"➕ Создать пользователя", "au:start"}},
			{{"🏠 Меню", "m:main"}},
		}))
		return
	}
	var rows [][][2]string
	for _, cl := range clients {
		rows = append(rows, [][2]string{{"👤 " + cl.Email, "u:" + cl.Email}})
	}
	rows = append(rows, [][2]string{{"➕ Создать", "au:start"}})
	rows = append(rows, [][2]string{{"🏠 Меню", "m:main"}})
	b.sendMessage(ctx, chat, "👥 <b>Пользователи</b> (нажмите для карточки):", kb(rows))
}

func (b *Bot) nodesList(ctx context.Context, chat int64) {
	rows, err := b.store.DB().Query(`SELECT name,country,host,health FROM nodes WHERE enabled=1 ORDER BY country,priority`)
	if err != nil {
		b.sendMessage(ctx, chat, "Ошибка чтения нод: "+esc(err.Error()), mainMenu())
		return
	}
	defer rows.Close()
	var sb strings.Builder
	sb.WriteString("🖥 <b>Ноды</b>\n\n")
	n := 0
	for rows.Next() {
		var name, country, host, health string
		rows.Scan(&name, &country, &host, &health)
		icon := "🟢"
		if health == "down" {
			icon = "🔴"
		} else if health != "alive" {
			icon = "🟡"
		}
		sb.WriteString(fmt.Sprintf("%s %s [%s] %s\n", icon, esc(name), esc(country), esc(host)))
		n++
	}
	if n == 0 {
		sb.WriteString("Нод нет. Добавьте в веб-панели.")
	}
	b.sendMessage(ctx, chat, sb.String(), mainMenu())
}

func (b *Bot) userCard(ctx context.Context, chat int64, email string) {
	cl, err := b.store.GetClient(email)
	if err != nil || cl == nil {
		b.sendMessage(ctx, chat, "Пользователь не найден.", mainMenu())
		return
	}
	status := "🟢 активен"
	if !cl.Enabled {
		status = "🔴 отключён"
	}
	used := humanBytes(cl.UsedBytes)
	quota := "безлимит"
	if cl.QuotaBytes > 0 {
		quota = humanBytes(cl.QuotaBytes)
	}
	expiry := "бессрочно"
	if cl.Expiry > 0 {
		expiry = time.Unix(cl.Expiry, 0).Format("02.01.2006")
	}
	msg := fmt.Sprintf("👤 <b>%s</b>\n\nСтатус: %s\nТрафик: %s / %s\nСрок: %s\nСтрана: %s",
		esc(cl.Email), status, used, quota, expiry, esc(cl.Country))
	b.sendMessage(ctx, chat, msg, kb([][][2]string{
		{{"🔗 Подписка", "sub:" + cl.Email}},
		{{"🗑 Удалить", "del:" + cl.Email}},
		{{"🏠 Меню", "m:main"}},
	}))
}

// userSubscription — УРОК XKIT: ОДНО HTML-сообщение, ссылки в <pre> блоках
// (Telegram даёт кнопку «копировать» на каждый блок — чистый URL, не куча сообщений).
func (b *Bot) userSubscription(ctx context.Context, chat int64, email string) {
	cl, err := b.store.GetClient(email)
	if err != nil || cl == nil {
		b.sendMessage(ctx, chat, "Пользователь не найден.", mainMenu())
		return
	}
	subURL := fmt.Sprintf("https://%s/%s/%s", b.domain, b.store.SubPrefix(), cl.SubID)
	msg := fmt.Sprintf("🔗 <b>Подписка %s</b>\n\n📲 Импорт в приложение (v2rayNG/Streisand/Hiddify):\nПодписка (все протоколы): <tg-spoiler>%s</tg-spoiler>\n\n💡 Нажмите на ссылку → скопируйте → вставьте в приложение.",
		esc(cl.Email), esc(subURL))
	b.sendMessage(ctx, chat, msg, kb([][][2]string{
		{{"👤 Карточка", "u:" + cl.Email}},
		{{"🏠 Меню", "m:main"}},
	}))
}

// --- пошаговый мастер создания (УРОК: для не-технарей, без точных команд) ---

func (b *Bot) handleAddUser(ctx context.Context, chat int64, rest string) {
	// rest: start / email:<...> не используется (email текстом) / days:<n> / gb:<n> / cancel
	action, val := splitCallback(rest)
	switch action {
	case "start":
		b.addUserStart(ctx, chat)
	case "days":
		b.addUserDays(ctx, chat, val)
	case "gb":
		b.addUserGB(ctx, chat, val)
	case "cancel":
		b.mu.Lock()
		delete(b.states, chat)
		b.mu.Unlock()
		b.sendMessage(ctx, chat, "Создание отменено.", mainMenu())
	default:
		b.addUserStart(ctx, chat)
	}
}

func (b *Bot) addUserStart(ctx context.Context, chat int64) {
	b.mu.Lock()
	b.states[chat] = &addState{Step: "email"}
	b.mu.Unlock()
	b.sendMessage(ctx, chat, "👤 <b>Создание пользователя</b>\n\nШаг 1/3: введите имя (email), например <code>ivan@mail.ru</code>\n(только латиница, цифры и . _ @ + -)",
		kb([][][2]string{{{"❌ Отмена", "au:cancel"}}}))
}

func (b *Bot) addUserEmail(ctx context.Context, chat int64, text string) {
	email := strings.TrimSpace(text)
	if !validEmail(email) {
		b.sendMessage(ctx, chat, "⚠️ Имя содержит недопустимые символы. Только латиница, цифры и . _ @ + -\nВведите ещё раз (например ivan@mail.ru):",
			kb([][][2]string{{{"❌ Отмена", "au:cancel"}}}))
		return
	}
	b.mu.Lock()
	b.states[chat] = &addState{Step: "days", Email: email}
	b.mu.Unlock()
	b.sendMessage(ctx, chat, fmt.Sprintf("👤 <b>%s</b>\n\nШаг 2/3: срок действия:", esc(email)),
		kb([][][2]string{
			{{"30 дней", "au:days:30"}, {"90 дней", "au:days:90"}},
			{{"365 дней", "au:days:365"}, {"♾ Бессрочно", "au:days:0"}},
			{{"❌ Отмена", "au:cancel"}},
		}))
}

func (b *Bot) addUserDays(ctx context.Context, chat int64, val string) {
	b.mu.Lock()
	st := b.states[chat]
	b.mu.Unlock()
	if st == nil || st.Email == "" {
		b.addUserStart(ctx, chat)
		return
	}
	days := atoiSafe(val)
	b.mu.Lock()
	st.Step = "gb"
	st.Days = days
	b.mu.Unlock()
	dlabel := fmt.Sprintf("%d дней", days)
	if days == 0 {
		dlabel = "бессрочно"
	}
	b.sendMessage(ctx, chat, fmt.Sprintf("👤 <b>%s</b> · %s\n\nШаг 3/3: лимит трафика:", esc(st.Email), dlabel),
		kb([][][2]string{
			{{"50 ГБ", "au:gb:50"}, {"100 ГБ", "au:gb:100"}},
			{{"200 ГБ", "au:gb:200"}, {"♾ Безлимит", "au:gb:0"}},
			{{"❌ Отмена", "au:cancel"}},
		}))
}

func (b *Bot) addUserGB(ctx context.Context, chat int64, val string) {
	b.mu.Lock()
	st := b.states[chat]
	delete(b.states, chat)
	b.mu.Unlock()
	if st == nil || st.Email == "" {
		b.addUserStart(ctx, chat)
		return
	}
	gb := atoiSafe(val)
	b.sendMessage(ctx, chat, fmt.Sprintf("⏳ Создаю %s…", esc(st.Email)), "")
	// УРОК: ошибки НЕ глушим — показываем причину.
	if err := b.createClient(st.Email, st.Days, gb); err != nil {
		b.sendMessage(ctx, chat, fmt.Sprintf("⚠️ Не удалось создать %s.\nПричина: <pre>%s</pre>\nПопробуйте снова: 👥 Пользователи → Создать.", esc(st.Email), esc(err.Error())), mainMenu())
		return
	}
	dlabel := fmt.Sprintf("%d дней", st.Days)
	if st.Days == 0 {
		dlabel = "бессрочно"
	}
	glabel := fmt.Sprintf("%d ГБ", gb)
	if gb == 0 {
		glabel = "безлимит"
	}
	b.sendMessage(ctx, chat, fmt.Sprintf("✅ Пользователь <b>%s</b> создан.\nСрок: %s · Трафик: %s\nПодписка и QR — в карточке.", esc(st.Email), dlabel, glabel),
		kb([][][2]string{
			{{"🔗 Подписка", "sub:" + st.Email}},
			{{"🏠 Меню", "m:main"}},
		}))
}

// createClient — создаёт клиента в SQLite (UUID/subId/expiry/quota).
// УРОК: валидация на границе доверия, ошибка возвращается (не глотается).
func (b *Bot) createClient(email string, days, gb int) error {
	if !validEmail(email) {
		return fmt.Errorf("недопустимый email")
	}
	if existing, _ := b.store.GetClient(email); existing != nil {
		return fmt.Errorf("пользователь уже существует")
	}
	var expiry int64
	if days > 0 {
		expiry = time.Now().AddDate(0, 0, days).Unix()
	}
	var quota int64
	if gb > 0 {
		quota = int64(gb) * 1024 * 1024 * 1024
	}
	cl := store.Client{
		Email:      email,
		UUID:       newUUID(),
		SubID:      randHex(8),
		Name:       email,
		Expiry:     expiry,
		QuotaBytes: quota,
		Enabled:    true,
	}
	return b.store.UpsertClient(cl)
}

// --- удаление (confirm) ---

func (b *Bot) confirmDelete(ctx context.Context, chat int64, email string) {
	b.sendMessage(ctx, chat, fmt.Sprintf("🗑 Удалить пользователя <b>%s</b>? Это действие необратимо.", esc(email)),
		kb([][][2]string{
			{{"✅ Да, удалить", "yes:" + email}, {"❌ Нет", "no:" + email}},
		}))
}

func (b *Bot) doDelete(ctx context.Context, chat int64, email string) {
	if _, err := b.store.DB().Exec(`DELETE FROM clients WHERE email=?`, email); err != nil {
		b.sendMessage(ctx, chat, "⚠️ Ошибка удаления: "+esc(err.Error()), mainMenu())
		return
	}
	b.store.AddEvent("client_deleted", "warn", "клиент "+email+" удалён через бот", "{}")
	b.sendMessage(ctx, chat, fmt.Sprintf("🗑 Пользователь %s удалён.", esc(email)), mainMenu())
}

// --- helpers ---

func validEmail(s string) bool {
	if len(s) == 0 || len(s) > 64 || !strings.Contains(s, "@") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '_' || r == '@' || r == '+' || r == '-') {
			return false
		}
	}
	return true
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func humanBytes(n int64) string {
	if n <= 0 {
		return "0 Б"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d Б", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cБ", float64(n)/float64(div), "KMGTPE"[exp])
}

// newUUID — случайный UUID v4 (crypto/rand).
func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// randHex — случайная hex-строка (subId).
func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}