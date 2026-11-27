package bot

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kambarro/xkit-panel/internal/store"
)

// 🌍 Страна выхода — кнопка клиентского меню (решение владельца: страна =
// clients.country, один UUID; смена горячо перестраивает базовое per-user
// правило). Тот же rate-limit 1 смена/10сек и валидация, что у API подписки —
// единая точка store.ChangeClientCountry.

// SetCountryChange — горячее переназначение после смены страны (ctrl.PushAssignment
// из main.go). nil = только запись в БД (reeval дочинит на следующем тике).
func (b *Bot) SetCountryChange(fn func(ctx context.Context, email, country string) error) {
	b.countryChange = fn
}

// clientCountryMenu — текущая страна + список живых стран/any кнопками (cl:country).
func (b *Bot) clientCountryMenu(ctx context.Context, chat int64) {
	email, _, _, ok := b.clientByChat(chat)
	if !ok {
		b.sendMessage(ctx, chat, "Подписка не найдена.", "")
		return
	}
	var country string
	b.store.DB().QueryRow(`SELECT country FROM clients WHERE email=?`, email).Scan(&country)
	if country == "" || strings.EqualFold(country, "any") {
		country = "any"
	}
	// живые страны мастера (включённые ноды)
	rows, err := b.store.DB().Query(`SELECT DISTINCT country FROM nodes WHERE enabled=1 ORDER BY country`)
	if err != nil {
		b.sendMessage(ctx, chat, "⚠️ Не удалось получить список стран.", clientMenuKB())
		return
	}
	var countries []string
	for rows.Next() {
		var c string
		rows.Scan(&c)
		countries = append(countries, c)
	}
	rows.Close()
	if len(countries) == 0 {
		b.sendMessage(ctx, chat, "🌍 Страна выхода: <b>авто</b> (нод нет — выход с мастера).", clientMenuKB())
		return
	}
	var kbRows [][][2]string
	kbRows = append(kbRows, [][2]string{{labelCountry("any", country), "cl:cc:any"}})
	for i := 0; i < len(countries); i += 2 {
		row := [][2]string{{labelCountry(countries[i], country), "cl:cc:" + countries[i]}}
		if i+1 < len(countries) {
			row = append(row, [2]string{labelCountry(countries[i+1], country), "cl:cc:" + countries[i+1]})
		}
		kbRows = append(kbRows, row)
	}
	kbRows = append(kbRows, [][2]string{{"⬅️ Меню", "cl:menu"}})
	msg := fmt.Sprintf("🌍 Страна выхода: <b>%s</b>\n\nВыберите страну — соединение переключится автоматически (не чаще раза в 10 секунд). «Авто» = лучшая нода среди всех.", country)
	b.sendMessage(ctx, chat, msg, kb(kbRows))
}

func labelCountry(c, current string) string {
	label := c
	if c == "any" {
		label = "🌐 Авто (любая)"
	}
	if strings.EqualFold(c, current) {
		label = "✅ " + label
	}
	return label
}

// clientCountrySet — выбор страны кнопкой (cl:cc:<COUNTRY>): единая точка смены
// (валидация/rate-limit/аудит) + горячее переназначение + ответ клиенту.
func (b *Bot) clientCountrySet(ctx context.Context, chat int64, country string) {
	email, _, _, ok := b.clientByChat(chat)
	if !ok {
		b.sendMessage(ctx, chat, "Подписка не найдена.", "")
		return
	}
	country = strings.TrimSpace(country)
	if country == "" || strings.EqualFold(country, "any") {
		country = "any"
	}
	if _, err := b.store.ChangeClientCountry(email, country, 10, "bot"); err != nil {
		switch {
		case errors.Is(err, store.ErrCountryRateLimit):
			b.sendMessage(ctx, chat, "⏳ Страну можно менять не чаще раза в 10 секунд. Подождите немного.", "")
		case errors.Is(err, store.ErrCountryUnavailable):
			b.sendMessage(ctx, chat, "❌ Эта страна сейчас недоступна. Нажмите «🌍 Страна» — там список живых.", "")
		default:
			b.sendMessage(ctx, chat, "⚠️ Не удалось сменить страну. Попробуйте позже.", "")
		}
		return
	}
	// горячо: базовое per-user правило на лучшую ноду выбранной страны
	if b.countryChange != nil {
		if err := b.countryChange(ctx, email, country); err != nil {
			// страна записана — балансир дочинит на следующем reeval-тике
			b.store.AddEvent("country_change", "warn", fmt.Sprintf("%s → %s (бот): назначение не удалось: %v", email, country, err), "{}")
		}
	}
	b.sendMessage(ctx, chat, fmt.Sprintf("✅ Страна выхода: <b>%s</b>. Переподключите VPN, если приложение не переключилось само.", country), clientMenuKB())
}