package bot

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// INVITE-LINK самопривязки клиента к TG-боту (P0 #4, panels-research 3x-ui Invite Link).
// УРОК: админ генерит claim-token для клиента → ссылка t.me/<bot>?start=<token>.
// Первый открывший привязан (tg_chat_id). Лимит попыток — токен одноразовый (после привязки гаснет).
// Killer-UX для не-технаря: родственник сам смотрит трафик/срок/QR без админа.

// GenerateClaimToken — создаёт одноразовый токен привязки для клиента (админ/API).
func GenerateClaimToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// handleClaim — /start <token>: привязать chat к клиенту по токену.
func (b *Bot) handleClaim(ctx context.Context, chat int64, token string) {
	// найдём клиента с этим токеном (и ещё не привязанного)
	var email, name string
	err := b.store.DB().QueryRow(`SELECT email,name FROM clients WHERE tg_claim_token=? AND enabled=1`, token).Scan(&email, &name)
	if err != nil {
		b.sendMessage(ctx, chat, "❌ Ссылка недействительна или уже использована. Попросите администратора выслать новую.", "")
		return
	}
	// уже привязан другой chat? (защита: токен одноразовый)
	var existingChat int64
	b.store.DB().QueryRow(`SELECT tg_chat_id FROM clients WHERE email=?`, email).Scan(&existingChat)
	if existingChat != 0 && existingChat != chat {
		b.sendMessage(ctx, chat, "❌ Эта подписка уже привязана к другому Telegram. Попросите администратора отвязать.", "")
		return
	}
	// привязываем + гасим токен (одноразовый)
	_, err = b.store.DB().Exec(`UPDATE clients SET tg_chat_id=?, tg_claim_token='', updated_at=strftime('%s','now') WHERE email=?`, chat, email)
	if err != nil {
		b.sendMessage(ctx, chat, "⚠️ Ошибка привязки. Попробуйте позже.", "")
		return
	}
	b.store.AddEvent("tg_claim", "ok", fmt.Sprintf("клиент %s привязал Telegram", email), "{}")
	if name == "" { name = email }
	b.sendMessage(ctx, chat, fmt.Sprintf("✅ <b>%s</b>, вы привязаны к подписке XKIT!\n\nТеперь вы можете смотреть трафик, срок и получать ссылку подключения прямо здесь.", name), clientMenuKB())
}

// isLinkedClient — привязан ли chat к клиенту.
func (b *Bot) isLinkedClient(chat int64) bool {
	var n int
	b.store.DB().QueryRow(`SELECT COUNT(*) FROM clients WHERE tg_chat_id=? AND enabled=1`, chat).Scan(&n)
	return n > 0
}

// clientByChat — email/name/sub_id клиента по chat.
func (b *Bot) clientByChat(chat int64) (email, name, subID string, ok bool) {
	err := b.store.DB().QueryRow(`SELECT email,name,sub_id FROM clients WHERE tg_chat_id=? AND enabled=1 LIMIT 1`, chat).Scan(&email, &name, &subID)
	return email, name, subID, err == nil
}

// clientMenuKB — клиентское меню (трафик/срок/подписка/страна).
func clientMenuKB() string {
	return `{"inline_keyboard":[[{"text":"📊 Трафик и срок","callback_data":"cl:status"},{"text":"🔗 Подписка","callback_data":"cl:sub"}],[{"text":"🌍 Страна","callback_data":"cl:country"},{"text":"📲 Как подключиться","callback_data":"cl:help"}]]}`
}

// clientMenu — обработка сообщений привязанного клиента.
func (b *Bot) clientMenu(ctx context.Context, chat int64, text string) {
	switch {
	case text == "/start" || text == "/menu" || text == "/help":
		b.sendMessage(ctx, chat, "🏠 Меню подписки XKIT:", clientMenuKB())
	case text == "/status":
		b.clientStatus(ctx, chat)
	case text == "/sub":
		b.clientSub(ctx, chat)
	default:
		b.sendMessage(ctx, chat, "🏠 Меню подписки XKIT:", clientMenuKB())
	}
}

// clientStatus — трафик/срок клиента (одно сообщение, HTML).
func (b *Bot) clientStatus(ctx context.Context, chat int64) {
	email, name, _, ok := b.clientByChat(chat)
	if !ok { b.sendMessage(ctx, chat, "Подписка не найдена.", ""); return }
	var quota, used, expiry int64
	b.store.DB().QueryRow(`SELECT quota_bytes,used_bytes,expiry FROM clients WHERE email=?`, email).Scan(&quota, &used, &expiry)
	if name == "" { name = email }
	quotaStr := "безлимит"
	if quota > 0 { quotaStr = humanBytesBot(quota) }
	expiryStr := "бессрочно"
	if expiry > 0 {
		days := int((expiry - nowUnix()) / 86400)
		if days > 0 { expiryStr = fmt.Sprintf("осталось %d дн.", days) } else { expiryStr = "истёк" }
	}
	msg := fmt.Sprintf("📊 <b>%s</b>\n\nТрафик: %s / %s\nСрок: %s", name, humanBytesBot(used), quotaStr, expiryStr)
	b.sendMessage(ctx, chat, msg, clientMenuKB())
}

// clientSub — ссылка подписки клиента (одно сообщение с <pre> для копирования).
func (b *Bot) clientSub(ctx context.Context, chat int64) {
	_, name, subID, ok := b.clientByChat(chat)
	if !ok { b.sendMessage(ctx, chat, "Подписка не найдена.", ""); return }
	if name == "" { name = "клиент" }
	subURL := fmt.Sprintf("https://%s/%s/%s", b.domain, b.store.SubPrefix(), subID)
	msg := fmt.Sprintf("🔗 <b>%s</b>, ваша подписка:\n\nПодписка (все протоколы): <tg-spoiler>%s</tg-spoiler>\n\nНажмите на ссылку → скопируйте → вставьте в приложение (v2rayNG/Hiddify/Streisand). Или откройте в браузере — там QR.", name, subURL)
	b.sendMessage(ctx, chat, msg, clientMenuKB())
}

// clientHelpCallback — инструкция подключения (callback cl:help).
func (b *Bot) clientHelp(ctx context.Context, chat int64) {
	msg := "📲 <b>Как подключиться:</b>\n\n1. Установите приложение: v2rayNG (Android), Streisand/Hiddify (iOS), v2rayN (Windows).\n2. Нажмите «🔗 Подписка» — скопируйте ссылку.\n3. В приложении: импорт из буфера / добавить подписку.\n4. Включите соединение.\n\nИли откройте ссылку подписки в браузере — там QR-код для сканирования."
	b.sendMessage(ctx, chat, msg, clientMenuKB())
}

func humanBytesBot(n int64) string {
	if n <= 0 { return "0 B" }
	const unit = 1024
	if n < unit { return fmt.Sprintf("%d B", n) }
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit { div *= unit; exp++ }
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func nowUnix() int64 { return time.Now().Unix() }