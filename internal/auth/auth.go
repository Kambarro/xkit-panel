// Package auth — логин/пароль XKIT Panel (argon2id + сессии cookie).
// Админ в SQLite admins. Сессия — случайный токен в HttpOnly cookie, хранится в памяти/БД.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
	"golang.org/x/crypto/argon2"
)

const (
	sessionCookie = "xkit_session"
	sessionTTL    = 24 * time.Hour
)

type session struct {
	username string
	expires  time.Time
}

type Auth struct {
	store    *store.Store
	mu       sync.RWMutex
	sessions map[string]session
}

func New(s *store.Store) *Auth {
	return &Auth{store: s, sessions: make(map[string]session)}
}

// HashPassword — argon2id hash (параметры OWASP: t=1, m=64MB, p=4, key=32).
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=1,p=4$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(key)), nil
}

// VerifyPassword проверяет пароль против argon2id hash.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := hex.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// EnsureAdmin создаёт админа если нет (первый запуск). Возвращает сгенерированный пароль если создан.
// УРОК (владелец): пароль одноразовый (must_change=1) — первый вход блокирует до смены.
func (a *Auth) EnsureAdmin(username, password string) (created bool, err error) {
	var cnt int
	a.store.DB().QueryRow(`SELECT COUNT(*) FROM admins WHERE username=?`, username).Scan(&cnt)
	if cnt > 0 {
		return false, nil
	}
	hash, err := HashPassword(password)
	if err != nil {
		return false, err
	}
	_, err = a.store.DB().Exec(`INSERT INTO admins(username,pass_hash,must_change) VALUES(?,?,1)`, username, hash)
	return err == nil, err
}

// MustChange — пароль одноразовый (первый вход / после SSH-сброса)?
func (a *Auth) MustChange(username string) bool {
	var mc int
	a.store.DB().QueryRow(`SELECT must_change FROM admins WHERE username=?`, username).Scan(&mc)
	return mc == 1
}

// ResetPassword — SSH-сброс: новый одноразовый пароль + must_change=1 + все сессии убить.
// Вызывается CLI-командой reset-password на сервере (аварийный доступ без старого пароля).
func (a *Auth) ResetPassword(username, newPassword string) error {
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	res, err := a.store.DB().Exec(`UPDATE admins SET pass_hash=?, must_change=1 WHERE username=?`, hash, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("пользователь %s не найден", username)
	}
	// убить все сессии (старый доступ отозван)
	a.mu.Lock()
	a.sessions = make(map[string]session)
	a.mu.Unlock()
	return nil
}

// AdminUsername — имя единственного админа (для CLI reset без знания логина).
func (a *Auth) AdminUsername() string {
	var u string
	a.store.DB().QueryRow(`SELECT username FROM admins LIMIT 1`).Scan(&u)
	return u
}

// AdminExists — существует ли оператор (для защиты от повторного создания при старте).
func (a *Auth) AdminExists(username string) bool {
	var cnt int
	a.store.DB().QueryRow(`SELECT COUNT(*) FROM admins WHERE username=?`, username).Scan(&cnt)
	return cnt > 0
}

// Login проверяет креды, создаёт сессию, ставит cookie.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request, username, password string) bool {
	var hash string
	err := a.store.DB().QueryRow(`SELECT pass_hash FROM admins WHERE username=?`, username).Scan(&hash)
	if err != nil || !VerifyPassword(password, hash) {
		return false
	}
	tok := make([]byte, 32)
	rand.Read(tok)
	token := hex.EncodeToString(tok)
	a.mu.Lock()
	a.sessions[token] = session{username: username, expires: time.Now().Add(sessionTTL)}
	a.mu.Unlock()
	// УРОК (QA): сессия в БД — переживает рестарт панели (деплой не выкидывает админа).
	a.store.DB().Exec(`INSERT OR REPLACE INTO sessions(token,username,expires) VALUES(?,?,?)`,
		token, username, time.Now().Add(sessionTTL).Unix())
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds()),
	})
	return true
}

// Logout удаляет сессию.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
		a.store.DB().Exec(`DELETE FROM sessions WHERE token=?`, c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
}

// User возвращает username активной сессии или "".
func (a *Auth) User(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	a.mu.RLock()
	s, ok := a.sessions[c.Value]
	a.mu.RUnlock()
	if !ok {
		// fallback в БД (после рестарта панели память пуста)
		var username string
		var exp int64
		if err := a.store.DB().QueryRow(`SELECT username,expires FROM sessions WHERE token=?`, c.Value).Scan(&username, &exp); err == nil {
			s = session{username: username, expires: time.Unix(exp, 0)}
			ok = true
			a.mu.Lock()
			a.sessions[c.Value] = s
			a.mu.Unlock()
		}
	}
	if !ok || time.Now().After(s.expires) {
		return ""
	}
	return s.username
}

// Require middleware: если не залогинен — редирект на login (для UI) или 401 (для API).
// УРОК (владелец): must_change=1 (одноразовый пароль) — БЛОКИРУЮЩИЙ шаг: пускаем
// только на смену пароля (/setup-password, /api/password) и logout, остальное закрыто.
func (a *Auth) Require(loginPath string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := a.User(r)
		if user == "" {
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.Contains(r.URL.Path, "/api/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"unauthorized"}`)
				return
			}
			http.Redirect(w, r, loginPath, http.StatusFound)
			return
		}
		if a.MustChange(user) {
			p := r.URL.Path
			allowed := strings.HasSuffix(p, "/setup-password") || strings.HasSuffix(p, "/api/password") || strings.HasSuffix(p, "/logout")
			if !allowed {
				if strings.Contains(p, "/api/") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprint(w, `{"error":"password_change_required"}`)
					return
				}
				// prefix из loginPath: /<secret>/login → /<secret>
				prefix := strings.TrimSuffix(loginPath, "/login")
				http.Redirect(w, r, prefix+"/setup-password", http.StatusFound)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ChangePassword меняет пароль админа (после первого входа).
// Снимает must_change (одноразовый пароль стал постоянным).
func (a *Auth) ChangePassword(username, newPassword string) error {
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	_, err = a.store.DB().Exec(`UPDATE admins SET pass_hash=?, must_change=0 WHERE username=?`, hash, username)
	return err
}
