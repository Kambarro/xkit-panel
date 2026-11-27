package bot

import (
	"context"
	"strings"
	"testing"

	"github.com/kambarro/xkit-panel/internal/store"
)

// TestClientCountryButton — 🌍 Страна в клиентском меню: cl:country показывает
// текущую страну + живые страны/any; cl:cc:<C> меняет clients.country (единая
// store-точка: rate-limit/валидация/аудит) + горячий колбэк; невалидная страна
// отклоняется; повторная смена сразу → rate-limit.
func TestClientCountryButton(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.DB().Exec(`INSERT INTO country_codes(country,code) VALUES('NL',1),('US',3)`)
	for _, n := range []store.Node{
		{ID: "node-nl-1", Name: "NL", Country: "NL", CountryCode: 1, Host: "nl.test", Health: "alive", Enabled: true},
		{ID: "node-us-1", Name: "US", Country: "US", CountryCode: 3, Host: "us.test", Health: "alive", Enabled: true},
	} {
		if err := st.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UpsertClient(store.Client{Email: "c@test.ru", UUID: "u", SubID: "s1", Country: "NL", CountryCode: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.DB().Exec(`UPDATE clients SET tg_chat_id=555 WHERE email='c@test.ru'`)
	b := New("faketoken", 999, st, "vpn.example.com") // sendMessage залогирует сетевую ошибку — БД-логика проверяется напрямую
	var hotEmail, hotCountry string
	b.SetCountryChange(func(ctx context.Context, email, country string) error {
		hotEmail, hotCountry = email, country
		return nil
	})

	// меню содержит кнопку Страна
	if !strings.Contains(clientMenuKB(), "cl:country") || !strings.Contains(clientMenuKB(), "🌍") {
		t.Fatal("кнопка 🌍 Страна отсутствует в клиентском меню")
	}

	// выбор US: clients.country=US + горячий колбэк с той же страной
	b.clientCountrySet(context.Background(), 555, "US")
	var country string
	var code uint32
	st.DB().QueryRow(`SELECT country,country_code FROM clients WHERE email='c@test.ru'`).Scan(&country, &code)
	if country != "US" || code != 3 {
		t.Fatalf("после кнопки: %s/%d, want US/3", country, code)
	}
	if hotEmail != "c@test.ru" || hotCountry != "US" {
		t.Fatalf("горячий колбэк: %s/%s, want c@test.ru/US", hotEmail, hotCountry)
	}
	var events int
	st.DB().QueryRow(`SELECT COUNT(*) FROM events WHERE kind='country_change'`).Scan(&events)
	if events != 1 {
		t.Fatalf("аудит: %d, want 1", events)
	}

	// повторная смена сразу → rate-limit: БД не меняется, колбэк не зовётся
	hotEmail, hotCountry = "", ""
	b.clientCountrySet(context.Background(), 555, "NL")
	st.DB().QueryRow(`SELECT country FROM clients WHERE email='c@test.ru'`).Scan(&country)
	if country != "US" {
		t.Fatalf("rate-limit не сработал: %s", country)
	}
	if hotEmail != "" {
		t.Fatal("горячий колбэк вызван при rate-limit")
	}

	// невалидная страна → отклонена (обнулим таймер чтобы проверить именно валидацию)
	st.DB().Exec(`UPDATE clients SET country_changed_at=0 WHERE email='c@test.ru'`)
	b.clientCountrySet(context.Background(), 555, "XX")
	st.DB().QueryRow(`SELECT country FROM clients WHERE email='c@test.ru'`).Scan(&country)
	if country != "US" {
		t.Fatalf("невалидная страна принята: %s", country)
	}

	// any нормализуется
	b.clientCountrySet(context.Background(), 555, "any")
	st.DB().QueryRow(`SELECT country FROM clients WHERE email='c@test.ru'`).Scan(&country)
	if country != "any" {
		t.Fatalf("any: %s", country)
	}

	// непривязанный chat — молча (никаких записей)
	b.clientCountrySet(context.Background(), 777, "US")
	st.DB().QueryRow(`SELECT country FROM clients WHERE email='c@test.ru'`).Scan(&country)
	if country != "any" {
		t.Fatal("непривязанный chat смог сменить страну")
	}
}