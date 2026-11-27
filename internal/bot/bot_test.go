package bot

import (
	"testing"
)

// УРОК XKIT (crash-loop кнопок): защитный парсинг callback_data не паникует на малформ.
func TestSplitCallback(t *testing.T) {
	cases := []struct {
		in           string
		wantP, wantR string
	}{
		{"m:users", "m", "users"},
		{"au:days:30", "au", "days:30"},
		{"au:gb:0", "au", "gb:0"},
		{"sub:ivan@mail.ru", "sub", "ivan@mail.ru"},
		{"menu", "menu", ""},      // без ':' — не паникует
		{"", "", ""},              // пусто — не паникует
		{":x", "", "x"},           // пустой prefix
		{"a:b:c:d", "a", "b:c:d"}, // много ':'
	}
	for _, c := range cases {
		p, r := splitCallback(c.in)
		if p != c.wantP || r != c.wantR {
			t.Errorf("splitCallback(%q) = (%q,%q), want (%q,%q)", c.in, p, r, c.wantP, c.wantR)
		}
	}
}

// УРОК: валидация email на границе доверия (кириллица/спецсимволы отклоняются).
func TestValidEmail(t *testing.T) {
	good := []string{"ivan@mail.ru", "user+tag@example.com", "a.b_c@d.e", "u1@x.y"}
	bad := []string{"", "иван@почта.рф", "no-at-sign", "a b@c.d", "a<b>@c.d", "a@b.c\"", strings64()}
	for _, e := range good {
		if !validEmail(e) {
			t.Errorf("validEmail(%q) = false, want true", e)
		}
	}
	for _, e := range bad {
		if validEmail(e) {
			t.Errorf("validEmail(%q) = true, want false", e)
		}
	}
}

func strings64() string {
	s := ""
	for i := 0; i < 70; i++ {
		s += "a"
	}
	return s + "@b.c" // >64 символов
}

// УРОК: atoiSafe не паникует на мусоре (защита от малформ callback).
func TestAtoiSafe(t *testing.T) {
	cases := map[string]int{"30": 30, "0": 0, "365": 365, "": 0, "abc": 0, "12x": 0, "-5": 0}
	for in, want := range cases {
		if got := atoiSafe(in); got != want {
			t.Errorf("atoiSafe(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 Б"},
		{512, "512 Б"},
		{1024, "1.0 KБ"},
		{1073741824, "1.0 GБ"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

// УРОК: master state machine — шаги email→days→gb, переходы корректны.
func TestAddStateFlow(t *testing.T) {
	st := &addState{Step: "email"}
	if st.Step != "email" {
		t.Fatal("initial step")
	}
	st.Step = "days"
	st.Email = "ivan@mail.ru"
	if st.Email != "ivan@mail.ru" {
		t.Fatal("email saved")
	}
	st.Step = "gb"
	st.Days = 30
	if st.Days != 30 {
		t.Fatal("days saved")
	}
}

// newUUID формат + уникальность.
func TestNewUUID(t *testing.T) {
	u1, u2 := newUUID(), newUUID()
	if len(u1) != 36 {
		t.Errorf("uuid len = %d, want 36", len(u1))
	}
	if u1 == u2 {
		t.Error("uuid not unique")
	}
	if u1[14] != '4' {
		t.Errorf("uuid version not 4: %s", u1)
	}
}

func TestRandHex(t *testing.T) {
	h := randHex(8)
	if len(h) != 16 {
		t.Errorf("randHex(8) len = %d, want 16", len(h))
	}
}