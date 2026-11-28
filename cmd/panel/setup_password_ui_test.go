package main

import (
	"strings"
	"testing"
)

func TestSetupPasswordIdentifiesAdminForPasswordManager(t *testing.T) {
	data, err := webFS.ReadFile("web/setup-password.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	// Без поля username менеджер паролей просит «выберите логин для обновления».
	if !strings.Contains(html, `name="username"`) {
		t.Error("на странице смены пароля нет скрытого поля username")
	}
	if !strings.Contains(html, `autocomplete="username"`) {
		t.Error("поле username не помечено autocomplete для менеджера паролей")
	}
	if !strings.Contains(html, `value="{{.AdminLogin}}"`) {
		t.Error("в username не подставляется единственный логин админа")
	}
}

func TestSetupPasswordVisibilityAndMatch(t *testing.T) {
	data, err := webFS.ReadFile("web/setup-password.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	if !strings.Contains(html, `togglePass('p1'`) || !strings.Contains(html, `togglePass('p2'`) {
		t.Error("нет «глазика» показа пароля для обоих полей")
	}
	if !strings.Contains(html, `id="match"`) {
		t.Error("нет живого индикатора совпадения паролей")
	}
	if !strings.Contains(html, `function togglePass`) {
		t.Error("нет функции переключения видимости пароля")
	}
}

func TestLoginPasswordHasVisibilityToggle(t *testing.T) {
	data, err := webFS.ReadFile("web/login.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	if !strings.Contains(html, `id="password"`) || !strings.Contains(html, `togglePass(this)`) {
		t.Error("на странице входа нет «глазика» показа пароля")
	}
}
