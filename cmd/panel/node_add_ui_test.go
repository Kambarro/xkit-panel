package main

import (
	"regexp"
	"strings"
	"testing"
)

func TestAddNodeButtonsWired(t *testing.T) {
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`<button\b[^>]*data-i18n="add_node"[^>]*>`)
	buttons := re.FindAllString(string(data), -1)
	if len(buttons) < 2 {
		t.Fatalf("ожидались кнопки добавления ноды на дашборде и вкладке, найдено %d", len(buttons))
	}
	for _, button := range buttons {
		if !strings.Contains(button, `onclick="openAddNode()"`) {
			t.Errorf("кнопка добавления ноды без openAddNode(): %s", button)
		}
	}
}

func TestAddNodeFormPassesOptionalName(t *testing.T) {
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	start := strings.Index(html, "function openAddNode()")
	end := strings.Index(html, "function genPassword")
	if start < 0 || end <= start {
		t.Fatal("не найден блок формы добавления ноды")
	}
	form := html[start:end]
	if !strings.Contains(form, `name="name"`) {
		t.Error("в простой форме нет поля имени ноды")
	}
	if !strings.Contains(form, `name:f.get('name')`) {
		t.Error("имя ноды не передаётся в POST /api/nodes/add")
	}
	if strings.Contains(form, `name="name" required`) {
		t.Error("имя должно быть необязательным: backend подставляет страну и host")
	}
}
