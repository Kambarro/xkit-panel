package api

// camo.go — управление сайтом-прикрытием (камуфляж).
// Пользовательский сайт (/var/www/camo-custom/) НЕ сбрасывается при обновлении панели.
// Дефолтный шаблон (/var/www/camo/) — fallback. nginx смотрит custom → default.

import (
	"encoding/json"
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	camoCustomDir  = "/var/www/camo-custom"
	camoDefaultDir = "/var/www/camo"
)

// GET /api/camo — статус текущего сайта.
func (s *Server) camoStatus(w http.ResponseWriter, r *http.Request) {
	dir := camoDefaultDir
	custom := false
	if _, err := os.Stat(filepath.Join(camoCustomDir, "index.html")); err == nil {
		dir = camoCustomDir
		custom = true
	}
	var files int
	var size int64
	filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			files++
			size += info.Size()
		}
		return nil
	})
	writeJSON(w, map[string]any{
		"custom": custom, "files": files, "size_kb": size / 1024,
		"domain": s.domain,
	})
}

// POST /api/camo/upload — загрузка ZIP со статическим сайтом.
func (s *Server) camoUpload(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20) // 10 MB
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "файл не получен", 400)
		return
	}
	defer file.Close()
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".zip") {
		http.Error(w, "нужен ZIP-архив", 400)
		return
	}
	// сохраняю во временный файл
	tmp, err := os.CreateTemp("", "camo-*.zip")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, file); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tmp.Close()
	// валидация ZIP: index.html обязателен, без php/cgi, размер
	zr, err := zip.OpenReader(tmp.Name())
	if err != nil {
		http.Error(w, "невалидный ZIP: "+err.Error(), 400)
		return
	}
	defer zr.Close()
	hasIndex := false
	var totalSize int64
	for _, f := range zr.File {
		name := strings.ToLower(f.Name)
		if strings.Contains(name, "..") {
			http.Error(w, "недопустимый путь в архиве", 400)
			return
		}
		ext := filepath.Ext(name)
		if ext == ".php" || ext == ".py" || ext == ".cgi" || ext == ".sh" || ext == ".exe" {
			http.Error(w, "серверные скрипты запрещены: "+f.Name, 400)
			return
		}
		if name == "index.html" || strings.HasSuffix(name, "/index.html") {
			hasIndex = true
		}
		totalSize += int64(f.UncompressedSize64)
	}
	if !hasIndex {
		http.Error(w, "index.html не найден в архиве", 400)
		return
	}
	if totalSize > 10<<20 {
		http.Error(w, "распакованный размер > 10 МБ", 400)
		return
	}
	// распаковка в camo-custom (очищаю старую)
	os.RemoveAll(camoCustomDir)
	os.MkdirAll(camoCustomDir, 0755)
	for _, f := range zr.File {
		target := filepath.Join(camoCustomDir, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(target), 0755)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		out, err := os.Create(target)
		if err != nil {
			rc.Close()
			continue
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}
	// nginx: обновлю root на camo-custom (если есть index.html)
	s.syncCamoNginx()
	s.store.AddEvent("camo", "ok", fmt.Sprintf("пользовательский сайт загружен (%s, %d файлов)", header.Filename, len(zr.File)), "{}")
	writeJSON(w, map[string]any{"ok": true, "files": len(zr.File)})
}

// syncCamoNginx — nginx root: custom если есть, иначе default.
func (s *Server) syncCamoNginx() {
	root := camoDefaultDir
	if _, err := os.Stat(filepath.Join(camoCustomDir, "index.html")); err == nil {
		root = camoCustomDir
	}
	confPath := "/etc/nginx/conf.d/xkit-panel.conf"
	out, err := exec.Command("cat", confPath).Output()
	if err != nil {
		return
	}
	conf := string(out)
	// заменяю root в camo location (location / { root ... })
	lines := strings.Split(conf, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "root /var/www/camo") {
			lines[i] = strings.Replace(line, "/var/www/camo-custom", root, 1)
			lines[i] = strings.Replace(lines[i], "/var/www/camo", root, 1)
		}
	}
	conf = strings.Join(lines, "\n")
	exec.Command("bash", "-c", fmt.Sprintf("cat > %s << 'XEOF'\n%s\nXEOF", confPath, conf)).Run()
	exec.Command("nginx", "-t").Run()
	exec.Command("systemctl", "reload", "nginx").Run()
}
// POST /api/camo/generate — генерация нового camo-сайта через sitegen.
func (s *Server) camoGenerate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Seed string `json:"seed"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	seed := body.Seed
	if seed == "" {
		seed = randHex(32)
	}
	// вызов sitegen.py
	cmd := exec.Command("python3", "/usr/local/lib/xkit-panel/camo_sitegen.py", "--seed", seed, "--out", camoDefaultDir, "--domain", s.domain)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "sitegen: "+string(out), 500)
		return
	}
	s.store.SetSetting("camo_seed", seed)
	s.store.AddEvent("camo", "ok", "Сгенерирован новый сайт-прикрытие (seed "+seed[:8]+"…)", "{}")
	writeJSON(w, map[string]any{"ok": true, "seed": seed})
}
