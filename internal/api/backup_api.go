package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kambarro/xkit-panel/internal/backup"
)

// backupAPI — HTTP-обвязка бэкапов: настройки/создать/список/скачать.
// УРОК XKIT: настройки как в main (интервал/дни/минимум/TG), ошибки не глушим.

func (s *Server) SetBackupManager(m *backup.Manager, dir string) { s.backupMgr = m; s.backupDir = dir }

// backupStatus — GET /api/backup: настройки + список бэкапов.
func (s *Server) backupStatus(w http.ResponseWriter, r *http.Request) {
	if s.backupMgr == nil {
		http.Error(w, "backup manager not available", 503)
		return
	}
	st := s.backupMgr.Settings()
	writeJSON(w, map[string]any{
		"enabled": st.Enabled, "interval_h": st.IntervalH, "keep_days": st.KeepDays,
		"keep_min": st.KeepMin, "tg_send": st.TGSend, "last_backup": st.LastBackup,
		"backups": s.backupMgr.List(),
	})
}

// backupConfigure — POST /api/backup/settings: сохранить настройки.
func (s *Server) backupConfigure(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	allowed := map[string]bool{"backup_enabled": true, "backup_interval_h": true, "backup_keep_days": true, "backup_keep_min": true, "backup_tg_send": true}
	for k, v := range body {
		if !allowed[k] {
			continue
		}
		// числовые — валидация (урок: не ломать арифметику тикера мусором)
		if k != "backup_enabled" && k != "backup_tg_send" {
			if n, err := strconv.Atoi(v); err != nil || n < 0 {
				http.Error(w, k+" должно быть целым >= 0", 400)
				return
			}
		}
		s.store.SetSetting(k, v)
	}
	s.store.AddEvent("backup", "info", "настройки бэкапа изменены", "{}")
	writeJSON(w, map[string]any{"ok": true})
}

// backupCreate — POST /api/backup/create: создать бэкап сейчас.
func (s *Server) backupCreate(w http.ResponseWriter, r *http.Request) {
	if s.backupMgr == nil {
		http.Error(w, "backup manager not available", 503)
		return
	}
	path, err := s.backupMgr.Create(r.Context())
	if err != nil {
		http.Error(w, "бэкап не удался: "+err.Error(), 500)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "file": filepath.Base(path)})
}

// backupDownload — GET /api/backup/download?name=...: скачать бэкап.
// УРОК: path traversal защита — только имя файла из каталога бэкапов.
func (s *Server) backupDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" || strings.ContainsAny(name, "/\\") || !strings.HasPrefix(name, "xkit-panel-backup-") || !strings.HasSuffix(name, ".tar.gz") {
		http.Error(w, "invalid backup name", 400)
		return
	}
	if s.backupMgr == nil {
		http.Error(w, "backup manager not available", 503)
		return
	}
	// проверяем что файл есть в списке (не произвольный путь)
	found := false
	for _, b := range s.backupMgr.List() {
		if b["name"] == name {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "backup not found", 404)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeFile(w, r, filepath.Join(s.backupDir, name))
}