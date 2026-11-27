// Package backup — бэкапы XKIT Panel (настраиваемые, как в XKIT main).
// УРОК XKIT: база = источник правды → бэкап SQLite + TLS + REALITY ключи = полный
// аварийный переезд. MANIFEST + RESTORE внутри архива (как backup_now в main).
// Retention: интервал часов / хранить дней / минимум копий. Отправка в TG-бот.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

const restoreDoc = `XKIT Panel — аварийное восстановление (переезд на новый сервер)
================================================================
1. На новом сервере: curl -fsSL <install.sh> | bash  (домен/IP тот же или новый)
2. Остановить панель: systemctl stop xkit-panel xray
3. Распаковать архив: tar xzf xkit-panel-backup-*.tar.gz -C /
4. Проверить /var/lib/xkit-panel/panel.db (клиенты/ноды/настройки — источник правды)
5. Запустить: systemctl start xray xkit-panel
6. Если IP сменился — переключить A-запись домена на новый IP (или панель
   переключит сама при настроенном DNS-провайдере).
UUID/subId клиентов сохранены — подписки заработают без перенастройки клиентов.
`

// Manager — планировщик бэкапов + создание/retention.
type Manager struct {
	store     *store.Store
	dir       string // каталог бэкапов
	dbPath    string
	tgSend    func(ctx context.Context, file string) error // отправка в бот (опц)
}

func NewManager(st *store.Store, dir, dbPath string) *Manager {
	return &Manager{store: st, dir: dir, dbPath: dbPath}
}

// SetTGSend подключает отправку бэкапа в Telegram (бот панели).
func (m *Manager) SetTGSend(fn func(ctx context.Context, file string) error) { m.tgSend = fn }

// Settings — текущие настройки бэкапа из SQLite.
type Settings struct {
	Enabled    bool
	IntervalH  int
	KeepDays   int
	KeepMin    int
	TGSend     bool
	LastBackup int64
}

func (m *Manager) Settings() Settings {
	gi := func(k string, def int) int {
		v, _ := strconv.Atoi(m.store.GetSetting(k, strconv.Itoa(def)))
		return v
	}
	last, _ := strconv.ParseInt(m.store.GetSetting("backup_last", "0"), 10, 64)
	return Settings{
		Enabled:    m.store.GetSetting("backup_enabled", "1") == "1",
		IntervalH:  gi("backup_interval_h", 24),
		KeepDays:   gi("backup_keep_days", 14),
		KeepMin:    gi("backup_keep_min", 3),
		TGSend:     m.store.GetSetting("backup_tg_send", "1") == "1",
		LastBackup: last,
	}
}

// Create — создать бэкап сейчас (кнопка/API/тикер). Возвращает путь к архиву.
// Состав: panel.db (WAL checkpoint!), TLS серты, REALITY/tunnel env, xray config.
func (m *Manager) Create(ctx context.Context) (string, error) {
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		return "", fmt.Errorf("backup dir: %w", err)
	}
	// SQLite WAL checkpoint — чтобы .db содержал всё (не только -wal)
	m.store.DB().Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	// имя с наносекундами — быстрые повторные бэкапы не перетирают друг друга
	name := fmt.Sprintf("xkit-panel-backup-%s.tar.gz", time.Now().Format("20060102-150405.000"))
	path := filepath.Join(m.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	addFile := func(src, name string) error {
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), ModTime: time.Now()}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	}
	// база — главное
	if err := addFile(m.dbPath, strings.TrimPrefix(m.dbPath, "/")); err != nil {
		return "", fmt.Errorf("backup db: %w", err)
	}
	// конфиг xray (REALITY ключи мастера, outbounds нод)
	addFile("/usr/local/etc/xray/config.json", "usr/local/etc/xray/config.json")
	// TLS (LE или self-signed)
	filepath.WalkDir("/etc/letsencrypt/live", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".pem") {
			// симлинки LE — читаем реальное содержимое
			if real, err := filepath.EvalSymlinks(p); err == nil {
				addFile(real, strings.TrimPrefix(p, "/"))
			}
		}
		return nil
	})
	filepath.WalkDir("/etc/xkit-panel/tls", func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			addFile(p, strings.TrimPrefix(p, "/"))
		}
		return nil
	})
	// tunnel.env (uuid каскада)
	addFile(filepath.Join(filepath.Dir(m.dbPath), "tunnel.env"), strings.TrimPrefix(filepath.Join(filepath.Dir(m.dbPath), "tunnel.env"), "/"))
	// MANIFEST + RESTORE (урок main: документация внутри архива)
	manifest := fmt.Sprintf("XKIT Panel backup\ncreated: %s\ndb: %s\nсостав: panel.db, xray config, TLS, tunnel.env\n", time.Now().UTC().Format(time.RFC3339), m.dbPath)
	for name, content := range map[string]string{"MANIFEST.txt": manifest, "RESTORE.txt": restoreDoc} {
		hdr := &tar.Header{Name: name, Mode: 0644, Size: int64(len(content)), ModTime: time.Now()}
		tw.WriteHeader(hdr)
		io.WriteString(tw, content)
	}
	tw.Close()
	gz.Close()
	f.Close()

	m.store.SetSetting("backup_last", strconv.FormatInt(time.Now().Unix(), 10))
	m.store.AddEvent("backup", "ok", "бэкап создан: "+name, "{}")
	m.retention()
	// отправка в TG (если включена и бот подключён)
	if m.Settings().TGSend && m.tgSend != nil {
		if err := m.tgSend(ctx, path); err != nil {
			m.store.AddEvent("backup", "warn", "бэкап создан, но отправка в TG не удалась: "+err.Error(), "{}")
		} else {
			m.store.AddEvent("backup", "ok", "бэкап отправлен в Telegram", "{}")
		}
	}
	return path, nil
}

// retention — удалить старые бэкапы: старше KeepDays, но оставить минимум KeepMin.
func (m *Manager) retention() {
	s := m.Settings()
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	type bf struct {
		name string
		mod  time.Time
	}
	var files []bf
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "xkit-panel-backup-") && strings.HasSuffix(e.Name(), ".tar.gz") {
			info, err := e.Info()
			if err == nil {
				files = append(files, bf{e.Name(), info.ModTime()})
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) }) // новые первые
	cutoff := time.Now().AddDate(0, 0, -s.KeepDays)
	for i, f := range files {
		if i < s.KeepMin {
			continue // минимум копий всегда храним
		}
		if f.mod.Before(cutoff) {
			os.Remove(filepath.Join(m.dir, f.name))
		}
	}
}

// List — список бэкапов (для UI: скачать/удалить).
func (m *Manager) List() []map[string]any {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "xkit-panel-backup-") && strings.HasSuffix(e.Name(), ".tar.gz") {
			info, err := e.Info()
			if err != nil {
				continue
			}
			out = append(out, map[string]any{"name": e.Name(), "size": info.Size(), "time": info.ModTime().Unix()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["time"].(int64) > out[j]["time"].(int64) })
	return out
}

// Start — тикер авто-бэкапа (интервал из настроек, проверяет каждый час).
func (m *Manager) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s := m.Settings()
				if !s.Enabled || s.IntervalH <= 0 {
					continue
				}
				if time.Now().Unix()-s.LastBackup >= int64(s.IntervalH)*3600 {
					if _, err := m.Create(ctx); err != nil {
						log.Printf("backup auto: %v", err)
						m.store.AddEvent("backup", "error", "авто-бэкап не удался: "+err.Error(), "{}")
					}
				}
			}
		}
	}()
}