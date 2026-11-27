// Package store — SQLite-хранилище XKIT Panel (control plane балансировщика).
// modernc.org/sqlite (pure Go, CGO_ENABLED=0). Клиенты/ноды/sticky-карта/события/настройки.
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Store struct {
	db *sql.DB
	// EventHook — вызывается на каждое событие (P1 #14 webhook). Ставится из main.go.
	EventHook func(kind, severity, message, meta string)
}

// Open открывает/создаёт SQLite БД и применяет миграции.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite: один писатель, избегаем lock
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	// применяем все миграции по порядку (001, 002, ...). Идемпотентно:
	// CREATE TABLE IF NOT EXISTS + ALTER guarded (ошибка duplicate column игнорируется).
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if _, err := s.db.Exec(string(data)); err != nil {
			// ALTER TABLE ADD COLUMN на уже существующей колонке = duplicate column —
			// идемпотентность: пропускаем (миграция уже применена ранее).
			if strings.Contains(err.Error(), "duplicate column") {
				continue
			}
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) DB() *sql.DB  { return s.db }

// ---- Node ----

type Node struct {
	ID          string
	Name        string
	Country     string
	CountryCode uint32
	Priority    int
	Price       float64
	Host        string
	Port        int
	Tunnel      string
	TunnelCfg   string
	Health      string
	HealthFails int
	Expiry      int64 // дата аренды (unix ts), 0 = бессрочно
	Enabled     bool
	Capacity    int   // ёмкость: клиентов = 100% загрузки (0 → дефолт 50)
	MTU         int   // MTU каскадного туннеля (0 → глобальный дефолт)
	LastGoodCfg string // последний рабочий конфиг ноды (откат)
	LatencyMs   float64 // текущая задержка пробы (мс)
	UptimePct   float64 // доступность за 24ч (%)
	QualityScore float64 // интегральная оценка качества 0..100
	Note         string  // заметка владельца (хостер/тариф/контакт)
}

func (s *Store) UpsertNode(n Node) error {
	_, err := s.db.Exec(`INSERT INTO nodes(id,name,country,country_code,priority,price,host,port,tunnel,tunnel_cfg,health,expiry,enabled,note)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,country=excluded.country,country_code=excluded.country_code,
		priority=excluded.priority,price=excluded.price,host=excluded.host,port=excluded.port,tunnel=excluded.tunnel,
		tunnel_cfg=excluded.tunnel_cfg,expiry=excluded.expiry,enabled=excluded.enabled,note=excluded.note,updated_at=strftime('%s','now')`,
		n.ID, n.Name, n.Country, n.CountryCode, n.Priority, n.Price, n.Host, n.Port, n.Tunnel, n.TunnelCfg, n.Health, n.Expiry, b2i(n.Enabled), n.Note)
	return err
}

// ExpiredNodes — ноды с истёкшей арендой (для enforce тикера). expiry>0 и <now.
func (s *Store) ExpiredNodes(now int64) ([]Node, error) {
	rows, err := s.db.Query(`SELECT id,name,country,country_code,priority,price,host,port,tunnel,tunnel_cfg,health,health_fails,expiry,enabled,capacity,latency_ms,uptime_pct,quality_score,note
		FROM nodes WHERE enabled=1 AND expiry>0 AND expiry<?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var en int
		if err := rows.Scan(&n.ID, &n.Name, &n.Country, &n.CountryCode, &n.Priority, &n.Price, &n.Host, &n.Port, &n.Tunnel, &n.TunnelCfg, &n.Health, &n.HealthFails, &n.Expiry, &en, &n.Capacity, &n.LatencyMs, &n.UptimePct, &n.QualityScore, &n.Note); err != nil {
			return nil, err
		}
		n.Enabled = en == 1
		out = append(out, n)
	}
	return out, rows.Err()
}

// NodesByCountry возвращает ноды страны по приоритету (для assignment/failover).
func (s *Store) NodesByCountry(country string) ([]Node, error) {
	rows, err := s.db.Query(`SELECT id,name,country,country_code,priority,price,host,port,tunnel,tunnel_cfg,health,health_fails,expiry,enabled,capacity,latency_ms,uptime_pct,quality_score,note
		FROM nodes WHERE country=? AND enabled=1 ORDER BY priority ASC, price ASC`, country)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var en int
		if err := rows.Scan(&n.ID, &n.Name, &n.Country, &n.CountryCode, &n.Priority, &n.Price, &n.Host, &n.Port, &n.Tunnel, &n.TunnelCfg, &n.Health, &n.HealthFails, &n.Expiry, &en, &n.Capacity, &n.LatencyMs, &n.UptimePct, &n.QualityScore, &n.Note); err != nil {
			return nil, err
		}
		n.Enabled = en == 1
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) SetNodeHealth(id, health string, fails int) error {
	_, err := s.db.Exec(`UPDATE nodes SET health=?,health_fails=?,updated_at=strftime('%s','now') WHERE id=?`, health, fails, id)
	return err
}

// ---- Client ----

type Client struct {
	Email       string
	UUID        string
	SubID       string
	Name        string
	Country     string
	CountryCode uint32
	Expiry      int64
	QuotaBytes  int64
	UsedBytes   int64
	Enabled     bool
	MTU         int // MTU клиентского туннеля (0 → глобальный дефолт)
}

func (s *Store) UpsertClient(c Client) error {
	_, err := s.db.Exec(`INSERT INTO clients(email,uuid,sub_id,name,country,country_code,expiry,quota_bytes,used_bytes,enabled)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(email) DO UPDATE SET uuid=excluded.uuid,sub_id=excluded.sub_id,name=excluded.name,
		country=excluded.country,country_code=excluded.country_code,expiry=excluded.expiry,quota_bytes=excluded.quota_bytes,
		enabled=excluded.enabled,updated_at=strftime('%s','now')`,
		c.Email, c.UUID, c.SubID, c.Name, c.Country, c.CountryCode, c.Expiry, c.QuotaBytes, c.UsedBytes, b2i(c.Enabled))
	return err
}

func (s *Store) GetClient(email string) (*Client, error) {
	var c Client
	var en int
	err := s.db.QueryRow(`SELECT email,uuid,sub_id,name,country,country_code,expiry,quota_bytes,used_bytes,enabled FROM clients WHERE email=?`, email).
		Scan(&c.Email, &c.UUID, &c.SubID, &c.Name, &c.Country, &c.CountryCode, &c.Expiry, &c.QuotaBytes, &c.UsedBytes, &en)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Enabled = en == 1
	return &c, nil
}

// ExpiredClients — клиенты с истёкшим сроком (для enforce тикера).
func (s *Store) ExpiredClients(now int64) ([]Client, error) {
	rows, err := s.db.Query(`SELECT email,uuid,sub_id,name,country,country_code,expiry,quota_bytes,used_bytes,enabled
		FROM clients WHERE enabled=1 AND expiry>0 AND expiry<?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var c Client
		var en int
		if err := rows.Scan(&c.Email, &c.UUID, &c.SubID, &c.Name, &c.Country, &c.CountryCode, &c.Expiry, &c.QuotaBytes, &c.UsedBytes, &en); err != nil {
			return nil, err
		}
		c.Enabled = en == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---- Assignment (sticky-карта) ----

type Assignment struct {
	Email        string
	Country      string
	NodeID       string
	RuleTag      string
	Status       string
	FailoverFrom string
}

func (s *Store) SetAssignment(a Assignment) error {
	_, err := s.db.Exec(`INSERT INTO assignments(email,country,node_id,rule_tag,status,failover_from)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(email,country) DO UPDATE SET node_id=excluded.node_id,rule_tag=excluded.rule_tag,
		status=excluded.status,failover_from=excluded.failover_from,updated_at=strftime('%s','now')`,
		a.Email, a.Country, a.NodeID, a.RuleTag, a.Status, a.FailoverFrom)
	return err
}

func (s *Store) GetAssignment(email, country string) (*Assignment, error) {
	var a Assignment
	err := s.db.QueryRow(`SELECT email,country,node_id,rule_tag,status,failover_from FROM assignments WHERE email=? AND country=?`, email, country).
		Scan(&a.Email, &a.Country, &a.NodeID, &a.RuleTag, &a.Status, &a.FailoverFrom)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// AssignmentsByNode — все клиенты ноды (для failover при отвале).
func (s *Store) AssignmentsByNode(nodeID string) ([]Assignment, error) {
	rows, err := s.db.Query(`SELECT email,country,node_id,rule_tag,status,failover_from FROM assignments WHERE node_id=?`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Assignment
	for rows.Next() {
		var a Assignment
		if err := rows.Scan(&a.Email, &a.Country, &a.NodeID, &a.RuleTag, &a.Status, &a.FailoverFrom); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) AllAssignments() ([]Assignment, error) {
	rows, err := s.db.Query(`SELECT email,country,node_id,rule_tag,status,failover_from FROM assignments`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Assignment
	for rows.Next() {
		var a Assignment
		if err := rows.Scan(&a.Email, &a.Country, &a.NodeID, &a.RuleTag, &a.Status, &a.FailoverFrom); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- Events ----

func (s *Store) AddEvent(kind, severity, message, meta string) error {
	_, err := s.db.Exec(`INSERT INTO events(kind,severity,message,meta) VALUES(?,?,?,?)`, kind, severity, message, meta)
	// webhook-хук (P1 #14): асинхронная отправка наружу, если настроен.
	// kind=webhook* не эмитим (защита от рекурсии: ошибки доставки тоже события).
	if s.EventHook != nil && !strings.HasPrefix(kind, "webhook") {
		s.EventHook(kind, severity, message, meta)
	}
	return err
}

// PruneEvents — удалить события старше days дней (retention журнала, чтобы БД не росла бесконечно).
func (s *Store) PruneEvents(days int) {
	s.db.Exec(`DELETE FROM events WHERE ts < strftime('%s','now') - ?*86400`, days)
}

func (s *Store) RecentEvents(limit int) ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT id,ts,kind,severity,message,meta FROM events ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, ts int64
		var kind, sev, msg, meta string
		if err := rows.Scan(&id, &ts, &kind, &sev, &msg, &meta); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "ts": ts, "time": time.Unix(ts, 0).UTC().Format(time.RFC3339), "kind": kind, "severity": sev, "message": msg, "meta": meta})
	}
	return out, rows.Err()
}

// ---- Settings ----

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) GetSetting(key, def string) string {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err != nil {
		return def
	}
	return v
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// AddUsedBytes атомарно добавляет трафик к used_bytes клиента (дельта из StatsService).
// УРОК XKIT (никаких молчаливых ошибок): ошибка возвращается, не глотается.
func (s *Store) AddUsedBytes(email string, delta int64) error {
	if delta <= 0 {
		return nil
	}
	_, err := s.db.Exec(`UPDATE clients SET used_bytes=used_bytes+?, updated_at=strftime('%s','now') WHERE email=?`, delta, email)
	return err
}

// SetUsedBytes устанавливает абсолютное значение used_bytes (кумулятивный счётчик Xray).
func (s *Store) SetUsedBytes(email string, used int64) error {
	_, err := s.db.Exec(`UPDATE clients SET used_bytes=?, updated_at=strftime('%s','now') WHERE email=?`, used, email)
	return err
}

// EnabledClients — все включённые клиенты (для enforce/stats тикера).
func (s *Store) EnabledClients() ([]Client, error) {
	rows, err := s.db.Query(`SELECT email,uuid,sub_id,name,country,country_code,expiry,quota_bytes,used_bytes,enabled
		FROM clients WHERE enabled=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var c Client
		var en int
		if err := rows.Scan(&c.Email, &c.UUID, &c.SubID, &c.Name, &c.Country, &c.CountryCode, &c.Expiry, &c.QuotaBytes, &c.UsedBytes, &en); err != nil {
			return nil, err
		}
		c.Enabled = en == 1
		out = append(out, c)
	}
	return out, rows.Err()
}