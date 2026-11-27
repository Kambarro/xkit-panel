package store

import "database/sql"

// Sidecar — нативный протокол-демон (панель=оркестратор).
type Sidecar struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Enabled    bool   `json:"enabled"`
	Binary     string `json:"binary"`
	Version    string `json:"version"`
	ConfigPath string `json:"config_path"`
	Unit       string `json:"unit"`
	Port       int    `json:"port"`
	Config     string `json:"config"` // JSON источник правды
	Status     string `json:"status"`
	LastError  string `json:"last_error"`
}

func (s *Store) UpsertSidecar(sc Sidecar) error {
	en := 0; if sc.Enabled { en = 1 }
	_, err := s.db.Exec(`INSERT INTO sidecars(id,kind,enabled,binary,version,config_path,unit,port,config,status,last_error)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,enabled=excluded.enabled,binary=excluded.binary,
		version=excluded.version,config_path=excluded.config_path,unit=excluded.unit,port=excluded.port,
		config=excluded.config,status=excluded.status,last_error=excluded.last_error,updated_at=strftime('%s','now')`,
		sc.ID, sc.Kind, en, sc.Binary, sc.Version, sc.ConfigPath, sc.Unit, sc.Port, sc.Config, sc.Status, sc.LastError)
	return err
}

func (s *Store) GetSidecar(id string) (*Sidecar, error) {
	var sc Sidecar; var en int
	err := s.db.QueryRow(`SELECT id,kind,enabled,binary,version,config_path,unit,port,config,status,last_error FROM sidecars WHERE id=?`, id).
		Scan(&sc.ID,&sc.Kind,&en,&sc.Binary,&sc.Version,&sc.ConfigPath,&sc.Unit,&sc.Port,&sc.Config,&sc.Status,&sc.LastError)
	if err == sql.ErrNoRows { return nil, nil }
	if err != nil { return nil, err }
	sc.Enabled = en==1
	return &sc, nil
}

func (s *Store) AllSidecars() ([]Sidecar, error) {
	rows, err := s.db.Query(`SELECT id,kind,enabled,binary,version,config_path,unit,port,config,status,last_error FROM sidecars ORDER BY id`)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []Sidecar
	for rows.Next() {
		var sc Sidecar; var en int
		if err := rows.Scan(&sc.ID,&sc.Kind,&en,&sc.Binary,&sc.Version,&sc.ConfigPath,&sc.Unit,&sc.Port,&sc.Config,&sc.Status,&sc.LastError); err != nil { return nil, err }
		sc.Enabled = en==1
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSidecar(id string) error {
	_, err := s.db.Exec(`DELETE FROM sidecars WHERE id=?`, id)
	return err
}

// SidecarBinariesExcept — бинари других сайдкаров (для IsSharedBinary при удалении).
func (s *Store) SidecarBinariesExcept(id string) []string {
	rows, err := s.db.Query(`SELECT binary FROM sidecars WHERE id!=? AND binary!=''`, id)
	if err != nil { return nil }
	defer rows.Close()
	var out []string
	for rows.Next() { var b string; rows.Scan(&b); out = append(out, b) }
	return out
}
