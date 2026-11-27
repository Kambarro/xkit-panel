package store

import (
	"database/sql"
	"encoding/json"
)

// AWGServer — единственный AWG-сервер мастера (id=1).
type AWGServer struct {
	Enabled    bool
	Port       int
	Iface      string
	Subnet     string
	PrivateKey string
	PublicKey  string
	Params     string // AWGParams JSON
	DNS        string
}

func (s *Store) GetAWGServer() (*AWGServer, error) {
	var a AWGServer
	var en int
	err := s.db.QueryRow(`SELECT enabled,port,iface,subnet,private_key,public_key,params,dns FROM awg_server WHERE id=1`).
		Scan(&en, &a.Port, &a.Iface, &a.Subnet, &a.PrivateKey, &a.PublicKey, &a.Params, &a.DNS)
	if err != nil {
		return nil, err
	}
	a.Enabled = en == 1
	return &a, nil
}

func (s *Store) SaveAWGServer(a AWGServer) error {
	en := 0
	if a.Enabled {
		en = 1
	}
	_, err := s.db.Exec(`UPDATE awg_server SET enabled=?,port=?,iface=?,subnet=?,private_key=?,public_key=?,params=?,dns=?,updated_at=strftime('%s','now') WHERE id=1`,
		en, a.Port, a.Iface, a.Subnet, a.PrivateKey, a.PublicKey, a.Params, a.DNS)
	return err
}

// AWGPeer — пир клиента панели.
type AWGPeer struct {
	Email        string `json:"email"`
	Name         string `json:"name"`
	PrivateKey   string `json:"-"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"-"`
	Address      string `json:"address"`
	Enabled      bool   `json:"enabled"`
}

func (s *Store) UpsertAWGPeer(p AWGPeer) error {
	en := 0
	if p.Enabled {
		en = 1
	}
	_, err := s.db.Exec(`INSERT INTO awg_peers(email,name,private_key,public_key,preshared_key,address,enabled)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(email) DO UPDATE SET name=excluded.name,private_key=excluded.private_key,
		public_key=excluded.public_key,preshared_key=excluded.preshared_key,address=excluded.address,
		enabled=excluded.enabled,updated_at=strftime('%s','now')`,
		p.Email, p.Name, p.PrivateKey, p.PublicKey, p.PresharedKey, p.Address, en)
	return err
}

func (s *Store) GetAWGPeer(email string) (*AWGPeer, error) {
	var p AWGPeer
	var en int
	err := s.db.QueryRow(`SELECT email,name,private_key,public_key,preshared_key,address,enabled FROM awg_peers WHERE email=?`, email).
		Scan(&p.Email, &p.Name, &p.PrivateKey, &p.PublicKey, &p.PresharedKey, &p.Address, &en)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.Enabled = en == 1
	return &p, nil
}

func (s *Store) AllAWGPeers() ([]AWGPeer, error) {
	rows, err := s.db.Query(`SELECT email,name,private_key,public_key,preshared_key,address,enabled FROM awg_peers ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AWGPeer
	for rows.Next() {
		var p AWGPeer
		var en int
		if err := rows.Scan(&p.Email, &p.Name, &p.PrivateKey, &p.PublicKey, &p.PresharedKey, &p.Address, &en); err != nil {
			return nil, err
		}
		p.Enabled = en == 1
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAWGPeer(email string) error {
	_, err := s.db.Exec(`DELETE FROM awg_peers WHERE email=?`, email)
	return err
}

// AWGUsedAddresses — занятые адреса пиров (для AssignIP).
func (s *Store) AWGUsedAddresses() map[string]bool {
	used := map[string]bool{}
	rows, err := s.db.Query(`SELECT address FROM awg_peers`)
	if err != nil {
		return used
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		rows.Scan(&a)
		used[a] = true
	}
	return used
}

// AWGParamsJSON — маршалинг параметров (helper).
func AWGParamsJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}