package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// Inbound — протокол мастера в SQLite (источник правды, как nodes/clients).
// УРОК (владелец): не ограничены 3X-UI — protocol/network/security любые из Xray 26.x.
type Inbound struct {
	Tag      string
	Protocol string
	Port     int
	Listen   string
	Network  string
	Security string
	Settings string // JSON
	Stream   string // JSON
	Enabled  bool
	Hidden   bool // спрятан за 443 (listen 127.0.0.1, клиентский порт = PublicPort)
	PublicPort int // порт в клиентской ссылке (443 для hidden; 0 = свой Port)
	InSub    bool // показывать в подписке (false = работает но не отсвечивает)
}

// ClientPort — порт, который видит клиент (hidden → 443).
func (ib *Inbound) ClientPort() int {
	if ib.Hidden && ib.PublicPort > 0 { return ib.PublicPort }
	return ib.Port
}

func (s *Store) UpsertInbound(ib Inbound) error {
	// УРОК: stream/settings ДОЛЖНЫ быть валидным JSON. Невалидный (JS-literal без кавычек)
	// ломает getInbound → форма показывает пустые dest/sni → владелец видит «wikipedia»
	// (placeholder) вместо реальных значений. Валидируем перед записью.
	if ib.Settings != "" && !json.Valid([]byte(ib.Settings)) {
		return fmt.Errorf("inbound %s: settings не валидный JSON", ib.Tag)
	}
	if ib.Stream != "" && !json.Valid([]byte(ib.Stream)) {
		return fmt.Errorf("inbound %s: stream не валидный JSON", ib.Tag)
	}
	_, err := s.db.Exec(`INSERT INTO inbounds(tag,protocol,port,listen,network,security,settings,stream,enabled,hidden,public_port,in_sub)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(tag) DO UPDATE SET protocol=excluded.protocol,port=excluded.port,listen=excluded.listen,
		network=excluded.network,security=excluded.security,settings=excluded.settings,stream=excluded.stream,
		enabled=excluded.enabled,hidden=excluded.hidden,public_port=excluded.public_port,in_sub=excluded.in_sub,updated_at=strftime('%s','now')`,
		ib.Tag, ib.Protocol, ib.Port, ib.Listen, ib.Network, ib.Security, ib.Settings, ib.Stream, b2i(ib.Enabled), b2i(ib.Hidden), ib.PublicPort, b2i(ib.InSub))
	return err
}

func (s *Store) GetInbound(tag string) (*Inbound, error) {
	var ib Inbound
	var en int
	var hid int
	var insub int
	err := s.db.QueryRow(`SELECT tag,protocol,port,listen,network,security,settings,stream,enabled,hidden,public_port,in_sub FROM inbounds WHERE tag=?`, tag).
		Scan(&ib.Tag, &ib.Protocol, &ib.Port, &ib.Listen, &ib.Network, &ib.Security, &ib.Settings, &ib.Stream, &en, &hid, &ib.PublicPort, &insub)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ib.Enabled = en == 1
	ib.Hidden = hid == 1
	ib.InSub = insub == 1
	return &ib, nil
}

func (s *Store) AllInbounds() ([]Inbound, error) {
	rows, err := s.db.Query(`SELECT tag,protocol,port,listen,network,security,settings,stream,enabled,hidden,public_port,in_sub FROM inbounds ORDER BY port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Inbound
	for rows.Next() {
		var ib Inbound
		var en, hid, insub int
		if err := rows.Scan(&ib.Tag, &ib.Protocol, &ib.Port, &ib.Listen, &ib.Network, &ib.Security, &ib.Settings, &ib.Stream, &en, &hid, &ib.PublicPort, &insub); err != nil {
			return nil, err
		}
		ib.Enabled = en == 1
		ib.Hidden = hid == 1
		ib.InSub = insub == 1
		out = append(out, ib)
	}
	return out, rows.Err()
}

func (s *Store) DeleteInbound(tag string) error {
	_, err := s.db.Exec(`DELETE FROM inbounds WHERE tag=?`, tag)
	return err
}

func (s *Store) SetInboundEnabled(tag string, enabled bool) error {
	_, err := s.db.Exec(`UPDATE inbounds SET enabled=?, updated_at=strftime('%s','now') WHERE tag=?`, b2i(enabled), tag)
	return err
}

// InboundClients — клиенты inbound'а из settings JSON (для подписок/управления).
func (ib *Inbound) Clients() []map[string]any {
	var st struct {
		Clients []map[string]any `json:"clients"`
	}
	json.Unmarshal([]byte(ib.Settings), &st)
	return st.Clients
}
func (s *Store) SetInboundInSub(tag string, inSub bool) error {
	_, err := s.db.Exec(`UPDATE inbounds SET in_sub=?, updated_at=strftime('%s','now') WHERE tag=?`, b2i(inSub), tag)
	return err
}
