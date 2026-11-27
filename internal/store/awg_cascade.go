package store

import "encoding/json"

// AWGCascade — персист AWG-каскада мастер→нода (переживает рестарт панели).
type AWGCascade struct {
	NodeID    string `json:"node_id"`
	Port      int    `json:"port"`
	MasterPriv string `json:"master_priv"`
	MasterPub string `json:"master_pub"`
	NodePub   string `json:"node_pub"`
	Params    string `json:"params"` // JSON amnezia.AWGParams
	MasterIP  string `json:"master_ip"`
	Subnet    string `json:"subnet"`
	Enabled   bool   `json:"enabled"`
}

func (s *Store) UpsertAWGCascade(c AWGCascade) error {
	en := 0
	if c.Enabled { en = 1 }
	_, err := s.db.Exec(`INSERT INTO awg_cascades(node_id,port,master_priv,master_pub,node_pub,params,master_ip,subnet,enabled)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(node_id) DO UPDATE SET port=excluded.port,master_priv=excluded.master_priv,master_pub=excluded.master_pub,
		node_pub=excluded.node_pub,params=excluded.params,master_ip=excluded.master_ip,subnet=excluded.subnet,enabled=excluded.enabled`,
		c.NodeID, c.Port, c.MasterPriv, c.MasterPub, c.NodePub, c.Params, c.MasterIP, c.Subnet, en)
	return err
}

func (s *Store) DeleteAWGCascade(nodeID string) {
	s.db.Exec(`DELETE FROM awg_cascades WHERE node_id=?`, nodeID)
}

func (s *Store) EnabledAWGCascades() []AWGCascade {
	rows, err := s.db.Query(`SELECT node_id,port,master_priv,master_pub,node_pub,params,master_ip,subnet,enabled FROM awg_cascades WHERE enabled=1`)
	if err != nil { return nil }
	defer rows.Close()
	var out []AWGCascade
	for rows.Next() {
		var c AWGCascade
		var en int
		if rows.Scan(&c.NodeID, &c.Port, &c.MasterPriv, &c.MasterPub, &c.NodePub, &c.Params, &c.MasterIP, &c.Subnet, &en) == nil {
			c.Enabled = en == 1
			out = append(out, c)
		}
	}
	return out
}

// AWGCascadeParams — распарсить params JSON в map (для восстановления).
func AWGCascadeParams(raw string) map[string]any {
	var m map[string]any
	json.Unmarshal([]byte(raw), &m)
	return m
}