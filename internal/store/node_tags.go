package store

import "strings"

// NodeTags — теги ноды (P1 #13). CSV в nodes.tags.
func (s *Store) SetNodeTags(id, tags string) error {
 _,err:=s.db.Exec(`UPDATE nodes SET tags=? WHERE id=?`,tags,id)
 return err
}

func (s *Store) NodeTags(id string) []string {
 var tags string
 s.db.QueryRow(`SELECT tags FROM nodes WHERE id=?`,id).Scan(&tags)
 if tags==""{return nil}
 var out []string
 for _,t:=range strings.Split(tags,","){
  if t=strings.TrimSpace(t);t!=""{out=append(out,t)}
 }
 return out
}

// AllNodes — все ноды (для тегов/bulk/фильтра).
func (s *Store) AllNodes() ([]Node, error) {
	rows, err := s.db.Query(`SELECT id,name,country,country_code,priority,price,host,port,tunnel,tunnel_cfg,health,health_fails,expiry,enabled,capacity,latency_ms,uptime_pct,quality_score FROM nodes ORDER BY priority`)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node; var en int
		if err := rows.Scan(&n.ID,&n.Name,&n.Country,&n.CountryCode,&n.Priority,&n.Price,&n.Host,&n.Port,&n.Tunnel,&n.TunnelCfg,&n.Health,&n.HealthFails,&n.Expiry,&en,&n.Capacity,&n.LatencyMs,&n.UptimePct,&n.QualityScore); err != nil {
			return nil, err
		}
		n.Enabled = en==1
		out = append(out, n)
	}
	return out, rows.Err()
}

// NodesByTag — ноды с тегом (для bulk-операций/фильтра).
func (s *Store) NodesByTag(tag string) ([]Node, error) {
	all, err := s.AllNodes()
	if err != nil { return nil, err }
	var out []Node
	for _, n := range all {
		for _, t := range s.NodeTags(n.ID) {
			if strings.EqualFold(t, tag) { out = append(out, n); break }
		}
	}
	return out, nil
}

// BulkDeleteNodes — удалить ноды по списку id.
func (s *Store) BulkDeleteNodes(ids []string) (int, error) {
	n := 0
	for _, id := range ids {
		res, err := s.db.Exec(`DELETE FROM nodes WHERE id=?`, id)
		if err != nil { return n, err }
		if aff, _ := res.RowsAffected(); aff > 0 { n++ }
	}
	return n, nil
}

// SetNodesEnabled — bulk вкл/выкл нод.
func (s *Store) SetNodesEnabled(ids []string, enabled bool) (int, error) {
	en := 0; if enabled { en = 1 }
	n := 0
	for _, id := range ids {
		res, err := s.db.Exec(`UPDATE nodes SET enabled=? WHERE id=?`, en, id)
		if err != nil { return n, err }
		if aff, _ := res.RowsAffected(); aff > 0 { n++ }
	}
	return n, nil
}
