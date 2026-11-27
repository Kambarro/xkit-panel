package store

import "encoding/json"

// Набор протоколов клиента (вариант B: группы + per-client override).
// Приоритет: свой набор клиента (protocols JSON) > набор группы (squad.inbounds) > все включённые.
// '' = наследовать. Реальный запрет: клиент не добавляется в inbound запрещённого протокола.

// ClientProtocols — свой набор клиента (override), nil если наследует.
func (s *Store) ClientProtocols(email string) []string {
	var raw string
	s.db.QueryRow(`SELECT protocols FROM clients WHERE email=?`, email).Scan(&raw)
	if raw == "" {
		return nil
	}
	var tags []string
	json.Unmarshal([]byte(raw), &tags)
	return tags
}

// SetClientProtocols — задать свой набор клиента (nil/пусто = наследовать группу/все).
func (s *Store) SetClientProtocols(email string, tags []string) {
	raw := ""
	if len(tags) > 0 {
		b, _ := json.Marshal(tags)
		raw = string(b)
	}
	s.db.Exec(`UPDATE clients SET protocols=? WHERE email=?`, raw, email)
}

// EffectiveProtocols — эффективный набор tag'ов клиента: override > группа > все включённые.
// Возвращает (tags, source): source = "client"|"squad"|"all".
func (s *Store) EffectiveProtocols(email string) ([]string, string) {
	if tags := s.ClientProtocols(email); tags != nil {
		return tags, "client"
	}
	var squadID string
	s.db.QueryRow(`SELECT squad_id FROM clients WHERE email=?`, email).Scan(&squadID)
	if squadID != "" {
		if sq, _ := s.GetSquad(squadID); sq != nil && len(sq.Inbounds) > 0 {
			return sq.Inbounds, "squad"
		}
	}
	// все включённые протоколы
	var tags []string
	rows, err := s.db.Query(`SELECT tag FROM inbounds WHERE enabled=1 AND tag NOT IN ('api-in','api')`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t string
			rows.Scan(&t)
			tags = append(tags, t)
		}
	}
	return tags, "all"
}

// ProtocolAllowed — разрешён ли протокол клиенту (по эффективному набору).
func (s *Store) ProtocolAllowed(email, tag string) bool {
	tags, _ := s.EffectiveProtocols(email)
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// RemoveProtocolEverywhere — убрать удалённый протокол из наборов групп и override клиентов.
// УРОК (QA): delete inbound оставлял висячий tag в squads.inbounds и clients.protocols.
func (s *Store) RemoveProtocolEverywhere(tag string) {
	// squads
	rows, err := s.db.Query(`SELECT id,inbounds FROM squads`)
	if err == nil {
		type sq struct {
			id  string
			ibs []string
		}
		var list []sq
		for rows.Next() {
			var id, raw string
			rows.Scan(&id, &raw)
			var ibs []string
			json.Unmarshal([]byte(raw), &ibs)
			list = append(list, sq{id, ibs})
		}
		rows.Close()
		for _, q := range list {
			var kept []string
			for _, t := range q.ibs {
				if t != tag {
					kept = append(kept, t)
				}
			}
			if len(kept) != len(q.ibs) {
				b, _ := json.Marshal(kept)
				s.db.Exec(`UPDATE squads SET inbounds=? WHERE id=?`, string(b), q.id)
			}
		}
	}
	// client overrides
	rows2, err := s.db.Query(`SELECT email,protocols FROM clients WHERE protocols!=''`)
	if err == nil {
		type cp struct {
			email string
			tags  []string
		}
		var list []cp
		for rows2.Next() {
			var email, raw string
			rows2.Scan(&email, &raw)
			var tags []string
			json.Unmarshal([]byte(raw), &tags)
			list = append(list, cp{email, tags})
		}
		rows2.Close()
		for _, c := range list {
			var kept []string
			for _, t := range c.tags {
				if t != tag {
					kept = append(kept, t)
				}
			}
			if len(kept) != len(c.tags) {
				raw := ""
				if len(kept) > 0 {
					b, _ := json.Marshal(kept)
					raw = string(b)
				}
				s.db.Exec(`UPDATE clients SET protocols=? WHERE email=?`, raw, c.email)
			}
		}
	}
}

// InboundAutoAdd — флаг auto_add протокола (новый добавляется всем по умолчанию).
func (s *Store) InboundAutoAdd(tag string) bool {
	var n int
	s.db.QueryRow(`SELECT auto_add FROM inbounds WHERE tag=?`, tag).Scan(&n)
	return n == 1
}

func (s *Store) SetInboundAutoAdd(tag string, v bool) {
	n := 0
	if v {
		n = 1
	}
	s.db.Exec(`UPDATE inbounds SET auto_add=? WHERE tag=?`, n, tag)
}

// SquadAutoAdd — флаг auto_add группы (новые auto_add-протоколы добавляются в набор).
func (s *Store) SquadAutoAdd(id string) bool {
	var n int
	s.db.QueryRow(`SELECT auto_add FROM squads WHERE id=?`, id).Scan(&n)
	return n == 1
}

// AddProtocolToAutoAddSquads — добавить новый auto_add-протокол во все группы с auto_add=1.
func (s *Store) AddProtocolToAutoAddSquads(tag string) {
	rows, err := s.db.Query(`SELECT id,inbounds FROM squads WHERE auto_add=1`)
	if err != nil {
		return
	}
	defer rows.Close()
	type sq struct {
		id  string
		ibs []string
	}
	var list []sq
	for rows.Next() {
		var id, raw string
		rows.Scan(&id, &raw)
		var ibs []string
		json.Unmarshal([]byte(raw), &ibs)
		list = append(list, sq{id, ibs})
	}
	for _, q := range list {
		found := false
		for _, t := range q.ibs {
			if t == tag {
				found = true
			}
		}
		if !found {
			q.ibs = append(q.ibs, tag)
			b, _ := json.Marshal(q.ibs)
			s.db.Exec(`UPDATE squads SET inbounds=? WHERE id=?`, string(b), q.id)
		}
	}
}