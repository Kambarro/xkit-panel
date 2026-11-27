package store

import (
	"sort"
	"strings"
)

// CurrentAssignment — актуальная строка sticky-карты: текущее закрепление
// клиента за нодой (не сырые строки assignments, где живут устаревшие варианты).
type CurrentAssignment struct {
	Email        string
	Country      string // страна назначения (при failover ≠ clients.country)
	NodeID       string
	NodeName     string
	NodeCountry  string
	Status       string
	FailoverFrom string
	Variant      bool // true = явный country-вариант (не базовое закрепление)
}

// CurrentAssignments — ТОЛЬКО актуальные назначения для sticky-карты.
// Семантика assignments: PRIMARY KEY(email,country); строка — «клиент
// назначался на ноду страны country». После смены clients.country старые
// строки остаются (failover их дочинивает лишь частично) — это история, не
// текущее закрепление. Актуальное базовое = строка страны клиента ('' и any
// взаимозаменяемы) — тот же выбор, что делает syncAllRules (fallback list[0]
// если строки страны нет). Явный country-вариант (второе устройство с другой
// страной) показываем дополнительно, только если его нода отличается от
// базовой и жива/включена. Устаревшие варианты (QA-наследие client: ''/any →
// node-us при country=NL) сюда не попадают — БД не чистим.
func (s *Store) CurrentAssignments() ([]CurrentAssignment, error) {
	assigns, err := s.AllAssignments()
	if err != nil { return nil, err }
	// updated_at строк (свежесть варианта относительно базовой)
	updatedAt := map[string]int64{}
	if rows, err := s.db.Query(`SELECT email,country,updated_at FROM assignments`); err == nil {
		for rows.Next() {
			var email, country string
			var ts int64
			if rows.Scan(&email, &country, &ts) == nil { updatedAt[email+"\x00"+country] = ts }
		}
		rows.Close()
	}
	// детерминированный порядок строк: updated_at DESC (первой — самая свежая),
	// затем country — fallback list[0] и выбор ''/any не зависят от порядка БД
	sort.SliceStable(assigns, func(i, j int) bool {
		if assigns[i].Email != assigns[j].Email { return assigns[i].Email < assigns[j].Email }
		ti, tj := updatedAt[assigns[i].Email+"\x00"+assigns[i].Country], updatedAt[assigns[j].Email+"\x00"+assigns[j].Country]
		if ti != tj { return ti > tj }
		return assigns[i].Country < assigns[j].Country
	})
	byEmail := map[string][]Assignment{}
	var order []string
	for _, a := range assigns {
		if _, ok := byEmail[a.Email]; !ok { order = append(order, a.Email) }
		byEmail[a.Email] = append(byEmail[a.Email], a)
	}
	// имя/страна/health ноды одним запросом (MaxOpenConns=1: без вложенных query)
	type ninfo struct{ name, country, health string; enabled bool }
	nodes := map[string]ninfo{}
	rows, err := s.db.Query(`SELECT id,name,country,health,enabled FROM nodes`)
	if err != nil { return nil, err }
	for rows.Next() {
		var id string
		var ni ninfo
		var en int
		if rows.Scan(&id, &ni.name, &ni.country, &ni.health, &en) == nil {
			ni.enabled = en == 1
			nodes[id] = ni
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil { return nil, err }

	var out []CurrentAssignment
	for _, email := range order {
		cl, _ := s.GetClient(email)
		if cl == nil { continue } // клиент удалён — строки-сироты не показываем
		list := byEmail[email]
		// базовое: как в syncAllRules — страна клиента, ''/any взаимозаменяемы
		var base *Assignment
		for i := range list {
			a := &list[i]
			if a.Country == cl.Country { base = a; break }
			if (cl.Country == "" || strings.EqualFold(cl.Country, "any")) && (a.Country == "" || strings.EqualFold(a.Country, "any")) { base = a; break }
		}
		if base == nil { base = &list[0] }
		mk := func(a *Assignment, variant bool) CurrentAssignment {
			ca := CurrentAssignment{Email: email, Country: a.Country, NodeID: a.NodeID,
				Status: a.Status, FailoverFrom: a.FailoverFrom, Variant: variant}
			if n, ok := nodes[a.NodeID]; ok {
				ca.NodeName, ca.NodeCountry = n.name, n.country
			} else {
				ca.NodeName = a.NodeID // нода удалена из БД — показываем id, не теряем строку
			}
			return ca
		}
		out = append(out, mk(base, false))
		// Исключение владельца: ВТОРОЕ УСТРОЙСТВО на явном country-варианте
		// другой ноды показываем дополнительно. Признак актуальности варианта —
		// строка СВЕЖЕЕ базовой (updated_at): после смены страны PushAssignment
		// обновляет базовую строку, устаревшие варианты (QA-мусор ''/any/US у
		// client) остаются СТАРШЕ базы и скрываются. Вариант младше базы =
		// назначен после последнего выбора страны (второе устройство).
		// Дополнительно: нода живая/включена, страна явная, не дубль базовой.
		for i := range list {
			a := &list[i]
			if a == base || a.Country == "" || strings.EqualFold(a.Country, "any") { continue }
			if a.Country == cl.Country || a.NodeID == base.NodeID { continue }
			if n, ok := nodes[a.NodeID]; !ok || !n.enabled || n.health == "down" { continue }
			if updatedAt[a.Email+"\x00"+a.Country] <= updatedAt[base.Email+"\x00"+base.Country] { continue }
			out = append(out, mk(a, true))
		}
	}
	return out, nil
}
