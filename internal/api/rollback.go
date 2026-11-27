package api

// rollback.go — откат разрушающих действий (цепочка за 24ч).
// УРОК (владелец): только разрушающие (удаление протокола/клиента/ноды, смена транспорта,
// регенерация ключей, смена версии AWG). Кнопка отката в модалке событий.
// Snapshot before сохраняется в events.meta.rollback JSON.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
)

// RollbackSnapshot — состояние сущности ДО разрушающего действия.
type RollbackSnapshot struct {
	Entity string         `json:"entity"` // "inbound" | "client" | "node" | "awg"
	ID     string         `json:"id"`     // tag / email / nodeID
	Action string         `json:"action"` // "delete" | "update" | "regen_keys" | "retunnel" | "awg_version"
	Before map[string]any `json:"before"` // полное состояние сущности до изменения
}

// AddEventWithRollback — событие + snapshot для отката.
func (s *Server) AddEventWithRollback(kind, severity, message string, snap RollbackSnapshot) {
	meta := map[string]any{"rollback": snap}
	b, _ := json.Marshal(meta)
	s.store.AddEvent(kind, severity, message, string(b))
}

// GET /api/events/rollback — события за 24ч с кнопками отката.
func (s *Server) eventsRollback(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour).Unix()
	rows, err := s.store.DB().Query(`SELECT id,ts,kind,severity,message,meta FROM events WHERE ts>? ORDER BY ts DESC LIMIT 100`, since)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, ts int64
		var kind, sev, msg, meta string
		rows.Scan(&id, &ts, &kind, &sev, &msg, &meta)
		ev := map[string]any{"id": id, "ts": ts, "kind": kind, "severity": sev, "message": msg}
		var m map[string]any
		if json.Unmarshal([]byte(meta), &m) == nil {
			if rb, ok := m["rollback"]; ok {
				ev["rollback"] = rb
			}
		}
		out = append(out, ev)
	}
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, out)
}

// POST /api/events/rollback {id} — откатить событие (и цепочку более новых для той же сущности).
func (s *Server) rollbackEvent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == 0 {
		http.Error(w, "id обязателен", 400)
		return
	}
	// получу событие
	var ts int64
	var kind, msg, meta string
	err := s.store.DB().QueryRow(`SELECT ts,kind,message,meta FROM events WHERE id=?`, body.ID).Scan(&ts, &kind, &msg, &meta)
	if err != nil {
		http.Error(w, "событие не найдено", 404)
		return
	}
	var m map[string]any
	if json.Unmarshal([]byte(meta), &m) != nil {
		http.Error(w, "нет snapshot для отката", 400)
		return
	}
	rbRaw, ok := m["rollback"]
	if !ok {
		http.Error(w, "нет snapshot для отката", 400)
		return
	}
	rbBytes, _ := json.Marshal(rbRaw)
	var snap RollbackSnapshot
	if json.Unmarshal(rbBytes, &snap) != nil {
		http.Error(w, "невалидный snapshot", 400)
		return
	}
	// цепочка: найду все более новые события с rollback для той же сущности
	chain := []RollbackSnapshot{snap}
	rows, err := s.store.DB().Query(`SELECT meta FROM events WHERE ts>? AND id!=? ORDER BY ts DESC`, ts, body.ID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var mt string
			rows.Scan(&mt)
			var mm map[string]any
			if json.Unmarshal([]byte(mt), &mm) == nil {
				if rb2, ok := mm["rollback"]; ok {
					b2, _ := json.Marshal(rb2)
					var s2 RollbackSnapshot
					if json.Unmarshal(b2, &s2) == nil && s2.Entity == snap.Entity && s2.ID == snap.ID {
						chain = append(chain, s2)
					}
				}
			}
		}
	}
	// применяю откат (самый старый snapshot = целевое состояние)
	target := chain[len(chain)-1]
	if err := s.applyRollback(target); err != nil {
		http.Error(w, "откат: "+err.Error(), 500)
		return
	}
	s.store.AddEvent("rollback", "ok", fmt.Sprintf("откат: %s %s (%s) → состояние до %s, отменено изменений: %d", snap.Entity, snap.ID, snap.Action, time.Unix(ts, 0).Format("15:04"), len(chain)), "{}")
	writeJSON(w, map[string]any{"ok": true, "reverted": len(chain)})
}

// applyRollback — восстанавливает сущность из snapshot.
func (s *Server) applyRollback(snap RollbackSnapshot) error {
	switch snap.Entity {
	case "inbound":
		return s.rollbackInbound(snap)
	case "client":
		return s.rollbackClient(snap)
	case "node":
		return s.rollbackNode(snap)
	case "awg":
		return s.rollbackAWG(snap)
	default:
		return fmt.Errorf("неизвестная сущность: %s", snap.Entity)
	}
}

func (s *Server) rollbackInbound(snap RollbackSnapshot) error {
	b := snap.Before
	tag, _ := b["tag"].(string)
	if tag == "" {
		return fmt.Errorf("нет tag в snapshot")
	}
	if snap.Action == "delete" {
		// восстановление удалённого inbound
		ib := store.Inbound{
			Tag:      tag,
			Protocol: str(b["protocol"]),
			Port:     int(num(b["port"])),
			Network:  str(b["network"]),
			Security: str(b["security"]),
			Settings: str(b["settings"]),
			Stream:   str(b["stream"]),
			Enabled:  boolVal(b["enabled"]),
			Hidden:   boolVal(b["hidden"]),
		}
		if err := s.store.UpsertInbound(ib); err != nil {
			return err
		}
		s.RestoreInbounds()
		s.syncFirewall()
		return nil
	}
	// update: восстановлю settings/stream/port/network/security
	ib, _ := s.store.GetInbound(tag)
	if ib == nil {
		return fmt.Errorf("inbound %s не найден", tag)
	}
	if v, ok := b["settings"]; ok {
		ib.Settings = str(v)
	}
	if v, ok := b["stream"]; ok {
		ib.Stream = str(v)
	}
	if v, ok := b["port"]; ok {
		ib.Port = int(num(v))
	}
	if v, ok := b["network"]; ok {
		ib.Network = str(v)
	}
	if v, ok := b["security"]; ok {
		ib.Security = str(v)
	}
	if err := s.store.UpsertInbound(*ib); err != nil {
		return err
	}
	s.RestoreInbounds()
	s.syncFirewall()
	return nil
}

func (s *Server) rollbackClient(snap RollbackSnapshot) error {
	b := snap.Before
	email, _ := b["email"].(string)
	if email == "" {
		return fmt.Errorf("нет email в snapshot")
	}
	if snap.Action == "delete" {
		cl := store.Client{
			Email:   email,
			UUID:    str(b["uuid"]),
			Name:    str(b["name"]),
			SubID:   str(b["sub_id"]),
			Country: str(b["country"]),
			CountryCode: uint32(num(b["country_code"])),
			Enabled: boolVal(b["enabled"]),
			QuotaBytes: int64(num(b["quota_bytes"])),
			Expiry:  int64(num(b["expiry"])),
		}
		if err := s.store.UpsertClient(cl); err != nil {
			return err
		}
		s.RestoreInbounds()
		return nil
	}
	cl, _ := s.store.GetClient(email)
	if cl == nil {
		return fmt.Errorf("клиент %s не найден", email)
	}
	if v, ok := b["country"]; ok {
		cl.Country = str(v)
	}
	if v, ok := b["enabled"]; ok {
		cl.Enabled = boolVal(v)
	}
	if v, ok := b["quota_bytes"]; ok {
		cl.QuotaBytes = int64(num(v))
	}
	if v, ok := b["expiry"]; ok {
		cl.Expiry = int64(num(v))
	}
	return s.store.UpsertClient(*cl)
}

func (s *Server) rollbackNode(snap RollbackSnapshot) error {
	b := snap.Before
	id, _ := b["id"].(string)
	if id == "" {
		return fmt.Errorf("нет id в snapshot")
	}
	n := s.getNode(id)
	if n == nil {
		return fmt.Errorf("нода %s не найдена", id)
	}
	if v, ok := b["tunnel"]; ok {
		n.Tunnel = str(v)
	}
	if v, ok := b["tunnel_cfg"]; ok {
		n.TunnelCfg = str(v)
	}
	if v, ok := b["country"]; ok {
		n.Country = str(v)
	}
	if v, ok := b["enabled"]; ok {
		n.Enabled = boolVal(v)
	}
	if err := s.store.UpsertNode(*n); err != nil {
		return err
	}
	if s.ctrl != nil {
		s.ctrl.SyncRulesNow(context.Background())
	}
	return nil
}

func (s *Server) rollbackAWG(snap RollbackSnapshot) error {
	b := snap.Before
	cfg, err := s.store.GetAWGServer()
	if err != nil {
		return err
	}
	if v, ok := b["params"]; ok {
		cfg.Params = str(v)
	}
	if v, ok := b["enabled"]; ok {
		cfg.Enabled = boolVal(v)
	}
	return s.store.SaveAWGServer(*cfg)
}

// helpers
func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func num(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		f, _ := strconv.ParseFloat(n, 64)
		return f
	}
	return 0
}
func boolVal(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}