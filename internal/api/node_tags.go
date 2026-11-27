package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"
)

func nowUnix() int64 { return time.Now().Unix() }

// Теги нод + bulk-операции (P1 #13, 3x-ui group tags / bulk expired).
// POST /api/nodes/tags {id, tags}, /api/nodes/bulk-delete {ids[]},
// /api/nodes/bulk-enable {ids[], enabled}, /api/nodes/by-tag?tag=,
// /api/nodes/delete-expired (удалить ноды с истёкшей арендой).

func (s *Server) setNodeTags(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Tags string `json:"tags"` // CSV: "быстрые,резерв"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "id required", 400); return
	}
	if err := s.store.SetNodeTags(body.ID, body.Tags); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("node", "ok", "теги ноды "+body.ID+": "+body.Tags, "{}")
	writeJSON(w, map[string]any{"ok": true, "id": body.ID, "tags": s.store.NodeTags(body.ID)})
}

func (s *Server) nodesByTag(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("tag")
	nodes, err := s.store.NodesByTag(tag)
	if err != nil { http.Error(w, err.Error(), 500); return }
	type nv struct{ ID, Name, Country, Health string }
	var out []nv
	for _, n := range nodes { out = append(out, nv{n.ID, n.Name, n.Country, n.Health}) }
	if out == nil { out = []nv{} }
	writeJSON(w, out)
}

func (s *Server) bulkDeleteNodes(w http.ResponseWriter, r *http.Request) {
	var body struct{ IDs []string `json:"ids"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.IDs) == 0 {
		http.Error(w, "ids required", 400); return
	}
	// удаляем ноды + их outbounds мастера + назначения
	for _, id := range body.IDs {
		s.removeMasterOutbound(id)
		s.store.DB().Exec(`DELETE FROM assignments WHERE node_id=?`, id)
	}
	n, err := s.store.BulkDeleteNodes(body.IDs)
	if err != nil { http.Error(w, err.Error(), 500); return }
	exec.Command("systemctl", "restart", "xray").Run()
	s.store.AddEvent("node", "ok", fmt.Sprintf("bulk удалено %d нод", n), "{}")
	writeJSON(w, map[string]any{"ok": true, "deleted": n})
}

func (s *Server) bulkEnableNodes(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs     []string `json:"ids"`
		Enabled bool     `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.IDs) == 0 {
		http.Error(w, "ids required", 400); return
	}
	n, err := s.store.SetNodesEnabled(body.IDs, body.Enabled)
	if err != nil { http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("node", "ok", fmt.Sprintf("bulk %d нод enabled=%v", n, body.Enabled), "{}")
	writeJSON(w, map[string]any{"ok": true, "changed": n})
}

func (s *Server) deleteExpiredNodes(w http.ResponseWriter, r *http.Request) {
	expired, err := s.store.ExpiredNodes(nowUnix())
	if err != nil { http.Error(w, err.Error(), 500); return }
	var ids []string
	for _, n := range expired { ids = append(ids, n.ID) }
	if len(ids) == 0 {
		writeJSON(w, map[string]any{"ok": true, "deleted": 0}); return
	}
	for _, id := range ids {
		s.removeMasterOutbound(id)
		s.store.DB().Exec(`DELETE FROM assignments WHERE node_id=?`, id)
	}
	n, _ := s.store.BulkDeleteNodes(ids)
	exec.Command("systemctl", "restart", "xray").Run()
	s.store.AddEvent("node", "ok", fmt.Sprintf("удалено %d истёкших нод", n), "{}")
	writeJSON(w, map[string]any{"ok": true, "deleted": n})
}