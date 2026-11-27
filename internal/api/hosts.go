package api

import (
	"encoding/json"
	"net/http"

	"github.com/kambarro/xkit-panel/internal/store"
)

// Точки входа мастера (P1 #10, hosts/CDN-фронтинг).
// GET/POST /api/hosts, POST /api/hosts/delete.

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.store.AllMasterHosts()
	if err != nil { http.Error(w, err.Error(), 500); return }
	if hosts == nil { hosts = []store.MasterHost{} }
	writeJSON(w, hosts)
}

func (s *Server) addHost(w http.ResponseWriter, r *http.Request) {
	var h store.MasterHost
	if err := json.NewDecoder(r.Body).Decode(&h); err != nil || h.Address == "" {
		http.Error(w, "address required", 400); return
	}
	h.Enabled = true
	id, err := s.store.AddMasterHost(h)
	if err != nil { http.Error(w, err.Error(), 500); return }
	h.ID = int(id)
	s.store.AddEvent("hosts", "ok", "точка входа "+h.Address+" добавлена", "{}")
	writeJSON(w, map[string]any{"ok": true, "host": h})
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	var body struct{ ID int `json:"id"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == 0 {
		http.Error(w, "id required", 400); return
	}
	if err := s.store.DeleteMasterHost(body.ID); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("hosts", "ok", "точка входа удалена", "{}")
	writeJSON(w, map[string]any{"ok": true})
}