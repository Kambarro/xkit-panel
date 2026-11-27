package api

// retunnel.go — смена транспорта туннеля существующей ноды БЕЗ удаления.
// УРОК (владелец): «не вижу где проверить транспорт до нод и выбрать подходящий».
// Панель пере-провижнит ноду по SSH-ключу (пароль не нужен — ключ уже стоит),
// обновит tunnel/tunnel_cfg, пересоберёт outbound мастера и пересинхронизирует
// маршруты клиентов. Клиенты НЕ пересоздаются (UUID/подписи те же).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// POST /api/nodes/retunnel {id, tunnel} — сменить транспорт ноды.
func (s *Server) nodeRetunnel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID     string `json:"id"`
		Tunnel string `json:"tunnel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" || body.Tunnel == "" {
		http.Error(w, "id и tunnel обязательны", 400)
		return
	}
	valid := map[string]bool{"xhttp-reality": true, "reality": true, "ws-tls": true, "grpc-tls": true, "hysteria2": true}
	if !valid[body.Tunnel] {
		http.Error(w, "неизвестный транспорт: "+body.Tunnel, 400)
		return
	}
	n := s.getNode(body.ID)
	if n == nil {
		http.Error(w, "нода не найдена", 404)
		return
	}
	if strings.EqualFold(n.Tunnel, body.Tunnel) {
		writeJSON(w, map[string]any{"ok": true, "unchanged": true})
		return
	}
	// SSH-ключ панели должен быть установлен (нода уже провижнена)
	keyPath := "/var/lib/xkit-panel/node_key"
	if !fileExists(keyPath) {
		http.Error(w, "SSH-ключ панели не найден — нода не управляема", 400)
		return
	}
	oldTunnel := n.Tunnel
	s.AddEventWithRollback("node_retunnel", "info", fmt.Sprintf("%s: смена транспорта %s → %s (пере-провижн по ключу)", n.Name, oldTunnel, body.Tunnel), RollbackSnapshot{
		Entity: "node", ID: n.ID, Action: "retunnel",
		Before: map[string]any{"id": n.ID, "tunnel": n.Tunnel, "tunnel_cfg": n.TunnelCfg, "country": n.Country, "enabled": n.Enabled},
	})
	// пере-провижн: provisionNode сам обновит tunnel/tunnel_cfg/health в БД
	go func() {
		s.provisionNode(n.ID, n.Name, n.Country, n.Host, n.Port, body.Tunnel, "root", "", keyPath, n.CountryCode)
		// после провижна — маршруты (addMasterOutbound уже пересобрал outbound + SyncRulesNow)
		if s.ctrl != nil {
			s.ctrl.SyncRulesNow(context.Background())
		}
		s.store.AddEvent("node_retunnel", "ok", fmt.Sprintf("%s: транспорт сменён на %s", n.Name, body.Tunnel), "{}")
	}()
	writeJSON(w, map[string]any{"ok": true, "started": true, "from": oldTunnel, "to": body.Tunnel})
}