package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kambarro/xkit-panel/internal/tunnel"
)

// Структурированный редактор каскадного туннеля ноды (продвинутый режим).
// УРОК владельца: «поля» (без сырого JSON для каскада), синхронизация ОБЕИХ сторон.
// Каскад = парные настройки (inbound ноды ↔ outbound мастера): правим ОДНИМ экраном,
// применяем на ОБА конца атомарно, откат при провале. Сырой JSON каскада = рассинхрон → нет.

// GET /api/nodes/tunnel?id — текущие параметры туннеля для формы.
func (s *Server) getNodeTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id обязателен", 400)
		return
	}
	var host, tr, tunnelCfg string
	var port int
	if err := s.store.DB().QueryRow(`SELECT host,port,tunnel,tunnel_cfg FROM nodes WHERE id=?`, id).Scan(&host, &port, &tr, &tunnelCfg); err != nil {
		http.Error(w, "нода не найдена", 404)
		return
	}
	var tc map[string]any
	json.Unmarshal([]byte(tunnelCfg), &tc)
	str := func(k string) string { v, _ := tc[k].(string); return v }
	sni := str("sni")
	if sni == "" {
		sni = host
	}
	// нормализуем legacy-алиасы для UI-флагов
	switch tr {
	case "reality", "tcp":
		tr = "tcp-reality"
	case "xhttp":
		tr = "xhttp-reality"
	case "ws":
		tr = "ws-tls"
	case "grpc":
		tr = "grpc-tls"
	case "hy2":
		tr = "hysteria2"
	}
	writeJSON(w, map[string]any{
		"id": id, "host": host, "transport": tr, "port": port,
		"sni": sni, "path": str("path"), "service_name": str("serviceName"),
		"public_key": str("publicKey"), "short_id": str("shortId"),
		"mtu": s.store.NodeMTU(id), "uuid": str("uuid"),
		"is_reality": tr == "tcp-reality" || tr == "xhttp-reality",
		"is_tls":     tr == "ws-tls" || tr == "grpc-tls" || tr == "hysteria2",
		"is_ws":      tr == "ws-tls" || tr == "xhttp-reality", "is_grpc": tr == "grpc-tls",
	})
}

// POST /api/nodes/tunnel/update {id, port, sni, path, service_name, regen_keys} —
// редактировать поля туннеля. Применяет на ОБА конца атомарно, откат при провале.
// Транспорт НЕ меняется здесь (для этого /api/nodes/transport). Ключи REALITY — regen опц.
func (s *Server) updateNodeTunnel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID          string `json:"id"`
		Port        int    `json:"port"`
		SNI         string `json:"sni"`
		Path        string `json:"path"`
		ServiceName string `json:"service_name"`
		RegenKeys   bool   `json:"regen_keys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "id обязателен", 400)
		return
	}
	var host, tr, tunnelCfg string
	var port int
	if err := s.store.DB().QueryRow(`SELECT host,port,tunnel,tunnel_cfg FROM nodes WHERE id=?`, body.ID).Scan(&host, &port, &tr, &tunnelCfg); err != nil {
		http.Error(w, "нода не найдена", 404)
		return
	}
	if tr == "" || tr == "awg" {
		http.Error(w, "нода не на xray-каскаде (AWG — отдельный механизм)", 400)
		return
	}
	if surveyRunning(body.ID) {
		http.Error(w, "идёт survey транспортов ноды — дождитесь завершения", 409)
		return
	}
	tp := s.paramsFromCfg(tr, host, port, tunnelCfg)
	// применим правки полей
	if body.Port != 0 {
		if body.Port < 1 || body.Port > 65535 {
			http.Error(w, "port 1..65535", 400)
			return
		}
		tp.Port = body.Port
	}
	// SEC-04: SNI/path/serviceName попадают в конфиг и shell на ноде —
	// только безопасные символы (анти-инъекция через heredoc/кавычки).
	if body.SNI != "" {
		if !validTunnelField(body.SNI) {
			http.Error(w, "sni: допустимы A-Za-z0-9._:/-", 400)
			return
		}
		tp.SNI = body.SNI
	}
	if body.Path != "" {
		if !validTunnelField(body.Path) {
			http.Error(w, "path: допустимы A-Za-z0-9._:/-", 400)
			return
		}
		tp.Path = body.Path
	}
	if body.ServiceName != "" {
		if !validTunnelField(body.ServiceName) {
			http.Error(w, "service_name: допустимы A-Za-z0-9._:/-", 400)
			return
		}
		tp.ServiceName = body.ServiceName
	}
	// REALITY: regen ключей опционально
	if body.RegenKeys && (tp.Transport == tunnel.TCPReality || tp.Transport == tunnel.XHTTPReality) {
		priv, pub, err := genRealityKeys()
		if err != nil {
			http.Error(w, "reality keys: "+err.Error(), 500)
			return
		}
		tp.PrivateKey, tp.PublicKey, tp.ShortID = priv, pub, randHex(4)
	}
	tp.MTU = s.store.NodeMTU(body.ID)
	// атомарно на оба конца + откат
	if err := s.applyTunnelBothEnds(body.ID, host, tp); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// сохраним обновлённый tunnel_cfg + порт в БД
	newTC := map[string]any{"publicKey": tp.PublicKey, "privateKey": tp.PrivateKey, "shortId": tp.ShortID,
		"sni": tp.SNI, "uuid": tp.UUID, "transport": string(tp.Transport), "path": tp.Path, "serviceName": tp.ServiceName}
	if tp.Transport == tunnel.Hysteria2 {
		newTC["hy2Pass"] = tp.Hy2Pass
		newTC["hy2Obfs"] = tp.Hy2Obfs
	}
	tcBytes, _ := json.Marshal(newTC)
	s.store.DB().Exec(`UPDATE nodes SET port=?, tunnel_cfg=?, health='alive' WHERE id=?`, tp.Port, string(tcBytes), body.ID)
	// firewall ноды: порт мог измениться
	nodeProto := "tcp"
	if tp.Transport == tunnel.Hysteria2 {
		nodeProto = "udp"
	}
	s.sshToNode(host, fmt.Sprintf("ufw allow %d/%s comment 'XKIT:node-tunnel' >/dev/null 2>&1; echo OK", tp.Port, nodeProto))
	s.syncFirewall()
	s.store.AddEvent("node_tunnel", "ok", fmt.Sprintf("нода %s: туннель отредактирован (порт %d)", body.ID, tp.Port), fmt.Sprintf(`{"node":%q}`, body.ID))
	writeJSON(w, map[string]any{"ok": true, "id": body.ID, "port": tp.Port})
}
