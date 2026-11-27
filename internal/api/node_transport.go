package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/tunnel"
)

// POST /api/nodes/transport {id, transport} — сменить каскадный транспорт СУЩЕСТВУЮЩЕЙ ноды
// без пересоздания. Перегенерирует inbound ноды + outbound мастера, горячо.
// Поддерживает весь кит xray: tcp-reality/xhttp-reality/ws-tls/grpc-tls/hysteria2.
// УРОК (владелец): «на нодах также должны ставиться протоколы... потом тестировать тунели».
func (s *Server) changeNodeTransport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID        string `json:"id"`
		Transport string `json:"transport"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" || req.Transport == "" {
		http.Error(w, "id и transport обязательны", 400)
		return
	}
	// нормализуем транспорт
	tr := tunnel.TCPReality
	switch req.Transport {
	case "xhttp", "xhttp-reality":
		tr = tunnel.XHTTPReality
	case "ws", "ws-tls":
		tr = tunnel.WSTLS
	case "grpc", "grpc-tls":
		tr = tunnel.GRPCTLS
	case "hysteria2", "hy2":
		tr = tunnel.Hysteria2
	case "reality", "tcp", "tcp-reality":
		tr = tunnel.TCPReality
	default:
		http.Error(w, "неизвестный транспорт: "+req.Transport, 400)
		return
	}
	// survey транспортов этой ноды уже крутится — смена транспорта сломает замеры
	if surveyRunning(req.ID) {
		http.Error(w, "идёт survey транспортов ноды — дождитесь завершения", 409)
		return
	}
	if err := s.applyTransport(req.ID, tr); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.store.AddEvent("node_transport", "ok", fmt.Sprintf("нода %s: транспорт → %s", req.ID, tr), fmt.Sprintf(`{"node":%q}`, req.ID))
	writeJSON(w, map[string]any{"ok": true, "id": req.ID, "transport": string(tr)})
}

// applyTransport — переиспользуемое ядро смены каскадного транспорта (HTTP-хендлер
// и survey транспортов вызывают один код-путь). Применяет кандидат на ОБА конца:
// inbound ноды (агент с валидацией+откатом, SSH-fallback) + outbound мастера,
// обновляет nodes.tunnel/tunnel_cfg, открывает порт на ноде. Ключи транспортов
// генерируются заново (как при ручной смене); для ВОССТАНОВления оригинала survey
// использует paramsFromCfg + applyTunnelBothEnds (без перегенерации).
func (s *Server) applyTransport(nodeID string, tr tunnel.Transport) error {
	var host string
	var port int
	var tunnelCfg string
	if err := s.store.DB().QueryRow(`SELECT host,port,tunnel_cfg FROM nodes WHERE id=?`, nodeID).Scan(&host, &port, &tunnelCfg); err != nil {
		return fmt.Errorf("нода не найдена")
	}
	// разберём существующий tunnel_cfg (uuid/sni/pub/sid)
	var tc map[string]any
	json.Unmarshal([]byte(tunnelCfg), &tc)
	uuid, _ := tc["uuid"].(string)
	sni, _ := tc["sni"].(string)
	if sni == "" {
		sni = host
	}
	if uuid == "" {
		uuid = randHex(8) + "-" + randHex(4) + "-4" + randHex(3) + "-8" + randHex(3) + "-" + randHex(12)
	}
	tp := tunnel.Params{Transport: tr, Host: host, Port: port, UUID: uuid, SNI: sni, MTU: s.store.NodeMTU(nodeID)}
	// REALITY: перегенерим ключи (новый транспорт — новые ключи)
	if tr == tunnel.TCPReality || tr == tunnel.XHTTPReality {
		priv, pub, err := genRealityKeys()
		if err != nil {
			return fmt.Errorf("reality keys: %w", err)
		}
		tp.PrivateKey, tp.PublicKey, tp.ShortID = priv, pub, randHex(4)
	}
	// TLS транспорты: серт ноды (LE от домена ноды)
	if tr == tunnel.WSTLS || tr == tunnel.GRPCTLS || tr == tunnel.Hysteria2 {
		tp.TLSCert = "/etc/letsencrypt/live/" + sni + "/fullchain.pem"
		tp.TLSKey = "/etc/letsencrypt/live/" + sni + "/privkey.pem"
	}
	if tr == tunnel.Hysteria2 {
		tp.Hy2Pass = randHex(16)
		tp.Hy2Obfs = randHex(8)
	}
	// 1) новый inbound ноды
	nodeIB, err := tp.NodeInbound()
	if err != nil {
		return fmt.Errorf("tunnel config: %w", err)
	}
	nodeCfgMap := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"dns":       ipv4OnlyDNS(), // аудит #10: IPv6 ноды мёртв — только A-записи
		"inbounds":  []any{nodeIB},
		"outbounds": []any{freedomIPv4("direct"), map[string]any{"tag": "blackhole", "protocol": "blackhole"}},
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "port": "0-65535", "outboundTag": "direct"}}},
	}
	nodeCfgBytes, _ := json.MarshalIndent(nodeCfgMap, "", "  ")
	// единая доставка через агента (валидация+откат), SSH-fallback. Директива: единообразно.
	if err := s.deliverNodeConfig(nodeID, host, string(nodeCfgBytes)); err != nil {
		return fmt.Errorf("нода: конфиг не применился: %w", err)
	}
	s.store.SetNodeLastGoodCfg(nodeID, string(nodeCfgBytes))
	key := nodeSSHKey()
	sshArgs := []string{"-i", key, "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/var/lib/xkit-panel/known_hosts", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=15", "root@" + host}
	// 2) обновим tunnel_cfg в БД
	newTC := map[string]any{"publicKey": tp.PublicKey, "privateKey": tp.PrivateKey, "shortId": tp.ShortID, "sni": sni, "uuid": uuid, "transport": string(tr)}
	if tr == tunnel.Hysteria2 {
		newTC["hy2Pass"] = tp.Hy2Pass
		newTC["hy2Obfs"] = tp.Hy2Obfs
	}
	tcBytes, _ := json.Marshal(newTC)
	s.store.DB().Exec(`UPDATE nodes SET tunnel=?, tunnel_cfg=?, health='alive' WHERE id=?`, string(tr), string(tcBytes), nodeID)
	// 3) заменим outbound мастера (удалить старый + добавить новый)
	s.replaceMasterOutbound(nodeID, tp)
	// 4) firewall ноды: порт мог сменить протокол (hysteria2=udp)
	nodeProto := "tcp"
	if tr == tunnel.Hysteria2 {
		nodeProto = "udp"
	}
	fwCmd := fmt.Sprintf("ufw allow %d/%s comment 'XKIT:node-tunnel' >/dev/null 2>&1; echo OK", port, nodeProto)
	exec.Command("ssh", append(sshArgs, fwCmd)...).Run()
	s.syncFirewall()
	return nil
}

// replaceMasterOutbound — удалить старый outbound ноды + добавить новый (горячо через рестарт).
func (s *Server) replaceMasterOutbound(nodeID string, tp tunnel.Params) {
	cfgPath := "/usr/local/etc/xray/config.json"
	out, err := os.ReadFile(cfgPath)
	if err != nil {
		return
	}
	var cfg map[string]any
	if json.Unmarshal(out, &cfg) != nil {
		return
	}
	ob, _ := cfg["outbounds"].([]any)
	// удаляем старый outbound с tag=nodeID
	var filtered []any
	for _, o := range ob {
		if m, ok := o.(map[string]any); ok {
			if m["tag"] == nodeID {
				continue
			}
		}
		filtered = append(filtered, o)
	}
	mob, err := tp.MasterOutbound(nodeID)
	if err != nil {
		s.store.AddEvent("node_transport", "error", "outbound config: "+err.Error(), "{}")
		return
	}
	filtered = append(filtered, mob)
	cfg["outbounds"] = filtered
	// УРОК (QA BUG#23): config-файл не отражает gRPC AddUser — клиенты теряются при
	// перезаписи файла + рестарте. Пересобираем clients всех user-inbound из БД (effective set).
	s.rebuildConfigClients(cfg)
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(cfgPath, data, 0644)
	exec.Command("systemctl", "restart", "xray").Run()
	time.Sleep(2 * time.Second)
	if s.xray != nil {
		if err := s.xray.Reconnect(); err == nil && s.ctrl != nil {
			s.ctrl.SyncRulesNow(context.Background())
		}
	}
	go s.RestoreInbounds() // восстановить горячие preset-inbound после рестарта
	s.store.AddEvent("node_transport", "ok", fmt.Sprintf("outbound %s (%s) обновлён на мастер", nodeID, tp.Transport), "{}")
}

// rebuildConfigClients — пересобирает settings.clients всех user-inbound в config-файле
// из БД (effective set). УРОК (QA): gRPC AddUser не персистится в файл — при перезаписи
// config + рестарте клиенты терялись ("invalid request user id").
func (s *Server) rebuildConfigClients(cfg map[string]any) {
	ibs, _ := s.store.AllInbounds()
	clients, _ := s.store.EnabledClients()
	inbounds, _ := cfg["inbounds"].([]any)
	for _, ibRaw := range inbounds {
		ib, ok := ibRaw.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := ib["tag"].(string)
		var spec *storeInbound
		for i := range ibs {
			if ibs[i].Tag == tag {
				spec = &ibs[i]
				break
			}
		}
		if spec == nil || !userProto(spec.Protocol) {
			continue
		}
		var cls []any
		for _, cl := range clients {
			if !s.store.ProtocolAllowed(cl.Email, tag) {
				continue
			}
			c := map[string]any{"email": cl.Email}
			switch spec.Protocol {
			case "vless":
				c["id"] = cl.UUID
				if (spec.Network == "tcp" || spec.Network == "") && (spec.Security == "reality" || spec.Security == "tls") {
					c["flow"] = "xtls-rprx-vision"
				}
			case "trojan":
				c["password"] = cl.UUID
			case "vmess":
				c["id"] = cl.UUID
			case "hysteria2", "hysteria":
				// УРОК (аудит #2): hy2 clients = {auth,email} (account.Auth), не id
				c["auth"] = cl.UUID
			}
			cls = append(cls, c)
		}
		if cls == nil {
			cls = []any{}
		}
		if settings, ok := ib["settings"].(map[string]any); ok {
			settings["clients"] = cls
		}
	}
}

type storeInbound = store.Inbound
