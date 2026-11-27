package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kambarro/xkit-panel/internal/amnezia"
	"github.com/kambarro/xkit-panel/internal/store"
)

// AWG-каскад мастер→нода. Нода поднимает AWG-сервер (через агента), мастер — AWG-клиент
// (userspace netstack, без TUN/root) + локальный SOCKS5 для форвардинга трафика в туннель.
// Xray outbound мастера → socks5://127.0.0.1:<port> → AWG-туннель → нода → интернет.

type awgCascade struct {
	mu         sync.Mutex
	client     *amnezia.Client
	socksLn    net.Listener
	socksPort  int
	nodeID     string
	nodePub    string
	nodePort   int
	params     amnezia.AWGParams
	masterPriv string
	masterPub  string
	masterIP   string
	subnet     string
	running    bool
}

var (
	cascadesMu sync.Mutex
	cascades   = map[string]*awgCascade{} // nodeID → cascade
)

// POST /api/nodes/awg-cascade {id, action:start|stop, port} — поднять/остановить AWG-каскад.
func (s *Server) awgCascadeHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string `json:"id"`
		Action string `json:"action"`
		Port   int    `json:"port"` // UDP порт AWG на ноде (0=51821)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "id обязателен", 400)
		return
	}
	var host string
	if err := s.store.DB().QueryRow(`SELECT host FROM nodes WHERE id=?`, req.ID).Scan(&host); err != nil {
		http.Error(w, "нода не найдена", 404)
		return
	}
	if surveyRunning(req.ID) {
		http.Error(w, "идёт survey транспортов ноды — дождитесь завершения", 409)
		return
	}
	switch req.Action {
	case "stop":
		s.stopAWGCascade(req.ID)
		s.store.DeleteAWGCascade(req.ID)    // явный стоп → убрать персист (не восстановится при рестарте)
		s.restoreMasterOutboundXray(req.ID) // outbound мастера обратно к xray-транспорту ноды
		writeJSON(w, map[string]any{"ok": true, "running": false})
	case "start", "":
		c, err := s.startAWGCascade(req.ID, host, req.Port)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "running": true, "node_id": req.ID,
			"socks_port": c.socksPort, "awg_port": c.nodePort, "node_pub": c.nodePub, "master_ip": c.masterIP})
	default:
		http.Error(w, "action: start|stop", 400)
	}
}

// GET /api/nodes/awg-cascade/test?id&addr — прямой TCP dial через каскад (диагностика).
func (s *Server) awgCascadeTest(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	addr := r.URL.Query().Get("addr")
	if addr == "" {
		addr = "1.1.1.1:80"
	}
	cascadesMu.Lock()
	c := cascades[id]
	cascadesMu.Unlock()
	if c == nil {
		http.Error(w, "каскад не запущен", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := c.client.DialContext(ctx, "tcp", addr)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error(), "ms": time.Since(start).Milliseconds()})
		return
	}
	defer conn.Close()
	// шлём HTTP GET
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", addr)
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	writeJSON(w, map[string]any{"ok": true, "ms": time.Since(start).Milliseconds(), "response": string(buf[:n])})
}

// GET /api/nodes/awg-cascade?id — статус каскада.
func (s *Server) awgCascadeStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	cascadesMu.Lock()
	c := cascades[id]
	cascadesMu.Unlock()
	if c == nil {
		writeJSON(w, map[string]any{"running": false})
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	writeJSON(w, map[string]any{"running": c.running, "socks_port": c.socksPort, "awg_port": c.nodePort, "node_pub": c.nodePub, "master_ip": c.masterIP, "client_uapi": c.client.UAPI()})
}

func (s *Server) startAWGCascade(nodeID, host string, awgPort int) (*awgCascade, error) {
	if awgPort == 0 {
		awgPort = 51821
	}
	// остановим старый если есть
	s.stopAWGCascade(nodeID)
	// ключи мастера-клиента
	mPriv, mPub, err := amnezia.GenKeyPair()
	if err != nil {
		return nil, fmt.Errorf("master keygen: %w", err)
	}
	params, err := amnezia.GenParams()
	if err != nil {
		return nil, fmt.Errorf("params: %w", err)
	}
	// MTU каскада ноды (0 → глобальный дефолт). УРОК владельца: регулировка MTU каскада.
	// params.MTU используется ОБЕМЯ концами (нода-сервер TUN + мастер-клиент netstack).
	params.MTU = s.store.NodeMTU(nodeID)
	subnet := "10.9.0.0/24"
	masterIP := "10.9.0.2"
	// 1) нода: поднять AWG-сервер через агента (POST /tunnel start)
	cfg := map[string]any{
		"port": awgPort, "subnet": subnet, "iface": "awg-cascade",
		"params": params, "master_pub": mPub, "master_ip": masterIP,
	}
	cfgBytes, _ := json.Marshal(cfg)
	body := fmt.Sprintf(`{"action":"start","config":%s}`, cfgBytes)
	token := s.agentToken(nodeID)
	remote := fmt.Sprintf("curl -s --max-time 20 -X POST -H 'X-Agent-Token: %s' -H 'Content-Type: application/json' -d '%s' http://127.0.0.1:9101/tunnel", token, body)
	out, err := s.sshToNode(host, remote)
	if err != nil {
		return nil, fmt.Errorf("нода AWG start: %v: %s", err, out)
	}
	var nodeResp map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &nodeResp) != nil {
		return nil, fmt.Errorf("нода AWG ответ: %s", out)
	}
	if ok, _ := nodeResp["ok"].(bool); !ok {
		return nil, fmt.Errorf("нода AWG не запустился: %s", out)
	}
	nodePub, _ := nodeResp["pub_key"].(string)
	// endpoint AWG должен быть IP:port (UAPI не резолвит домены) — резолвим host
	endpointHost := host
	if net.ParseIP(host) == nil {
		if ips, err := net.LookupHost(host); err == nil && len(ips) > 0 {
			endpointHost = ips[0]
		}
	}
	endpoint := fmt.Sprintf("%s:%d", endpointHost, awgPort)
	// 2) мастер: AWG-клиент (userspace)
	client, err := amnezia.NewClient(amnezia.ClientConfig{
		PrivKey: mPriv, PeerPubKey: nodePub, Endpoint: endpoint,
		LocalIP: masterIP, Params: params,
	})
	if err != nil {
		return nil, err
	}
	if err := client.Start(amnezia.ClientConfig{
		PrivKey: mPriv, PeerPubKey: nodePub, Endpoint: endpoint,
		LocalIP: masterIP, Params: params,
	}); err != nil {
		return nil, fmt.Errorf("master AWG client: %w", err)
	}
	// 3) локальный SOCKS5 сервер → форвардинг через AWG-туннель
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		client.Stop()
		return nil, fmt.Errorf("socks listen: %w", err)
	}
	socksPort := ln.Addr().(*net.TCPAddr).Port
	c := &awgCascade{client: client, socksLn: ln, socksPort: socksPort, nodeID: nodeID,
		nodePub: nodePub, nodePort: awgPort, params: params, masterPriv: mPriv, masterPub: mPub,
		masterIP: masterIP, subnet: subnet, running: true}
	go c.socksServe()
	cascadesMu.Lock()
	cascades[nodeID] = c
	cascadesMu.Unlock()
	// 4) firewall ноды: открыть AWG UDP порт
	s.sshToNode(host, fmt.Sprintf("ufw allow %d/udp comment 'XKIT:awg-cascade' >/dev/null 2>&1; echo OK", awgPort))
	// 5) персист каскада в БД (переживает рестарт панели). УРОК: мастер-клиент in-memory.
	paramsJSON, _ := json.Marshal(params)
	s.store.UpsertAWGCascade(store.AWGCascade{NodeID: nodeID, Port: awgPort, MasterPriv: mPriv, MasterPub: mPub,
		NodePub: nodePub, Params: string(paramsJSON), MasterIP: masterIP, Subnet: subnet, Enabled: true})
	// 6) привязка к балансировщику: outbound мастера tag=nodeID → SOCKS5 AWG-каскада.
	// Существующие per-user/country-select правила балансировщика гонят трафик через AWG.
	s.setMasterOutboundSOCKS(nodeID, socksPort)
	s.store.AddEvent("awg_cascade", "ok", fmt.Sprintf("AWG-каскад %s поднят (нода :%d UDP, мастер socks :%d)", nodeID, awgPort, socksPort), fmt.Sprintf(`{"node":%q}`, nodeID))
	return c, nil
}

// RestoreAWGCascades — вызывается из main.go при старте панели: переподнять сохранённые каскады.
// Нода-сервер уже персистентен (агент restoreAWGTunnel); мастер-клиент восстанавливаем из БД.
func (s *Server) RestoreAWGCascades() {
	for _, c := range s.store.EnabledAWGCascades() {
		var host string
		if s.store.DB().QueryRow(`SELECT host FROM nodes WHERE id=?`, c.NodeID).Scan(&host) != nil {
			continue
		}
		if _, err := s.startAWGCascade(c.NodeID, host, c.Port); err != nil {
			s.store.AddEvent("awg_cascade", "error", fmt.Sprintf("каскад %s не восстановлен: %v", c.NodeID, err), "{}")
			continue
		}
		s.store.AddEvent("awg_cascade", "ok", fmt.Sprintf("AWG-каскад %s восстановлен при старте панели", c.NodeID), "{}")
	}
}

// reapplyAWGCascade — переподнять запущенный AWG-каскад с актуальным MTU ноды.
// Вызывается после смены MTU. Если каскад не запущен — ничего не делает.
func (s *Server) reapplyAWGCascade(nodeID string) {
	cascadesMu.Lock()
	c := cascades[nodeID]
	cascadesMu.Unlock()
	if c == nil || !c.running {
		return
	}
	var host string
	if s.store.DB().QueryRow(`SELECT host FROM nodes WHERE id=?`, nodeID).Scan(&host) != nil {
		return
	}
	port := c.nodePort
	if _, err := s.startAWGCascade(nodeID, host, port); err != nil {
		s.store.AddEvent("awg_cascade", "error", fmt.Sprintf("MTU reapply %s: %v", nodeID, err), "{}")
	}
}

func (s *Server) stopAWGCascade(nodeID string) {
	cascadesMu.Lock()
	c := cascades[nodeID]
	delete(cascades, nodeID)
	cascadesMu.Unlock()
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.socksLn != nil {
		c.socksLn.Close()
	}
	if c.client != nil {
		c.client.Stop()
	}
	c.running = false
	awgPort := c.nodePort
	c.mu.Unlock()
	// нода: остановить AWG-сервер
	var host string
	if s.store.DB().QueryRow(`SELECT host FROM nodes WHERE id=?`, nodeID).Scan(&host) == nil {
		token := s.agentToken(nodeID)
		s.sshToNode(host, fmt.Sprintf("curl -s --max-time 15 -X POST -H 'X-Agent-Token: %s' -d '{\"action\":\"stop\"}' http://127.0.0.1:9101/tunnel", token))
		// УРОК: порт каскада мог быть не 51821 — закрываем ФАКТИЧЕСКИЙ порт (+дефолт на всякий)
		s.sshToNode(host, fmt.Sprintf("ufw delete allow %d/udp >/dev/null 2>&1; ufw delete allow 51821/udp >/dev/null 2>&1; echo OK", awgPort))
	}
	s.store.AddEvent("awg_cascade", "ok", "AWG-каскад "+nodeID+" остановлен", fmt.Sprintf(`{"node":%q}`, nodeID))
}

// socksServe — минимальный SOCKS5 сервер, форвардит через AWG-туннель (client.DialContext).
func (c *awgCascade) socksServe() {
	for {
		conn, err := c.socksLn.Accept()
		if err != nil {
			return
		}
		go c.handleSocks(conn)
	}
}

func (c *awgCascade) handleSocks(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	// greeting: VER NMETHODS METHODS
	buf := make([]byte, 257)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 5 {
		return
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return
	}
	conn.Write([]byte{5, 0}) // no auth
	// request: VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[1] != 1 { // CONNECT only
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch buf[3] {
	case 1: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 3: // domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		dlen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:dlen]); err != nil {
			return
		}
		host = string(buf[:dlen])
	case 4: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])
	addr := fmt.Sprintf("%s:%d", host, port)
	// dial через AWG-туннель
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	target, err := c.client.DialContext(ctx, "tcp", addr)
	if err != nil {
		log.Printf("AWG socks dial %s: %v", addr, err)
		conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	conn.SetDeadline(time.Time{})
	// bidirectional copy
	done := make(chan struct{}, 2)
	go func() { io.Copy(target, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, target); done <- struct{}{} }()
	<-done
}
