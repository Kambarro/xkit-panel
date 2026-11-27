package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kambarro/xkit-panel/internal/store"
	"github.com/kambarro/xkit-panel/internal/tunnel"
)

// MTU-регулировка туннелей (каскад + клиенты). УРОК владельца: «для каскада что
// для подключения клиентов нужна регулировка mtu иногда это очень решает».
// РФ-мобилки/PPPoE/ТСПУ режут фрагменты; AWG padding добавляется сверху inner MTU.
// Подбор каскада = бинарный поиск максимального проходящего DF-пинга мастер→нода.

// GET /api/mtu — глобальный дефолт + границы.
func (s *Server) getMTU(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"default": s.store.DefaultMTU(), "min": store.MTUMin, "max": store.MTUMax})
}

// POST /api/mtu/default {mtu} — глобальный дефолт (0=сброс к 1280).
func (s *Server) setMTUDefault(w http.ResponseWriter, r *http.Request) {
	var req struct{ MTU int `json:"mtu"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "mtu обязателен", 400); return
	}
	if req.MTU != 0 && (req.MTU < store.MTUMin || req.MTU > store.MTUMax) {
		http.Error(w, fmt.Sprintf("mtu: %d..%d (0=сброс)", store.MTUMin, store.MTUMax), 400); return
	}
	s.store.SetDefaultMTU(req.MTU)
	s.store.AddEvent("mtu", "ok", fmt.Sprintf("глобальный MTU → %d", req.MTU), "{}")
	writeJSON(w, map[string]any{"ok": true, "default": s.store.DefaultMTU()})
}

// POST /api/nodes/mtu {id, mtu} — MTU каскада ноды (0=дефолт). Применяется к ОБЕМ концам.
func (s *Server) setNodeMTU(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID  string `json:"id"`
		MTU int    `json:"mtu"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "id обязателен", 400); return
	}
	if req.MTU != 0 && (req.MTU < store.MTUMin || req.MTU > store.MTUMax) {
		http.Error(w, fmt.Sprintf("mtu: %d..%d (0=дефолт)", store.MTUMin, store.MTUMax), 400); return
	}
	if surveyRunning(req.ID) { http.Error(w, "идёт survey транспортов ноды — дождитесь завершения", 409); return }
	s.store.SetNodeMTU(req.ID, req.MTU)
	s.reapplyNodeTunnel(req.ID) // xray-каскад: оба конца атомарно, с откатом
	s.reapplyAWGCascade(req.ID) // AWG-каскад: переподнять с новым MTU (если запущен)
	s.store.AddEvent("mtu", "ok", fmt.Sprintf("нода %s: MTU → %d", req.ID, req.MTU), fmt.Sprintf(`{"node":%q}`, req.ID))
	writeJSON(w, map[string]any{"ok": true, "id": req.ID, "mtu": s.store.NodeMTU(req.ID)})
}

// POST /api/clients/mtu {email, mtu} — MTU клиента (течёт в его подписку/conf/QR).
func (s *Server) setClientMTU(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		MTU   int    `json:"mtu"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, "email обязателен", 400); return
	}
	if req.MTU != 0 && (req.MTU < store.MTUMin || req.MTU > store.MTUMax) {
		http.Error(w, fmt.Sprintf("mtu: %d..%d (0=дефолт)", store.MTUMin, store.MTUMax), 400); return
	}
	s.store.SetClientMTU(req.Email, req.MTU)
	s.store.AddEvent("mtu", "ok", fmt.Sprintf("клиент %s: MTU → %d", req.Email, req.MTU), "{}")
	writeJSON(w, map[string]any{"ok": true, "email": req.Email, "mtu": s.store.ClientMTU(req.Email)})
}

// POST /api/nodes/mtu-probe {id} — подобрать MTU каскада: DF-пинги мастер→нода,
// бинарный поиск максимального проходящего. recommended = path - запас на обфускацию.
func (s *Server) probeNodeMTU(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string `json:"id"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "id обязателен", 400); return
	}
	var host string
	if err := s.store.DB().QueryRow(`SELECT host FROM nodes WHERE id=?`, req.ID).Scan(&host); err != nil {
		http.Error(w, "нода не найдена", 404); return
	}
	lo, hi := store.MTUMin, store.MTUMax
	best := lo
	for lo <= hi {
		mid := (lo + hi) / 2
		if s.pingDF(host, mid-28) { best = mid; lo = mid + 1 } else { hi = mid - 1 }
	}
	rec := best - 80 // запас на AWG padding/trailers
	if rec < store.MTUMin { rec = store.MTUMin }
	writeJSON(w, map[string]any{"ok": true, "id": req.ID, "path_mtu": best, "recommended": rec, "min": store.MTUMin, "max": store.MTUMax})
}

// pingDF — DF-пинг payload-размера (не фрагментировать). true = прошёл.
func (s *Server) pingDF(host string, payload int) bool {
	out, err := exec.Command("ping", "-M", "do", "-c", "1", "-W", "2", "-s", strconv.Itoa(payload), host).CombinedOutput()
	if err != nil { return false }
	return strings.Contains(string(out), "bytes from")
}

// POST /api/clients/mtu-probe {email} — рекомендованный MTU клиента. Клиентский путь
// (мобилка→мастер) панель напрямую не меряет — recommended = дефолт с запасом.
func (s *Server) probeClientMTU(w http.ResponseWriter, r *http.Request) {
	var req struct{ Email string `json:"email"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, "email обязателен", 400); return
	}
	rec := s.store.DefaultMTU() - 80
	if rec < store.MTUMin { rec = store.MTUMin }
	writeJSON(w, map[string]any{"ok": true, "email": req.Email, "recommended": rec,
		"note": "клиентский путь меряется в приложении; recommended = дефолт с запасом на обфускацию",
		"min": store.MTUMin, "max": store.MTUMax})
}

// reapplyNodeTunnel — переприменить текущий xray-транспорт ноды с актуальным MTU
// (оба конца атомарно, без смены транспорта/ключей). AWG-каскад — отдельный механизм.
func (s *Server) reapplyNodeTunnel(nodeID string) {
	var host, tr, tunnelCfg string
	var port int
	if err := s.store.DB().QueryRow(`SELECT host,port,tunnel,tunnel_cfg FROM nodes WHERE id=?`, nodeID).Scan(&host, &port, &tr, &tunnelCfg); err != nil {
		return
	}
	if tr == "" || tr == "awg" { return }
	tp := s.paramsFromCfg(tr, host, port, tunnelCfg)
	tp.MTU = s.store.NodeMTU(nodeID)
	if err := s.applyTunnelBothEnds(nodeID, host, tp); err != nil {
		s.store.AddEvent("mtu", "error", fmt.Sprintf("нода %s: %v", nodeID, err), "{}")
	}
}

// paramsFromCfg — собрать tunnel.Params из сохранённого tunnel_cfg (без перегенерации ключей).
func (s *Server) paramsFromCfg(tr, host string, port int, tunnelCfg string) tunnel.Params {
	var tc map[string]any
	json.Unmarshal([]byte(tunnelCfg), &tc)
	str := func(k string) string { v, _ := tc[k].(string); return v }
	// нормализуем legacy-алиасы транспорта (в БД может быть "reality"/"xhttp"/"ws"/"grpc")
	switch tr {
	case "reality", "tcp": tr = "tcp-reality"
	case "xhttp": tr = "xhttp-reality"
	case "ws": tr = "ws-tls"
	case "grpc": tr = "grpc-tls"
	case "hy2": tr = "hysteria2"
	}
	tp := tunnel.Params{Transport: tunnel.Transport(tr), Host: host, Port: port,
		UUID: str("uuid"), SNI: str("sni"), PublicKey: str("publicKey"), ShortID: str("shortId"),
		Hy2Pass: str("hy2Pass"), Hy2Obfs: str("hy2Obfs"), Path: str("path"), ServiceName: str("serviceName")}
	if tp.SNI == "" { tp.SNI = host }
	if tp.Transport == tunnel.WSTLS || tp.Transport == tunnel.GRPCTLS || tp.Transport == tunnel.Hysteria2 {
		tp.TLSCert = "/etc/letsencrypt/live/" + tp.SNI + "/fullchain.pem"
		tp.TLSKey = "/etc/letsencrypt/live/" + tp.SNI + "/privkey.pem"
	}
	// REALITY priv key хранится в tunnel_cfg для перегенерации inbound.
	// УРОК: старые ноды provision-ены ДО сохранения privateKey → пустой ключ → crash-loop
	// ноды (empty privateKey). Если пуст — пробуем достать из живого конфига ноды.
	tp.PrivateKey = str("privateKey")
	if tp.PrivateKey == "" && (tp.Transport == tunnel.TCPReality || tp.Transport == tunnel.XHTTPReality) {
		tp.PrivateKey = s.readNodeRealityPriv(host)
	}
	return tp
}

// readNodeRealityPriv — достать privateKey из живого конфига ноды (fallback для старых нод).
func (s *Server) readNodeRealityPriv(host string) string {
	out, err := s.sshToNode(host, `python3 -c "import json;c=json.load(open('/usr/local/etc/xray/config.json'));print(next((i.get('streamSettings',{}).get('realitySettings',{}).get('privateKey','') for i in c['inbounds'] if i.get('streamSettings',{}).get('realitySettings',{}).get('privateKey','')),''))"`)
	if err != nil { return "" }
	return strings.TrimSpace(out)
}

// applyTunnelBothEnds — применить конфиг туннеля на ОБА конца (нода inbound + мастер outbound)
// атомарно, с проверкой is-active и откатом ноды к last_good_cfg при провале.
func (s *Server) applyTunnelBothEnds(nodeID, host string, tp tunnel.Params) error {
	// guard: REALITY без privateKey = crash-loop ноды (empty privateKey). Не применяем.
	if (tp.Transport == tunnel.TCPReality || tp.Transport == tunnel.XHTTPReality) && tp.PrivateKey == "" {
		return fmt.Errorf("REALITY privateKey неизвестен (старая нода) — включите «Перегенерировать ключи»")
	}
	nodeCfg := s.buildNodeConfig(tp)
	if nodeCfg == "" { return fmt.Errorf("не удалось собрать конфиг ноды") }
	prev := s.store.NodeLastGoodCfg(nodeID)
	if err := s.deliverNodeConfig(nodeID, host, nodeCfg); err != nil {
		if prev != "" { s.deliverNodeConfig(nodeID, host, prev) } // откат
		return fmt.Errorf("нода: конфиг не применился (откат): %w", err)
	}
	s.store.SetNodeLastGoodCfg(nodeID, nodeCfg)
	s.replaceMasterOutboundParams(nodeID, tp)
	s.syncFirewall()
	return nil
}

// buildNodeConfig — JSON конфига ноды из params.
func (s *Server) buildNodeConfig(tp tunnel.Params) string {
	ib, err := tp.NodeInbound()
	if err != nil { return "" }
	cfg := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"dns":      ipv4OnlyDNS(), // аудит #10: IPv6 ноды мёртв — только A-записи
		"inbounds": []any{ib},
		"outbounds": []any{freedomIPv4("direct"), map[string]any{"tag": "blackhole", "protocol": "blackhole"}},
		"routing":  map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "port": "0-65535", "outboundTag": "direct"}}},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

// deliverNodeConfig — единая доставка xray-конфига на ноду ЧЕРЕЗ АГЕНТА (POST /xray).
// Принцип проекта: «всё единообразно, если есть агент — переиспользуем код».
// Агент валидирует (xray run -test) → применяет → откат при провале. SSH-fallback для нод без агента.
func (s *Server) deliverNodeConfig(nodeID, host, cfg string) error {
	token := s.agentToken(nodeID)
	if token != "" {
		// конфиг base64 → на ноде python формирует JSON-тело (без экранирования в shell)
		b64 := base64.StdEncoding.EncodeToString([]byte(cfg))
		remote := fmt.Sprintf(`echo '%s' | base64 -d > /tmp/xray-agent-cfg.json; python3 -c 'import json;print(json.dumps({"action":"apply","config":open("/tmp/xray-agent-cfg.json").read()}))' > /tmp/xray-agent-body.json; curl -s --max-time 25 -X POST -H 'X-Agent-Token: %s' -H 'Content-Type: application/json' -d @/tmp/xray-agent-body.json http://127.0.0.1:9101/xray; rm -f /tmp/xray-agent-cfg.json /tmp/xray-agent-body.json`, b64, token)
		out, err := s.sshToNode(host, remote)
		if err == nil {
			var resp map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(out)), &resp) == nil {
				if ok, _ := resp["ok"].(bool); ok {
					return nil
				}
				if e, _ := resp["error"].(string); e != "" {
					return fmt.Errorf("агент: %s", e)
				}
			}
		}
		// агент не ответил/ошибка — fallback на SSH ниже (нода могла быть без агента)
	}
	return s.deliverNodeConfigSSH(host, cfg)
}

// deliverNodeConfigSSH — legacy-доставка по SSH (fallback для нод без агента).
// SEC-04: конфиг доставляется base64-обёрткой (echo '<b64>' | base64 -d > file),
// НЕ heredoc — SNI/path/serviceName внутри JSON могли разорвать heredoc-маркер
// и выполнить произвольные команды на ноде. Base64-алфавит shell-безопасен.
func (s *Server) deliverNodeConfigSSH(host, cfg string) error {
	b64 := base64.StdEncoding.EncodeToString([]byte(cfg))
	cmd := fmt.Sprintf("mkdir -p /usr/local/etc/xray && echo '%s' | base64 -d > /usr/local/etc/xray/config.json\nsystemctl restart xray; for i in 1 2 3 4 5 6; do sleep 1; st=$(systemctl is-active xray); if [ \"$st\" = active ]; then echo active; exit 0; fi; done; systemctl is-active xray", b64)
	out, err := s.sshToNode(host, cmd)
	if err != nil || strings.TrimSpace(out) != "active" {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// replaceMasterOutboundParams — заменить outbound мастера (tag=nodeID) из params.
func (s *Server) replaceMasterOutboundParams(nodeID string, tp tunnel.Params) {
	cfgPath := "/usr/local/etc/xray/config.json"
	out, err := os.ReadFile(cfgPath)
	if err != nil { return }
	var cfg map[string]any
	if json.Unmarshal(out, &cfg) != nil { return }
	ob, _ := cfg["outbounds"].([]any)
	var filtered []any
	for _, o := range ob {
		if m, ok := o.(map[string]any); ok && m["tag"] == nodeID { continue }
		filtered = append(filtered, o)
	}
	mob, err := tp.MasterOutbound(nodeID)
	if err != nil { return }
	filtered = append(filtered, mob)
	cfg["outbounds"] = filtered
	s.rebuildConfigClients(cfg) // УРОК (QA BUG#23): сохранить клиентов при перезаписи config
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(cfgPath, data, 0644)
	exec.Command("systemctl", "restart", "xray").Run()
	time.Sleep(2 * time.Second)
	if s.xray != nil {
		if err := s.xray.Reconnect(); err == nil && s.ctrl != nil {
			s.ctrl.SyncRulesNow(context.Background())
		}
	}
	// УРОК (QA): рестарт xray убивает горячие preset-inbound (их нет в config-файле).
	// Восстанавливаем их из БД после рестарта (иначе порты закрыты, подписки битые).
	go s.RestoreInbounds()
}