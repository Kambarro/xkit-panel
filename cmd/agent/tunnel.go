// AWG-туннель на ноде (агент). Агент поднимает AmneziaWG-СЕРВЕР на ноде,
// мастер подключается AWG-клиентом (userspace netstack) → каскад через AWG.
// POST /tunnel {action:start|stop, ...} — управление AWG-сервером ноды.
// GET /tunnel — статус AWG-туннеля.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/kambarro/xkit-panel/internal/amnezia"
)

var (
	awgMu  sync.Mutex
	awgSrv *amnezia.Server
	awgCfg *awgTunnelConfig
)

type awgTunnelConfig struct {
	Port      int              `json:"port"`
	Subnet    string           `json:"subnet"`
	Iface     string           `json:"iface"`
	PrivKey   string           `json:"priv_key"`
	PubKey    string           `json:"pub_key"`
	Params    amnezia.AWGParams `json:"params"`
	MasterPub string           `json:"master_pub"`  // публичный ключ мастера-клиента
	MasterIP  string           `json:"master_ip"`   // IP мастера в туннеле (10.9.0.2)
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		awgMu.Lock()
		defer awgMu.Unlock()
		if awgSrv == nil || !awgSrv.Running() {
			writeJSON(w, map[string]any{"running": false})
			return
		}
		writeJSON(w, map[string]any{"running": true, "port": awgSrv.Port(), "pub_key": awgSrv.PubKey(), "iface": awgCfg.Iface, "uapi": awgSrv.PeersUAPI()})
		return
	}
	// POST start/stop
	var req struct {
		Action string          `json:"action"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400); return
	}
	switch req.Action {
	case "stop":
		awgMu.Lock()
		if awgSrv != nil { awgSrv.Stop(); awgSrv = nil }
		if awgCfg != nil { amnezia.TeardownNAT(awgCfg.Iface, awgCfg.Subnet, awgCfg.Port) }
		awgCfg = nil
		awgMu.Unlock()
		writeJSON(w, map[string]any{"ok": true, "running": false})
	case "start":
		var cfg awgTunnelConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			http.Error(w, "config: "+err.Error(), 400); return
		}
		if cfg.Port == 0 { cfg.Port = 51821 }
		if cfg.Subnet == "" { cfg.Subnet = "10.9.0.0/24" }
		if cfg.Iface == "" { cfg.Iface = "awg-cascade" }
		if cfg.MasterIP == "" { cfg.MasterIP = "10.9.0.2" }
		if err := startAWGTunnel(cfg); err != nil {
			http.Error(w, err.Error(), 500); return
		}
		writeJSON(w, map[string]any{"ok": true, "running": true, "port": cfg.Port, "pub_key": awgSrv.PubKey(), "iface": cfg.Iface})
	default:
		http.Error(w, "action: start|stop", 400)
	}
}

func startAWGTunnel(cfg awgTunnelConfig) error {
	awgMu.Lock()
	defer awgMu.Unlock()
	// остановим старый если есть
	if awgSrv != nil { awgSrv.Stop(); awgSrv = nil }
	// ключи если не переданы
	if cfg.PrivKey == "" {
		priv, pub, err := amnezia.GenKeyPair()
		if err != nil { return fmt.Errorf("keygen: %w", err) }
		cfg.PrivKey, cfg.PubKey = priv, pub
	}
	// параметры обфускации если не переданы
	// params переданы если H1 задан (Jc=0 допустим для минимальной обфускации)
	if cfg.Params.H1 == "" {
		p, err := amnezia.GenParams()
		if err != nil { return fmt.Errorf("params: %w", err) }
		cfg.Params = p
	}
	srv, err := amnezia.NewServer(amnezia.ServerConfig{
		Iface: cfg.Iface, Port: cfg.Port, PrivKey: cfg.PrivKey, Params: cfg.Params, Address: subnetAddr(cfg.Subnet),
	})
	if err != nil { return err }
	// пир мастера в ТОМ ЖЕ IpcSet что params (до Up) — как loopback тест
	if err := srv.StartWithPeer(amnezia.Peer{PublicKey: cfg.MasterPub, Address: cfg.MasterIP}); err != nil {
		return fmt.Errorf("AWG start: %w", err)
	}
	// NAT + firewall (нода должна форвардить трафик туннеля в интернет)
	if err := amnezia.SetupNAT(cfg.Iface, cfg.Subnet, cfg.Port); err != nil {
		srv.Stop()
		return fmt.Errorf("NAT: %w", err)
	}
	awgSrv = srv
	awgCfg = &cfg
	// сохраним конфиг для рестарта (агент может перезапуститься)
	saveAWGConfig(cfg)
	return nil
}

func subnetAddr(subnet string) string {
	// 10.9.0.0/24 → 10.9.0.1/24
	parts := strings.SplitN(subnet, "/", 2)
	ip := strings.Split(parts[0], ".")
	if len(ip) == 4 {
		ip[3] = "1"
		mask := "24"
		if len(parts) == 2 { mask = parts[1] }
		return strings.Join(ip, ".") + "/" + mask
	}
	return "10.9.0.1/24"
}

func saveAWGConfig(cfg awgTunnelConfig) {
	b, _ := json.Marshal(cfg)
	os.WriteFile("/etc/xkit-agent/awg-tunnel.json", b, 0600)
}

// restoreAWGTunnel — поднять AWG при старте агента если был сохранён конфиг.
func restoreAWGTunnel() {
	b, err := os.ReadFile("/etc/xkit-agent/awg-tunnel.json")
	if err != nil { return }
	var cfg awgTunnelConfig
	if json.Unmarshal(b, &cfg) != nil { return }
	if err := startAWGTunnel(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "AWG restore:", err)
	} else {
		fmt.Fprintln(os.Stderr, "AWG cascade tunnel restored on :"+fmt.Sprintf("%d", cfg.Port))
	}
}

var _ = exec.Command