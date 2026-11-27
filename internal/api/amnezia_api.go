package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/kambarro/xkit-panel/internal/amnezia"
	"github.com/kambarro/xkit-panel/internal/store"
)

// AWG-менеджер: сервер живёт в процессе панели (amneziawg-go библиотека).
// SQLite = источник правды: при старте панели сервер поднимается если enabled,
// пиры восстанавливаются из БД. Ошибки не глотаются (урок XKIT).

// SetAWGManager — wiring из main.go.
func (s *Server) SetAWGManager() {
	s.awgMu = &awgState{}
}

type awgState struct {
	srv *amnezia.Server // nil = не запущен
}

// awgStatus — GET /api/amnezia: статус сервера + пиры.
func (s *Server) awgStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetAWGServer()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	peers, _ := s.store.AllAWGPeers()
	if peers == nil {
		peers = []store.AWGPeer{}
	}
	running := s.awgMu != nil && s.awgMu.srv != nil
	var params amnezia.AWGParams
	json.Unmarshal([]byte(cfg.Params), &params)
	ver := params.Version
	if ver == "" { ver = "3.1" }
	writeJSON(w, map[string]any{
		"enabled": cfg.Enabled, "running": running,
		"port": cfg.Port, "iface": cfg.Iface, "subnet": cfg.Subnet,
		"public_key": cfg.PublicKey, "dns": cfg.DNS, "version": ver,
		"peers": peers, "peer_count": len(peers),
	})
}

// awgEnable — POST /api/amnezia/enable {enabled, port?}: вкл/выкл AWG-сервер.
// Вкл: генерим ключи/параметры если первый раз → TUN+bind+NAT → пиры из БД.
func (s *Server) awgEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool   `json:"enabled"`
		Port    int    `json:"port"`
		Version string `json:"version"` // "3.1" | "2.0" (роутеры)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	cfg, err := s.store.GetAWGServer()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if body.Port > 0 && body.Port < 65536 {
		cfg.Port = body.Port
	}

	if !body.Enabled {
		// выключить
		if s.awgMu != nil && s.awgMu.srv != nil {
			s.awgMu.srv.Stop()
			s.awgMu.srv = nil
		}
		amnezia.TeardownNAT(cfg.Iface, cfg.Subnet, cfg.Port)
		cfg.Enabled = false
		if err := s.store.SaveAWGServer(*cfg); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.store.AddEvent("amnezia", "ok", "AmneziaWG сервер выключен", "{}")
		s.syncFirewall() // автоматика UFW: закрыли UDP порт AWG
		writeJSON(w, map[string]any{"ok": true, "enabled": false})
		return
	}

	// смена версии AWG (3.1 ↔ 2.0): параметры несовместимы → регенерация + рестарт.
	// Пиры (ключи/IP) сохраняются — меняются только параметры обфускации сервера.
	if body.Version == "2.0" || body.Version == "3.1" {
		var cur amnezia.AWGParams
		json.Unmarshal([]byte(cfg.Params), &cur)
		curVer := cur.Version
		if curVer == "" { curVer = "3.1" }
		if curVer != body.Version {
			params, err := amnezia.GenParamsVersion(body.Version)
			if err != nil {
				http.Error(w, "params: "+err.Error(), 500)
				return
			}
			cfg.Params = store.AWGParamsJSON(params)
			if s.awgMu != nil && s.awgMu.srv != nil {
				s.awgMu.srv.Stop()
				s.awgMu.srv = nil
			}
			if body.Enabled {
				if err := s.startAWGServer(*cfg, params); err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				cfg.Enabled = true
			}
			s.store.SaveAWGServer(*cfg)
			s.syncFirewall()
			s.store.AddEvent("amnezia", "ok", "AmneziaWG переключён на версию "+body.Version+" (параметры регенерированы, пиры сохранены)", "{}")
			writeJSON(w, map[string]any{"ok": true, "enabled": cfg.Enabled, "version": body.Version, "port": cfg.Port})
			return
		}
	}

	// включить: ключи/параметры если первый раз
	if cfg.PrivateKey == "" {
		priv, pub, err := amnezia.GenKeyPair()
		if err != nil {
			http.Error(w, "keygen: "+err.Error(), 500)
			return
		}
		cfg.PrivateKey, cfg.PublicKey = priv, pub
		ver := body.Version
		if ver != "2.0" { ver = "3.1" }
		params, err := amnezia.GenParamsVersion(ver)
		if err != nil {
			http.Error(w, "params: "+err.Error(), 500)
			return
		}
		cfg.Params = store.AWGParamsJSON(params)
	}
	var params amnezia.AWGParams
	if err := json.Unmarshal([]byte(cfg.Params), &params); err != nil {
		http.Error(w, "params decode: "+err.Error(), 500)
		return
	}
	if err := s.startAWGServer(*cfg, params); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	cfg.Enabled = true
	if err := s.store.SaveAWGServer(*cfg); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.store.AddEvent("amnezia", "ok", fmt.Sprintf("AmneziaWG сервер запущен (:%d UDP, %s)", cfg.Port, cfg.Subnet), "{}")
	s.syncFirewall() // автоматика UFW: открыли UDP порт AWG
	writeJSON(w, map[string]any{"ok": true, "enabled": true, "port": cfg.Port, "public_key": cfg.PublicKey})
}

// startAWGServer — TUN+bind+device+NAT+пиры из БД. Возвращает РЕАЛЬНУЮ ошибку.
func (s *Server) startAWGServer(cfg store.AWGServer, params amnezia.AWGParams) error {
	if s.awgMu == nil {
		s.awgMu = &awgState{}
	}
	if s.awgMu.srv != nil {
		s.awgMu.srv.Stop()
		s.awgMu.srv = nil
	}
	srv, err := amnezia.NewServer(amnezia.ServerConfig{
		Iface: cfg.Iface, Port: cfg.Port, PrivKey: cfg.PrivateKey, Params: params,
	})
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return fmt.Errorf("AWG start: %w", err)
	}
	if err := amnezia.SetupNAT(cfg.Iface, cfg.Subnet, cfg.Port); err != nil {
		srv.Stop()
		return fmt.Errorf("NAT: %w", err)
	}
	s.awgMu.srv = srv
	// восстановим пиры из БД (источник правды)
	peers, _ := s.store.AllAWGPeers()
	for _, p := range peers {
		if !p.Enabled {
			continue
		}
		peer := amnezia.Peer{PublicKey: p.PublicKey, PresharedKey: p.PresharedKey, Address: p.Address}
		if err := srv.AddPeer(peer); err != nil {
			s.store.AddEvent("amnezia", "warn", fmt.Sprintf("пир %s не восстановлен: %v", p.Email, err), "{}")
		}
	}
	return nil
}

// RestoreAWG — вызывается из main.go при старте панели (если enabled в БД).
func (s *Server) RestoreAWG() {
	cfg, err := s.store.GetAWGServer()
	if err != nil || !cfg.Enabled || cfg.PrivateKey == "" {
		return
	}
	var params amnezia.AWGParams
	if json.Unmarshal([]byte(cfg.Params), &params) != nil {
		return
	}
	if err := s.startAWGServer(*cfg, params); err != nil {
		s.store.AddEvent("amnezia", "error", "AWG не восстановлен при старте: "+err.Error(), "{}")
		return
	}
	s.store.AddEvent("amnezia", "ok", "AmneziaWG сервер восстановлен при старте панели", "{}")
}

// awgCreatePeer — POST /api/amnezia/peer {email}: создать пир для клиента панели.
// Генерим ключи, назначаем IP, AddPeer горячо, сохраняем в БД. Возвращаем conf/vpn://.
func (s *Server) awgCreatePeer(w http.ResponseWriter, r *http.Request) {
	var body struct{ Email string `json:"email"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400)
		return
	}
	cl, _ := s.store.GetClient(body.Email)
	if cl == nil {
		http.Error(w, "client not found", 404)
		return
	}
	cfg, err := s.store.GetAWGServer()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !cfg.Enabled || s.awgMu == nil || s.awgMu.srv == nil {
		http.Error(w, "AWG сервер не запущен (включите на экране Протоколы)", 400)
		return
	}
	// уже есть пир? вернём существующий conf
	if existing, _ := s.store.GetAWGPeer(body.Email); existing != nil {
		writeJSON(w, s.awgPeerResponse(*cfg, *existing))
		return
	}
	priv, pub, err := amnezia.GenKeyPair()
	if err != nil {
		http.Error(w, "keygen: "+err.Error(), 500)
		return
	}
	psk, _ := amnezia.GenPresharedKey()
	addr, err := amnezia.AssignIP(cfg.Subnet, s.store.AWGUsedAddresses())
	if err != nil {
		http.Error(w, "IP assign: "+err.Error(), 500)
		return
	}
	var params amnezia.AWGParams
	json.Unmarshal([]byte(cfg.Params), &params)
	p := store.AWGPeer{Email: body.Email, Name: cl.Name, PrivateKey: priv, PublicKey: pub, PresharedKey: psk, Address: addr, Enabled: true}
	peer := amnezia.Peer{Name: cl.Name, PrivateKey: priv, PublicKey: pub, PresharedKey: psk, Address: addr,
		ServerPub: cfg.PublicKey, Endpoint: fmt.Sprintf("%s:%d", s.domain, cfg.Port), Params: params, DNS: cfg.DNS}
	if err := s.awgMu.srv.AddPeer(peer); err != nil {
		http.Error(w, "AddPeer: "+err.Error(), 500)
		return
	}
	if err := s.store.UpsertAWGPeer(p); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.store.AddEvent("amnezia", "ok", fmt.Sprintf("AWG пир %s создан (%s)", body.Email, addr), "{}")
	writeJSON(w, s.awgPeerResponse(*cfg, p))
}

// awgPeerResponse — conf + vpn:// + QR chunks для клиента.
// ensureAWGPeer — идемпотентно создаёт AWG-пир клиенту (если сервер включён и пира нет).
// УРОК (владелец): «не вижу амнезии в подписках» — пир создавался только вручную кнопкой.
// Теперь: при создании клиента и при запросе подписки пир создаётся автоматически.
func (s *Server) ensureAWGPeer(email string) {
	cfg, err := s.store.GetAWGServer()
	if err != nil || !cfg.Enabled || s.awgMu == nil || s.awgMu.srv == nil {
		return
	}
	if existing, _ := s.store.GetAWGPeer(email); existing != nil {
		return
	}
	cl, _ := s.store.GetClient(email)
	if cl == nil || !cl.Enabled {
		return
	}
	priv, pub, err := amnezia.GenKeyPair()
	if err != nil {
		return
	}
	psk, _ := amnezia.GenPresharedKey()
	addr, err := amnezia.AssignIP(cfg.Subnet, s.store.AWGUsedAddresses())
	if err != nil {
		return
	}
	var params amnezia.AWGParams
	json.Unmarshal([]byte(cfg.Params), &params)
	p := store.AWGPeer{Email: email, Name: cl.Name, PrivateKey: priv, PublicKey: pub, PresharedKey: psk, Address: addr, Enabled: true}
	peer := amnezia.Peer{Name: cl.Name, PrivateKey: priv, PublicKey: pub, PresharedKey: psk, Address: addr,
		ServerPub: cfg.PublicKey, Endpoint: fmt.Sprintf("%s:%d", s.domain, cfg.Port), Params: params, DNS: cfg.DNS}
	if err := s.awgMu.srv.AddPeer(peer); err != nil {
		return
	}
	if err := s.store.UpsertAWGPeer(p); err != nil {
		return
	}
	s.store.AddEvent("amnezia", "ok", fmt.Sprintf("AWG пир %s создан автоматически (%s)", email, addr), "{}")
}

// EnsureAWGPeerForSub — публичная обёртка ensureAWGPeer (для sub handler в main.go).
func (s *Server) EnsureAWGPeerForSub(email string) { s.ensureAWGPeer(email) }

func (s *Server) awgPeerResponse(cfg store.AWGServer, p store.AWGPeer) map[string]any {
	var params amnezia.AWGParams
	json.Unmarshal([]byte(cfg.Params), &params)
	// per-client MTU (0 → глобальный дефолт). УРОК владельца: регулировка MTU клиента.
	if m := s.store.ClientMTU(p.Email); m > 0 { params.MTU = m }
	peer := amnezia.Peer{Name: p.Name, PrivateKey: p.PrivateKey, PublicKey: p.PublicKey, PresharedKey: p.PresharedKey,
		Address: p.Address, ServerPub: cfg.PublicKey, Endpoint: fmt.Sprintf("%s:%d", s.domain, cfg.Port), Params: params, DNS: cfg.DNS}
	qrChunks, _ := amnezia.AWGQRPayload(peer, "XKIT "+p.Name)
	return map[string]any{
		"email": p.Email, "address": p.Address, "enabled": p.Enabled,
		"conf": peer.ClientConf(), "vpn_link": peer.VPNLink(), "qr_chunks": qrChunks,
	}
}

// awgDeletePeer — POST /api/amnezia/peer/delete {email}.
func (s *Server) awgDeletePeer(w http.ResponseWriter, r *http.Request) {
	var body struct{ Email string `json:"email"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400)
		return
	}
	p, _ := s.store.GetAWGPeer(body.Email)
	if p == nil {
		http.Error(w, "peer not found", 404)
		return
	}
	if s.awgMu != nil && s.awgMu.srv != nil {
		if err := s.awgMu.srv.RemovePeer(p.PublicKey); err != nil {
			s.store.AddEvent("amnezia", "warn", "RemovePeer: "+err.Error(), "{}")
		}
	}
	s.store.DeleteAWGPeer(body.Email)
	s.store.AddEvent("amnezia", "ok", "AWG пир "+body.Email+" удалён", "{}")
	writeJSON(w, map[string]any{"ok": true})
}

// awgPeerConf — GET /api/amnezia/peer?email=... : conf/vpn:// существующего пира.
func (s *Server) awgPeerConf(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	p, _ := s.store.GetAWGPeer(email)
	if p == nil {
		http.Error(w, "peer not found", 404)
		return
	}
	cfg, _ := s.store.GetAWGServer()
	writeJSON(w, s.awgPeerResponse(*cfg, *p))
}

// AWGPeerBySubID — для /sub/<id>/amnezia (main.go): находит пир по sub_id клиента.
func (s *Server) AWGPeerBySubID(subID string) (peer amnezia.Peer, ok bool) {
	var email string
	err := s.store.DB().QueryRow(`SELECT email FROM clients WHERE sub_id=? AND enabled=1`, subID).Scan(&email)
	if err != nil {
		return amnezia.Peer{}, false
	}
	p, _ := s.store.GetAWGPeer(email)
	if p == nil || !p.Enabled {
		return amnezia.Peer{}, false
	}
	cfg, err := s.store.GetAWGServer()
	if err != nil || !cfg.Enabled {
		return amnezia.Peer{}, false
	}
	var params amnezia.AWGParams
	json.Unmarshal([]byte(cfg.Params), &params)
	if m := s.store.ClientMTU(email); m > 0 { params.MTU = m } // per-client MTU в подписку
	return amnezia.Peer{Name: p.Name, PrivateKey: p.PrivateKey, PublicKey: p.PublicKey, PresharedKey: p.PresharedKey,
		Address: p.Address, ServerPub: cfg.PublicKey, Endpoint: fmt.Sprintf("%s:%d", s.domain, cfg.Port), Params: params, DNS: cfg.DNS}, true
}

// domain — публичный домен мастера (задаётся из main.go).
// (поле добавляется в Server struct через patch)
var _ = strings.TrimSpace