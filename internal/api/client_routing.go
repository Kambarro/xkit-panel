package api

import (
	"encoding/json"
	"net/http"

	"github.com/kambarro/xkit-panel/internal/routing"
	"github.com/kambarro/xkit-panel/internal/store"
)

// Per-client роутинг (P2 козырь): наш дефолт + кастом клиента поверх.
// GET /api/clients/routing?email → {mode, rules, allowed, default_rules, deeplink}
// POST /api/clients/routing {email, mode, rules} — клиент/владелец меняет
// POST /api/clients/routing/allow {email, allow} — тумблер владельца
// GET /api/clients/routing/deeplink?email → Happ deeplink (для кнопки «Применить в Happ»)

func (s *Server) getClientRouting(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cl, _ := s.store.GetClient(email)
	if cl == nil { http.Error(w, "client not found", 404); return }
	mode, rules, allowed := s.store.ClientRouting(email)
	d, p, b, dip, pip, bip := routing.MergedRulesBase(mode, toRoutingRules(rules), s.routingBase())
	writeJSON(w, map[string]any{
		"mode": mode, "rules": rules, "allowed": allowed,
		"default": map[string]any{
			"direct_sites": routing.DefaultDirectSites, "proxy_sites": routing.DefaultProxySites,
			"block_sites": routing.DefaultBlockSites, "direct_ip": routing.DefaultDirectIP,
		},
		"merged": map[string]any{"direct_sites": d, "proxy_sites": p, "block_sites": b, "direct_ip": dip, "proxy_ip": pip, "block_ip": bip},
		"deeplink": routing.HappDeeplink("XKIT "+cl.Name, d, p, b, dip, pip, bip),
	})
}

func (s *Server) setClientRouting(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string            `json:"email"`
		Mode  string            `json:"mode"`
		Rules routing.CustomRules `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	cl, _ := s.store.GetClient(body.Email)
	if cl == nil { http.Error(w, "client not found", 404); return }
	// если владелец запретил кастом — клиент не может включить custom
	_, _, allowed := s.store.ClientRouting(body.Email)
	if body.Mode == "custom" && !allowed {
		http.Error(w, "кастомный роутинг запрещён владельцем", 403); return
	}
	if body.Mode != "default" && body.Mode != "custom" { body.Mode = "default" }
	if err := s.store.SetClientRouting(body.Email, body.Mode, toStoreRules(body.Rules)); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	s.store.AddEvent("routing", "ok", "роутинг "+body.Email+" → "+body.Mode, "{}")
	writeJSON(w, map[string]any{"ok": true, "mode": body.Mode})
}

func (s *Server) setAllowRouting(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Allow bool   `json:"allow"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	if err := s.store.SetAllowCustomRouting(body.Email, body.Allow); err != nil {
		http.Error(w, err.Error(), 500); return
	}
	// если запретили — сбросим mode в default
	if !body.Allow {
		s.store.SetClientRouting(body.Email, "default", store.CustomRules{})
	}
	s.store.AddEvent("routing", "ok", "кастом роутинг "+body.Email+" разрешён="+boolStr(body.Allow), "{}")
	writeJSON(w, map[string]any{"ok": true, "allow": body.Allow})
}

func (s *Server) routingDeeplink(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cl, _ := s.store.GetClient(email)
	if cl == nil { http.Error(w, "client not found", 404); return }
	mode, rules, _ := s.store.ClientRouting(email)
	d, p, b, dip, pip, bip := routing.MergedRulesBase(mode, toRoutingRules(rules), s.routingBase())
	link := routing.HappDeeplink("XKIT "+cl.Name, d, p, b, dip, pip, bip)
	// antifilter: инверсия Happ (GlobalProxy=false) + always-правила владельца
	var n int
	s.store.DB().QueryRow(`SELECT COUNT(*) FROM nodes WHERE enabled=1`).Scan(&n)
	if af := s.AntifilterSubscriptionRules(n > 0); af != nil {
		link = routing.AntifilterHappDeeplink("XKIT "+cl.Name, af.DirectSites, af.ProxySites, nil, af.DirectIP, af.ProxyIP, nil)
	}
	writeJSON(w, map[string]any{"deeplink": link})
}

func toRoutingRules(r store.CustomRules) routing.CustomRules {
	return routing.CustomRules{DirectSites: r.DirectSites, ProxySites: r.ProxySites, BlockSites: r.BlockSites, DirectIP: r.DirectIP, ProxyIP: r.ProxyIP, BlockIP: r.BlockIP}
}
func toStoreRules(r routing.CustomRules) store.CustomRules {
	return store.CustomRules{DirectSites: r.DirectSites, ProxySites: r.ProxySites, BlockSites: r.BlockSites, DirectIP: r.DirectIP, ProxyIP: r.ProxyIP, BlockIP: r.BlockIP}
}
func boolStr(b bool) string { if b { return "true" }; return "false" }

// routingBase — базовый набор владельца из БД.
func (s *Server) routingBase() routing.BaseRules {
	dr := s.store.DefaultRouting()
	return routing.BaseRules{DirectSites: dr.DirectSites, ProxySites: dr.ProxySites, BlockSites: dr.BlockSites, DirectIP: dr.DirectIP, ProxyIP: dr.ProxyIP, BlockIP: dr.BlockIP}
}
