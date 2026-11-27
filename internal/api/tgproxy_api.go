package api

// tgproxy_api.go — Telegram-прокси (MTProto FakeTLS + Web Proxy) через mtg-multi.
// ОДИН процесс: MTProto (ee, публичный порт) + WEB mode (dd, loopback за nginx /<slug>/).
// Каскад через живую ноду (авто-failover, без выбора страны). nftables не нужен (UFW).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"github.com/kambarro/xkit-panel/internal/tgproxy"
)

func (s *Server) SetContext(ctx context.Context) { s.ctx = ctx }

// tgNodes — живые ноды для туннеля (по quality, без выбора страны).
func (s *Server) tgNodes() []tgproxy.Node {
	rows, err := s.store.DB().Query(`SELECT id,host FROM nodes WHERE enabled=1 AND health='alive' ORDER BY quality_score DESC, priority ASC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []tgproxy.Node
	for rows.Next() {
		var n tgproxy.Node
		rows.Scan(&n.ID, &n.Host)
		out = append(out, n)
	}
	return out
}

// InitTGProxy — инициализация при старте панели.
func (s *Server) InitTGProxy() {
	s.tgTunnel = tgproxy.NewTunnel("/var/lib/xkit-panel/node_key", s.tgNodes)
	s.tgMgr = &tgproxy.Manager{}
	s.tgTunnel.OnSwitch(func(socks, node string) {
		s.tgMgr.RestartWithSocks(socks)
		s.store.AddEvent("tgproxy", "info", "Telegram-прокси: каскад переключён на ноду "+node, "{}")
	})
	s.tgTunnel.Start(s.ctx)
	mtE := s.store.GetSetting("tg_mtproto_enabled", "0") == "1"
	webE := s.store.GetSetting("tg_web_enabled", "0") == "1"
	if mtE || webE {
		port := atoiDefault(s.store.GetSetting("tg_mtproto_port", "8449"), 8449)
		mtS := s.store.GetSetting("tg_mtproto_secret", "")
		webS := s.store.GetSetting("tg_web_secret", "")
		slug := s.store.GetSetting("tg_web_slug", "")
		s.tgMgr.Apply(s.domain, mtE, port, mtS, webE, webS, slug, s.tgTunnel.SocksAddr())
		if webE && slug != "" {
			s.syncTGWebNginx(slug)
		}
	}
}

// GET /api/tgproxy — статус.
func (s *Server) tgproxyStatus(w http.ResponseWriter, r *http.Request) {
	run, mtE, mtP, mtS, webE, webS, slug := s.tgMgr.Status()
	writeJSON(w, map[string]any{
		"running": run,
		"mtproto": map[string]any{
			"enabled": mtE, "running": run && mtE, "port": mtP,
			"link": tgproxy.TgLink(s.domain, mtP, mtS),
		},
		"web": map[string]any{
			"enabled": webE, "running": run && webE, "slug": slug,
			"link": tgproxy.WebLink(s.domain, slug, webS),
			"url":  fmt.Sprintf("https://%s/%s/", s.domain, slug),
		},
		"tunnel_node":  s.tgTunnel.NodeHost(),
		"tunnel_socks": s.tgTunnel.SocksAddr(),
	})
}

// POST /api/tgproxy/mtproto {enabled, port?}
func (s *Server) tgproxyMTProto(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
		Port    int  `json:"port"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	mtS := s.store.GetSetting("tg_mtproto_secret", "")
	port := body.Port
	if port == 0 {
		port = atoiDefault(s.store.GetSetting("tg_mtproto_port", "8449"), 8449)
	}
	if body.Enabled && mtS == "" {
		var err error
		mtS, err = tgproxy.GenFakeTLSSecret(s.domain)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.store.SetSetting("tg_mtproto_secret", mtS)
	}
	webE := s.store.GetSetting("tg_web_enabled", "0") == "1"
	webS := s.store.GetSetting("tg_web_secret", "")
	slug := s.store.GetSetting("tg_web_slug", "")
	if err := s.tgMgr.Apply(s.domain, body.Enabled, port, mtS, webE, webS, slug, s.tgTunnel.SocksAddr()); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if body.Enabled {
		s.store.SetSetting("tg_mtproto_enabled", "1")
		s.store.SetSetting("tg_mtproto_port", fmt.Sprintf("%d", port))
	} else {
		s.store.SetSetting("tg_mtproto_enabled", "0")
	}
	s.syncFirewall()
	s.store.AddEvent("tgproxy", "ok", fmt.Sprintf("MTProto прокси %v (:%d)", body.Enabled, port), "{}")
	writeJSON(w, map[string]any{"ok": true, "enabled": body.Enabled, "port": port, "link": tgproxy.TgLink(s.domain, port, mtS)})
}

// POST /api/tgproxy/web {enabled}
func (s *Server) tgproxyWeb(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	webS := s.store.GetSetting("tg_web_secret", "")
	slug := s.store.GetSetting("tg_web_slug", "")
	if body.Enabled {
		if webS == "" {
			var err error
			webS, err = tgproxy.GenFakeTLSSecret(s.domain)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			s.store.SetSetting("tg_web_secret", webS)
		}
		if slug == "" {
			slug = tgproxy.GenSlug()
			s.store.SetSetting("tg_web_slug", slug)
		}
	}
	mtE := s.store.GetSetting("tg_mtproto_enabled", "0") == "1"
	mtP := atoiDefault(s.store.GetSetting("tg_mtproto_port", "8449"), 8449)
	mtS := s.store.GetSetting("tg_mtproto_secret", "")
	if err := s.tgMgr.Apply(s.domain, mtE, mtP, mtS, body.Enabled, webS, slug, s.tgTunnel.SocksAddr()); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if body.Enabled {
		s.store.SetSetting("tg_web_enabled", "1")
		s.syncTGWebNginx(slug)
	} else {
		s.store.SetSetting("tg_web_enabled", "0")
		s.removeTGWebNginx()
	}
	s.store.AddEvent("tgproxy", "ok", fmt.Sprintf("Web Proxy %v (/%s/)", body.Enabled, slug), "{}")
	writeJSON(w, map[string]any{"ok": true, "enabled": body.Enabled, "slug": slug, "link": tgproxy.WebLink(s.domain, slug, webS), "url": fmt.Sprintf("https://%s/%s/", s.domain, slug)})
}

// TGProxyLinks — tg:// ссылки для подписки клиента.
func (s *Server) TGProxyLinks() []string {
	var out []string
	run, mtE, mtP, mtS, webE, webS, slug := s.tgMgr.Status()
	if !run {
		return out
	}
	if mtE && mtS != "" {
		out = append(out, tgproxy.TgLink(s.domain, mtP, mtS))
	}
	if webE && webS != "" {
		out = append(out, tgproxy.WebLink(s.domain, slug, webS))
	}
	return out
}

func (s *Server) syncTGWebNginx(slug string) {
	if slug == "" {
		return
	}
	confPath := "/etc/nginx/conf.d/xkit-panel.conf"
	out, err := exec.Command("cat", confPath).Output()
	if err != nil {
		return
	}
	conf := string(out)
	marker := "# XKIT-TGWEB"
	loc := marker + "\n" + tgproxy.NginxLocation(slug) + "# /XKIT-TGWEB"
	if i := strings.Index(conf, marker); i >= 0 {
		if j := strings.Index(conf[i:], "# /XKIT-TGWEB"); j >= 0 {
			conf = conf[:i] + conf[i+j+len("# /XKIT-TGWEB"):]
		}
	}
	firstServer := strings.Index(conf, "server {")
	if firstServer < 0 {
		return
	}
	rest := conf[firstServer:]
	rootLoc := strings.Index(rest, "location / {")
	if rootLoc < 0 {
		return
	}
	afterRoot := rest[rootLoc:]
	closeIdx := strings.Index(afterRoot, "}")
	if closeIdx < 0 {
		return
	}
	insertAt := firstServer + rootLoc + closeIdx + 1
	conf = conf[:insertAt] + "\n" + loc + conf[insertAt:]
	exec.Command("bash", "-c", fmt.Sprintf("cat > %s << 'XEOF'\n%s\nXEOF", confPath, conf)).Run()
	exec.Command("nginx", "-t").Run()
	exec.Command("systemctl", "reload", "nginx").Run()
}

func (s *Server) removeTGWebNginx() {
	confPath := "/etc/nginx/conf.d/xkit-panel.conf"
	out, err := exec.Command("cat", confPath).Output()
	if err != nil {
		return
	}
	conf := string(out)
	marker := "# XKIT-TGWEB"
	if i := strings.Index(conf, marker); i >= 0 {
		if j := strings.Index(conf[i:], "# /XKIT-TGWEB"); j >= 0 {
			conf = conf[:i] + conf[i+j+len("# /XKIT-TGWEB"):]
			exec.Command("bash", "-c", fmt.Sprintf("cat > %s << 'XEOF'\n%s\nXEOF", confPath, conf)).Run()
			exec.Command("systemctl", "reload", "nginx").Run()
		}
	}
}

func atoiDefault(s string, def int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n == 0 {
		return def
	}
	return n
}