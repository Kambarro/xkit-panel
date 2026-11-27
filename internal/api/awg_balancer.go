package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Привязка AWG-каскада к балансировщику (принцип проекта: «каскад как транспорт»).
// Балансировщик роутит клиентов на outbound с tag=nodeID. Для AWG заменяем этот outbound
// на SOCKS5 → 127.0.0.1:<socksPort> (локальный вход AWG-каскада). Существующие per-user/
// country-select правила балансировщика тогда гонят трафик через AWG-туннель → нода → интернет.
// При остановке каскада outbound возвращается к xray-транспорту ноды (tunnel_cfg).

// setMasterOutboundSOCKS — заменить outbound мастера tag=nodeID на SOCKS5 к AWG-каскаду.
func (s *Server) setMasterOutboundSOCKS(nodeID string, socksPort int) {
	mob := map[string]any{
		"tag":      nodeID,
		"protocol": "socks",
		"settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": socksPort}}},
	}
	s.swapMasterOutbound(nodeID, mob)
	s.store.AddEvent("awg_cascade", "ok", fmt.Sprintf("нода %s: outbound мастера → SOCKS5 AWG-каскада :%d (балансировщик)", nodeID, socksPort), fmt.Sprintf(`{"node":%q}`, nodeID))
}

// restoreMasterOutboundXray — вернуть outbound мастера tag=nodeID к xray-транспорту ноды.
func (s *Server) restoreMasterOutboundXray(nodeID string) {
	var host, tr, tunnelCfg string
	var port int
	if err := s.store.DB().QueryRow(`SELECT host,port,tunnel,tunnel_cfg FROM nodes WHERE id=?`, nodeID).Scan(&host, &port, &tr, &tunnelCfg); err != nil {
		return
	}
	if tr == "" || tr == "awg" {
		// нет xray-транспорта — просто убрать outbound (нода на AWG, xray-outbound не нужен)
		s.swapMasterOutbound(nodeID, nil)
		return
	}
	tp := s.paramsFromCfg(tr, host, port, tunnelCfg)
	tp.MTU = s.store.NodeMTU(nodeID)
	mob, err := tp.MasterOutbound(nodeID)
	if err != nil {
		return
	}
	s.swapMasterOutbound(nodeID, mob)
	s.store.AddEvent("awg_cascade", "ok", fmt.Sprintf("нода %s: outbound мастера → xray %s (каскад остановлен)", nodeID, tr), fmt.Sprintf(`{"node":%q}`, nodeID))
}

// swapMasterOutbound — заменить outbound tag=nodeID на mob (nil = удалить) + restart + sync rules.
func (s *Server) swapMasterOutbound(nodeID string, mob map[string]any) {
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
	var filtered []any
	for _, o := range ob {
		if m, ok := o.(map[string]any); ok && m["tag"] == nodeID {
			continue
		}
		filtered = append(filtered, o)
	}
	if mob != nil {
		filtered = append(filtered, mob)
	}
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
	go s.RestoreInbounds() // УРОК (QA): рестарт xray убивает горячие preset-inbound — восстановить
}