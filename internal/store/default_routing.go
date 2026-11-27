package store

import "encoding/json"

// DefaultRouting — базовый набор маршрутизации владельца (для ВСЕХ клиентов).
// Хранится в settings default_routing (JSON), редактируется админом в Настройках.
// Клиентский кастом добавляется поверх. Источник списков — geoip/geosite/domain.
type DefaultRouting struct {
 DirectSites []string `json:"direct_sites"`
 ProxySites  []string `json:"proxy_sites"`
 BlockSites  []string `json:"block_sites"`
 DirectIP    []string `json:"direct_ip"`
 ProxyIP     []string `json:"proxy_ip"`
 BlockIP     []string `json:"block_ip"`
 GeoipURL    string   `json:"geoip_url"`
 GeositeURL  string   `json:"geosite_url"`
}

// BuiltinDefaultRouting — наш базовый набор (по образцу roscomvpn-routing, курируемый под РФ).
func BuiltinDefaultRouting() DefaultRouting {
 return DefaultRouting{
  DirectSites: []string{"geosite:private", "geosite:category-ru", "geosite:microsoft", "geosite:apple", "geosite:steam", "geosite:epicgames", "geosite:riot"},
  ProxySites:  []string{"geosite:google-play", "geosite:github", "geosite:youtube", "geosite:telegram"},
  BlockSites:  []string{"geosite:category-ads", "geosite:win-spy",
   // STUN WebRTC (аудит #5) — синхронно с routing.DefaultBlockSites
   "domain:stun.l.google.com", "domain:stun1.l.google.com", "domain:stun2.l.google.com",
   "domain:stun3.l.google.com", "domain:stun4.l.google.com",
   "domain:stun.services.mozilla.com", "domain:stun.stunprotocol.org"},
  DirectIP:    []string{"geoip:private", "geoip:ru"},
  ProxyIP:     []string{},
  BlockIP:     []string{},
 }
}

func (s *Store) DefaultRouting() DefaultRouting {
 raw := s.GetSetting("default_routing", "")
 if raw == "" { return BuiltinDefaultRouting() }
 var dr DefaultRouting
 if json.Unmarshal([]byte(raw), &dr) != nil { return BuiltinDefaultRouting() }
 return dr
}

func (s *Store) SetDefaultRouting(dr DefaultRouting) error {
 raw, _ := json.Marshal(dr)
 return s.SetSetting("default_routing", string(raw))
}
