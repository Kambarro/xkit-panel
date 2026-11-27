package store

import "encoding/json"

// ClientRouting — per-client роутинг (P2, козырь: наш дефолт + кастом клиента поверх).
// routing_mode: default (только наш) | custom (наш + его правила).
// custom_rules: JSON {direct_sites[],proxy_sites[],block_sites[],direct_ip[],proxy_ip[],block_ip[]}.
// allow_custom_routing: тумблер владельца (0=запретить клиенту кастом).

type CustomRules struct {
 DirectSites []string `json:"direct_sites"`
 ProxySites  []string `json:"proxy_sites"`
 BlockSites  []string `json:"block_sites"`
 DirectIP    []string `json:"direct_ip"`
 ProxyIP     []string `json:"proxy_ip"`
 BlockIP     []string `json:"block_ip"`
}

func (s *Store) ClientRouting(email string) (mode string, rules CustomRules, allowed bool) {
 var raw string; var allow int
 s.db.QueryRow(`SELECT routing_mode,custom_rules,allow_custom_routing FROM clients WHERE email=?`,email).Scan(&mode,&raw,&allow)
 if mode==""{mode="default"}
 allowed=allow==1
 if raw!=""{json.Unmarshal([]byte(raw),&rules)}
 return
}

func (s *Store) SetClientRouting(email,mode string,rules CustomRules) error {
 raw,_:=json.Marshal(rules)
 _,err:=s.db.Exec(`UPDATE clients SET routing_mode=?,custom_rules=? WHERE email=?`,mode,string(raw),email)
 return err
}

func (s *Store) SetAllowCustomRouting(email string,allow bool) error {
 en:=0; if allow{en=1}
 _,err:=s.db.Exec(`UPDATE clients SET allow_custom_routing=? WHERE email=?`,en,email)
 return err
}
