package subscription
import (
 "encoding/json"
 "strings"
 "testing"
)
func TestXrayClientBalancer(t *testing.T){
 m:=MasterParams{Address:"vpn.example.com",Port:443,SNI:"vpn.example.com",PublicKey:"pk",ShortID:"sid",Fingerprint:"chrome",Flow:"xtls-rprx-vision"}
 // 2 страны → 2+ прокси-outbound → балансировщик
 l1:=VlessLink("uuid-1", "e", "N1", m)
 l2:=VlessLink("uuid-1", "e", "N2", m)
 xj:=XrayJSON([]string{l1,l2})
 var cfg map[string]any
 if err:=json.Unmarshal([]byte(xj),&cfg);err!=nil{t.Fatal("invalid JSON:",err)}
 if _,ok:=cfg["burstObservatory"];!ok{t.Error("burstObservatory missing for >1 proxy")}
 routing:=cfg["routing"].(map[string]any)
 if _,ok:=routing["balancers"];!ok{t.Error("balancers missing")}
 if !strings.Contains(xj,"leastPing"){t.Error("leastPing strategy")}
 if !strings.Contains(xj,"auto-balancer"){t.Error("balancerTag")}
 // 1 прокси → без балансировщика (просто outboundTag)
 xj1:=XrayJSON([]string{l1})
 var cfg1 map[string]any
 json.Unmarshal([]byte(xj1),&cfg1)
 if _,ok:=cfg1["burstObservatory"];ok{t.Error("single proxy should NOT have balancer")}
}
