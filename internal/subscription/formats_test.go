package subscription
import (
 "encoding/json"
 "strings"
 "testing"
)
func TestFormatsRoundTrip(t *testing.T){
 m:=MasterParams{Address:"vpn.example.com",Port:443,SNI:"vpn.example.com",PublicKey:"pubkey123",ShortID:"sid456",Fingerprint:"chrome",Flow:"xtls-rprx-vision"}
 link:=VlessLink("b831381d-6324-4d53-ad4f-8cda48b30811", "ivan@test.ru", "Ivan", m)
 links:=[]string{link}
 // clash
 cy:=ClashYAML(links)
 for _,want:=range []string{"type: vless","uuid: b831381d","reality-opts","public-key: pubkey123","GEOIP,RU,DIRECT","url-test"}{
  if !strings.Contains(cy,want){t.Errorf("clash missing %q",want)}
 }
 // singbox — валидный JSON
 sj:=SingboxJSON(links)
 var sc map[string]any
 if err:=json.Unmarshal([]byte(sj),&sc);err!=nil{t.Fatal("singbox JSON invalid:",err)}
 if !strings.Contains(sj,"reality"){t.Error("singbox reality missing")}
 if !strings.Contains(sj,"\"geoip\": \"ru\"")&&!strings.Contains(sj,"\"ru\""){t.Error("singbox RU route missing")}
 // xray — валидный JSON
 xj:=XrayJSON(links)
 var xc map[string]any
 if err:=json.Unmarshal([]byte(xj),&xc);err!=nil{t.Fatal("xray JSON invalid:",err)}
 if !strings.Contains(xj,"geoip:ru"){t.Error("xray RU routing missing")}
 if !strings.Contains(xj,"xtls-rprx-vision"){t.Error("xray flow missing")}
}
func TestParseLinkHysteria(t *testing.T){
 l:="hysteria2://secretpass@vpn.example.com:8443?sni=vpn.example.com&obfs=salamander&obfs-password=obfspass#Hy2"
 p:=ParseLink(l)
 if p==nil{t.Fatal("parse nil")}
 if p.Type!="hysteria2"||p.Password!="secretpass"||p.Port!=8443||p.Obfs!="salamander"||p.ObfsPass!="obfspass"{t.Errorf("bad parse: %+v",p)}
 cy:=ClashYAML([]string{l})
 if !strings.Contains(cy,"obfs: salamander"){t.Error("clash hy2 obfs missing")}
}
func TestParseLinkWS(t *testing.T){
 l:="vless://uuid-1@host.com:8443?type=ws&security=tls&sni=host.com&path=%2Fabc#WS"
 p:=ParseLink(l)
 if p==nil{t.Fatal("nil")}
 if p.Network!="ws"||p.Path!="/abc"{t.Errorf("ws parse: %+v",p)}
 cy:=ClashYAML([]string{l})
 if !strings.Contains(cy,"ws-opts"){t.Error("clash ws missing")}
}
