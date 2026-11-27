package routing
import (
 "encoding/base64"
 "encoding/json"
 "strings"
 "testing"
)
func TestMergedRules(t *testing.T){
 // default: только наш
 d,_,b,_,_,_:=MergedRules("default",CustomRules{})
 if len(d)==0||len(b)==0{t.Error("default empty")}
 // custom: дополняет, не удаляет дефолт
 cr:=CustomRules{DirectSites:[]string{"domain:mybank.ru"},BlockSites:[]string{"domain:ads.example.com"}}
 d2,p2,b2,_,_,_:=MergedRules("custom",cr)
 if len(d2)<=len(d){t.Error("custom must ADD to default")}
 found:=false
 for _,s:=range d2{if s=="domain:mybank.ru"{found=true}}
 if !found{t.Error("custom rule missing")}
 // дефолт всё ещё на месте
 foundDef:=false
 for _,s:=range d2{if s=="geosite:category-ru"{foundDef=true}}
 if !foundDef{t.Error("default foundation removed!")}
 _=p2;_=b2
}
func TestHappDeeplink(t *testing.T){
 d,p,b,dip,pip,bip:=MergedRules("default",CustomRules{})
 link:=HappDeeplink("XKIT",d,p,b,dip,pip,bip)
 if !strings.HasPrefix(link,"happ://routing/onadd/"){t.Error("prefix")}
 payload:=strings.TrimPrefix(link,"happ://routing/onadd/")
 raw,err:=base64.RawURLEncoding.DecodeString(payload)
 if err!=nil{t.Fatal("base64url:",err)}
 var cfg map[string]any
 if err:=json.Unmarshal(raw,&cfg);err!=nil{t.Fatal("json:",err)}
 if cfg["RouteOrder"]!="block-proxy-direct"{t.Error("RouteOrder")}
 if cfg["GlobalProxy"]!="true"{t.Error("GlobalProxy")}
 if _,ok:=cfg["DirectSites"];!ok{t.Error("DirectSites")}
 // аудит #5: STUN-домены в BlockSites (Happ формат не умеет порты/udp — только домены)
 bs,_:=cfg["BlockSites"].([]any)
 foundStun:=false
 for _,s:=range bs{if s=="domain:stun.l.google.com"{foundStun=true}}
 if !foundStun{t.Error("Happ BlockSites: stun domains missing (WebRTC leak)")}
}
func TestClashRules(t *testing.T){
 d,p,b,dip,_,_:=MergedRules("default",CustomRules{})
 rules:=ClashRules(d,p,b,dip,nil,nil)
 hasGeo:=false
 for _,r:=range rules{if strings.HasPrefix(r,"GEOSITE,category-ru,DIRECT"){hasGeo=true}}
 if !hasGeo{t.Error("clash geosite rule")}
}
