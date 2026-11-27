package subscription
import "testing"
func TestLinksFromInbounds(t *testing.T){
 specs:=[]InboundSpec{
  {Tag:"vless-reality",Protocol:"vless",Port:443,Network:"tcp",Security:"reality",
   Settings:map[string]any{"realityPub":"pub","realitySid":"sid","realitySni":"example.com"},Stream:map[string]any{}},
  {Tag:"vless-ws",Protocol:"vless",Port:8443,Network:"ws",Security:"tls",
   Settings:map[string]any{},Stream:map[string]any{"wsSettings":map[string]any{"path":"/abc"},"tlsSettings":map[string]any{"serverName":"example.com"}}},
 }
  // базовый UUID: 1 ссылка на протокол, БЕЗ страновых профилей
 links:=LinksFromInbounds(specs,"uuid-1234","ivan@test.ru","Ivan","example.com")
 // 2 протокола × 1 = 2 (страна — параметр подписки, не отдельные ссылки)
 if len(links)!=2{t.Errorf("ожидалось 2 ссылки, got %d: %v",len(links),links)}
 // первая — vless reality NL (preferred)
 if !contains(links[0],"security=reality"){t.Error("первая должна быть reality")}
 // ws-tls ссылка есть
 found:=false
 for _,l:=range links{if contains(l,"type=ws")&&contains(l,"security=tls"){found=true}}
 if !found{t.Error("ws-tls ссылка отсутствует")}
}
func TestToggleChangesLinks(t *testing.T){
 //模拟 переключатель: 2 протокола → выключили ws →只剩 reality
 specs2:=[]InboundSpec{{Tag:"r",Protocol:"vless",Port:443,Network:"tcp",Security:"reality",Settings:map[string]any{"realityPub":"p","realitySid":"s","realitySni":"m"},Stream:map[string]any{}},
  {Tag:"w",Protocol:"vless",Port:8443,Network:"ws",Security:"tls",Settings:map[string]any{},Stream:map[string]any{"wsSettings":map[string]any{"path":"/x"}}}}
 l2:=LinksFromInbounds(specs2,"u","e","n","m")
 specs1:=specs2[:1] // выключили ws
 l1:=LinksFromInbounds(specs1,"u","e","n","m")
 if len(l2)<=len(l1){t.Error("выключение протокола должно уменьшать ссылки")}
}
func contains(s,sub string)bool{for i:=0;i+len(sub)<=len(s);i++{if s[i:i+len(sub)]==sub{return true}};return false}
