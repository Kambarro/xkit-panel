package subscription
import (
 "strings"
 "testing"
)
func TestLinksFromHosts(t *testing.T){
 specs:=[]InboundSpec{{Tag:"vless-reality",Protocol:"vless",Port:443,Network:"tcp",Security:"reality",
  Settings:map[string]any{"clients":[]any{map[string]any{"id":"uuid","flow":"xtls-rprx-vision","email":"e"}},
   "realityPub":"pk","realitySid":"sid","realitySni":"default.com"},
  Stream:map[string]any{"realitySettings":map[string]any{"settings":map[string]any{"fingerprint":"chrome"}}}}}
  hosts:=[]HostEntry{
  {Address:"cdn.example.com",Port:443,SNI:"front.example.com",Label:"CDN"},
  {Address:"direct.example.com",Port:8443,SNI:"",Label:"прямой"},
 }
 links:=LinksFromInboundsHosts(specs,"uuid","e","n",hosts,"fallback.com")
 if len(links)<2{t.Fatal("ожидались ссылки для 2 hosts:",len(links))}
 if !strings.Contains(links[0],"cdn.example.com"){t.Error("host1 address")}
 if !strings.Contains(links[0],"sni=front.example.com"){t.Error("per-host SNI:",links[0])}
 if !strings.Contains(links[0],"CDN"){t.Error("label")}
 if !strings.Contains(links[1],"direct.example.com:8443"){t.Error("host2 port:",links[1])}
 if !strings.Contains(links[1],"sni=direct.example.com"){t.Error("host2 SNI=address")}
 // пустые hosts → fallback
 fb:=LinksFromInboundsHosts(specs,"uuid","e","n",nil,"fallback.com")
 if len(fb)==0||!strings.Contains(fb[0],"fallback.com"){t.Error("fallback")}
}
