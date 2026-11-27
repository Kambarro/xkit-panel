package subscription
import "testing"
func TestDetectFormat(t *testing.T){
 cases:=[]struct{ua,accept,qf,fmt string;page bool}{
  {"Mozilla/5.0 (Windows NT 10.0) Chrome/120","text/html,application/xhtml+xml","","raw",true},
  {"v2rayNG/1.8","","","raw",false},
  {"Hiddify/4.0","","","raw",false},  // hiddify→raw не clash!
  {"ClashMeta/1.0","","","clash",false},
  {"sing-box/1.9","","","singbox",false},
  {"incy/1.0","","","raw",false}, // incy→raw: xray-json parser не поддерживает multi-outbound (урок userinfo.go)
  {"Mozilla/5.0","text/html","clash","clash",false}, // ?format приоритетнее
  {"Mozilla/5.0","text/html","page","raw",true},
  {"SomeApp/1.0","*/*","","raw",false},
 }
 for _,c:=range cases{
  f,p:=DetectFormat(c.ua,c.accept,c.qf)
  if f!=c.fmt||p!=c.page{t.Errorf("DetectFormat(%q,%q,%q)=(%q,%v) want (%q,%v)",c.ua,c.accept,c.qf,f,p,c.fmt,c.page)}
 }
}
func TestUserinfoHeader(t *testing.T){
 u:=Userinfo{Upload:100,Download:200,Total:1000,Expire:1700000000}
 want:="upload=100; download=200; total=1000; expire=1700000000"
 if u.Header()!=want{t.Errorf("got %q want %q",u.Header(),want)}
}
func TestPlatformByUA(t *testing.T){
 if PlatformByUA("Mozilla/5.0 (iPhone; CPU iPhone OS)")!="ios"{t.Error("ios")}
 if PlatformByUA("Mozilla/5.0 (Linux; Android 14)")!="android"{t.Error("android")}
 if PlatformByUA("Mozilla/5.0 (Windows NT 10.0)")!="windows"{t.Error("windows")}
}
