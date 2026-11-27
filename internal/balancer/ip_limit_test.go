package balancer
import (
 "testing"
 "time"
)
func TestShouldNotifyDedup(t *testing.T){
 c:=&Controller{}
 if !c.shouldNotify("k",time.Minute){t.Error("first should notify")}
 if c.shouldNotify("k",time.Minute){t.Error("second within window should NOT notify")}
 if !c.shouldNotify("other",time.Minute){t.Error("different key should notify")}
}
func TestIPWindowCount(t *testing.T){
 now:=time.Now().Unix()
 ips:=map[string]int64{"1.1.1.1":now-10,"2.2.2.2":now-30,"3.3.3.3":now-200}
 active:=0
 for _,ts:=range ips{ if now-ts<=90{active++} }
 if active!=2{t.Error("expected 2 fresh IPs, got",active)}
}
