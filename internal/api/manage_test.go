package api
import "testing"
func TestValidClientEmail(t *testing.T){
 good:=[]string{"ivan@mail.ru","u+tag@x.com","a.b_c@d.e"}
 bad:=[]string{"","иван@почта.рф","no-at","a b@c.d","a<b>@c.d"}
 for _,e:=range good{if !validClientEmail(e){t.Errorf("good rejected: %s",e)}}
 for _,e:=range bad{if validClientEmail(e){t.Errorf("bad accepted: %s",e)}}
}
