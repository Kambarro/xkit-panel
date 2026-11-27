package reality
import "testing"
func TestExpandTargets(t *testing.T){
 // список
 ts,err:=ExpandTargets("1.2.3.4 example.com"); if err!=nil||len(ts)!=2{t.Fatal("list:",ts,err)}
 // CIDR /30 = 2 хоста
 ts,err=ExpandTargets("192.168.1.0/30"); if err!=nil||len(ts)!=2{t.Fatal("cidr:",ts,err)}
 // слишком большая подсеть
 if _,err:=ExpandTargets("10.0.0.0/16"); err==nil{t.Error("/16 должен отклоняться")}
 // bad charset (инъекция)
 if _,err:=ExpandTargets("1.2.3.4; rm -rf"); err==nil{t.Error("инъекция должна отклоняться")}
 if _,err:=ExpandTargets(""); err==nil{t.Error("пусто")}
}
func TestCandidatesFilter(t *testing.T){
 all:=[]Candidate{
  {IP:"1",SNI:"good-site.com",Verdict:"ДА+"},
  {IP:"2",SNI:"www.google.com",Verdict:"ДА+"},  // бренд — фильтр
  {IP:"3",SNI:"test.duckdns.org",Verdict:"ДА"}, // dynDNS — фильтр
  {IP:"4",SNI:"casino-bet.com",Verdict:"ДА"},   // плохие слова — фильтр
  {IP:"5",SNI:"ok.ru",Verdict:"НЕТ"},           // вердикт НЕТ — фильтр
  {IP:"6",SNI:"another-good.org",Verdict:"ДА"},
 }
 c:=Candidates(all)
 if len(c)!=2{t.Errorf("ожидалось 2 кандидата, got %d: %+v",len(c),c)}
}
