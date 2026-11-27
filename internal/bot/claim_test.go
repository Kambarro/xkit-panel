package bot
import (
 "context"
 "testing"
 "github.com/kambarro/xkit-panel/internal/store"
)
func TestClaimFlow(t *testing.T){
 st,err:=store.Open(t.TempDir()+"/t.db"); if err!=nil{t.Fatal(err)}
 defer st.Close()
 st.UpsertClient(store.Client{Email:"c@test.ru",UUID:"u",SubID:"sub123",Name:"Client",Enabled:true})
 b:=New("faketoken",999,st,"vpn.example.com")
 // генерим токен
 token:=GenerateClaimToken()
 st.DB().Exec("UPDATE clients SET tg_claim_token=? WHERE email='c@test.ru'",token)
 // isLinkedClient до привязки — false
 if b.isLinkedClient(555){t.Error("не должен быть привязан до claim")}
 // handleClaim шлёт сообщение через sendMessage (token=faketoken → api ошибка, но привязка в БД происходит ДО отправки)
 // проверим привязку напрямую через БД логику handleClaim (без сети — sendMessage просто залогирует ошибку)
 b.handleClaim(context.Background(),555,token)
 var chat int64; var tok string
 st.DB().QueryRow("SELECT tg_chat_id,tg_claim_token FROM clients WHERE email='c@test.ru'").Scan(&chat,&tok)
 if chat!=555{t.Errorf("chat не привязан: %d",chat)}
 if tok!=""{t.Error("токен должен погаснуть после привязки (одноразовый)")}
 if !b.isLinkedClient(555){t.Error("должен быть привязан после claim")}
 // clientByChat
 email,name,subID,ok:=b.clientByChat(555)
 if !ok||email!="c@test.ru"||subID!="sub123"{t.Errorf("clientByChat: %s %s %v",email,subID,ok)}
 _=name
 // повторный claim тем же токеном — недействителен (токен погашен)
 b.handleClaim(context.Background(),777,token)
 var chat2 int64
 st.DB().QueryRow("SELECT tg_chat_id FROM clients WHERE email='c@test.ru'").Scan(&chat2)
 if chat2!=555{t.Errorf("повторный claim не должен менять привязку: %d",chat2)}
 // неверный токен
 b.handleClaim(context.Background(),888,"badtoken")
 if b.isLinkedClient(888){t.Error("неверный токен не должен привязывать")}
}
