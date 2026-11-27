package balancer
import (
 "context"
 "testing"
 "time"
 "github.com/kambarro/xkit-panel/internal/store"
)
func TestNotifications(t *testing.T){
 st,err:=store.Open(t.TempDir()+"/test.db"); if err!=nil{t.Fatal(err)}
 defer st.Close()
 now:=time.Now().Unix()
 // клиент с TG, expiry через 24ч (окно -24), квота 90%
 st.UpsertClient(store.Client{Email:"n@test.ru",UUID:"u",SubID:"s",Name:"Nina",Expiry:now+24*3600-1800,QuotaBytes:1000,UsedBytes:950,Enabled:true})
 st.DB().Exec("UPDATE clients SET tg_chat_id=12345 WHERE email='n@test.ru'")
 c:=NewController(st,nil)
 var sent []string
 c.NotifyClient=func(ctx context.Context,chat int64,text string)error{sent=append(sent,text);return nil}
 c.processNotifications(context.Background(),now)
 // должно быть 2: expiry-24 + quota90
 if len(sent)!=2{t.Errorf("ожидалось 2 уведомления, got %d: %v",len(sent),sent)}
 // идемпотентность: повторный вызов — 0 новых
 sent=nil
 c.processNotifications(context.Background(),now)
 if len(sent)!=0{t.Errorf("повторно отправлено %d (должно 0 — идемпотентность)",len(sent))}
 // без TG chat — не слать
 st.DB().Exec("UPDATE clients SET tg_chat_id=0 WHERE email='n@test.ru'")
 st.DB().Exec("DELETE FROM client_notifications")
 sent=nil
 c.processNotifications(context.Background(),now)
 if len(sent)!=0{t.Errorf("без TG отправлено %d",len(sent))}
}
