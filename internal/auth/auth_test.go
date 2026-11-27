package auth
import (
 "path/filepath"
 "testing"
 "github.com/kambarro/xkit-panel/internal/store"
)
func TestMustChangeFlow(t *testing.T){
 st,err:=store.Open(filepath.Join(t.TempDir(),"t.db"))
 if err!=nil{t.Fatal(err)}
 defer st.Close()
 a:=New(st)
 created,err:=a.EnsureAdmin("xkit-ab12","onetimer")
 if err!=nil||!created{t.Fatal("ensure:",created,err)}
 if !a.MustChange("xkit-ab12"){t.Error("новый админ должен быть must_change=1")}
 if a.MustChange("nonexistent"){t.Error("несуществующий не must_change")}
 // смена снимает флаг
 if err:=a.ChangePassword("xkit-ab12","newpass123");err!=nil{t.Fatal(err)}
 if a.MustChange("xkit-ab12"){t.Error("после смены must_change должен сняться")}
 // сброс возвращает флаг
 if err:=a.ResetPassword("xkit-ab12","resetpass");err!=nil{t.Fatal(err)}
 if !a.MustChange("xkit-ab12"){t.Error("после сброса must_change=1")}
 if a.AdminUsername()!="xkit-ab12"{t.Error("AdminUsername")}
 if err:=a.ResetPassword("ghost","x");err==nil{t.Error("сброс несуществующего должен ошибиться")}
 // verify пароля работает
 var hash string
 st.DB().QueryRow("SELECT pass_hash FROM admins WHERE username='xkit-ab12'").Scan(&hash)
 if !VerifyPassword("resetpass",hash){t.Error("новый пароль не.verify")}
 if VerifyPassword("onetimer",hash){t.Error("старый пароль ещё работает!")}
}
