package store
import (
 "testing"
 "time"
)
func TestNodeBillingReset(t *testing.T){
 st,err:=Open(t.TempDir()+"/b.db"); if err!=nil{t.Fatal(err)}
 defer st.Close()
 st.UpsertNode(Node{ID:"n1",Name:"NL1",Country:"NL",CountryCode:1,Host:"h",Port:443,Enabled:true})
 st.SetNodeBilling("n1",100,15,2.0) // 100GB, сброс 15-го, ×2
 b:=st.GetNodeBilling("n1")
 if b.LimitGB!=100||b.ResetDay!=15||b.Multiplier!=2.0{t.Errorf("billing: %+v",b)}
 st.AddNodeTraffic("n1",50*1024*1024*1024) // 50GB
 b=st.GetNodeBilling("n1")
 if b.Pct()<49||b.Pct()>51{t.Errorf("pct=%.1f want ~50",b.Pct())}
 // сброс периода: now = 20 числа (после 15), period_start=0 → due
 now:=time.Date(2026,3,20,10,0,0,0,time.UTC).Unix()
 due,_:=st.NodesDueForBillingReset(now)
 if len(due)!=1||due[0]!="n1"{t.Errorf("due: %v",due)}
 st.ResetNodeBillingPeriod("n1",now)
 b=st.GetNodeBilling("n1")
 if b.UsedBytes!=0{t.Errorf("used не сброшен: %d",b.UsedBytes)}
 // после сброса period_start=now (20 число) → следующая граница 15 апреля, не due
 due,_=st.NodesDueForBillingReset(now)
 if len(due)!=0{t.Errorf("не должно быть due после сброса: %v",due)}
 // 16 апреля → due снова
 nowApr:=time.Date(2026,4,16,10,0,0,0,time.UTC).Unix()
 due,_=st.NodesDueForBillingReset(nowApr)
 if len(due)!=1{t.Errorf("16 апреля должно быть due: %v",due)}
}
