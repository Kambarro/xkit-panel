package backup
import (
 "archive/tar"
 "compress/gzip"
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "github.com/kambarro/xkit-panel/internal/store"
)
func TestBackupCreateRestore(t *testing.T){
 d:=t.TempDir()
 st,err:=store.Open(filepath.Join(d,"panel.db"))
 if err!=nil{t.Fatal(err)}
 defer st.Close()
 st.UpsertClient(store.Client{Email:"test@test.ru",UUID:"u",SubID:"s",Enabled:true})
 m:=NewManager(st,filepath.Join(d,"backups"),filepath.Join(d,"panel.db"))
 path,err:=m.Create(context.Background())
 if err!=nil{t.Fatal(err)}
 // проверю состав архива
 f,_:=os.Open(path); defer f.Close()
 gz,err:=gzip.NewReader(f); if err!=nil{t.Fatal(err)}
 tr:=tar.NewReader(gz)
 names:=[]string{}
 hasDB,hasManifest,hasRestore:=false,false,false
 for {
  h,err:=tr.Next(); if err!=nil{break}
  names=append(names,h.Name)
  if strings.HasSuffix(h.Name,"panel.db"){hasDB=true}
  if h.Name=="MANIFEST.txt"{hasManifest=true}
  if h.Name=="RESTORE.txt"{hasRestore=true}
 }
 if !hasDB{t.Error("нет panel.db в архиве")}
 if !hasManifest{t.Error("нет MANIFEST")}
 if !hasRestore{t.Error("нет RESTORE")}
 t.Log("состав:",names)
 // retention: создам ещё 5, проверю минимум
 for i:=0;i<5;i++{m.Create(context.Background())}
 list:=m.List()
 if len(list)<3{t.Errorf("retention: копий %d < минимума 3",len(list))}
}
