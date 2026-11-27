package subscription
import (
 "encoding/base64"
 "strings"
 "testing"
)
func TestHappCryptoLink(t *testing.T){
 if !HappCryptoAvailable(){t.Fatal("key not loaded")}
 url:="https://example.com/sub/037573792da249d6"
 link,err:=HappCryptoLink(url)
 if err!=nil{t.Fatal(err)}
 if !strings.HasPrefix(link,"happ://crypt3/"){t.Error("prefix:",link)}
 payload:=strings.TrimPrefix(link,"happ://crypt3/")
 raw,err:=base64.StdEncoding.DecodeString(payload)
 if err!=nil{t.Fatal("base64:",err)}
 if len(raw)!=512{t.Error("RSA-4096 block must be 512 bytes, got",len(raw))}
 // длинный URL (>501) → 2 блока
 long:="https://example.com/sub/"+strings.Repeat("a",600)
 link2,err:=HappCryptoLink(long)
 if err!=nil{t.Fatal(err)}
 raw2,_:=base64.StdEncoding.DecodeString(strings.TrimPrefix(link2,"happ://crypt3/"))
 if len(raw2)!=1024{t.Error("2 blocks=1024, got",len(raw2))}
}
