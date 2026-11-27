//go:build integration
package amnezia
import (
 "strings"
 "testing"
)
func TestLiveServer(t *testing.T){
 priv,pub,err:=GenKeyPair(); if err!=nil{t.Fatal(err)}
 params,err:=GenParams(); if err!=nil{t.Fatal(err)}
 srv,err:=NewServer(ServerConfig{Iface:"awgtest0",Port:51999,PrivKey:priv,Params:params}); if err!=nil{t.Fatal(err)}
 if err:=srv.Start(); err!=nil{t.Fatal("Start:",err)}
 defer srv.Stop()
 // pub key сервера должен совпасть с генерированным
 if srv.PubKey()==""{t.Error("pubkey empty")}
 t.Logf("server pubkey: %s (gen: %s)",srv.PubKey(),pub)
 // пир
 cpriv,cpub,_:=GenKeyPair()
 psk,_:=GenPresharedKey()
 peer:=Peer{PrivateKey:cpriv,PublicKey:cpub,PresharedKey:psk,Address:"10.99.0.2/32"}
 if err:=srv.AddPeer(peer); err!=nil{t.Fatal("AddPeer:",err)}
 // проверим через IpcGet что пир есть
 var buf strings.Builder
 if err:=srv.dev.IpcGetOperation(&buf); err!=nil{t.Fatal(err)}
 out:=buf.String()
 if !strings.Contains(out,"public_key="){t.Error("no peers in IpcGet")}
 t.Logf("IpcGet:\n%s",out[:min(500,len(out))])
 // remove
 if err:=srv.RemovePeer(cpub); err!=nil{t.Fatal("RemovePeer:",err)}
}
func min(a,b int)int{if a<b{return a};return b}
