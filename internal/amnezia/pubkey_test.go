//go:build integration
package amnezia
import "testing"
func TestPubKeyMatches(t *testing.T){
 priv,pub,_:=GenKeyPair()
 params,_:=GenParams()
 srv,_:=NewServer(ServerConfig{Iface:"awgtest1",Port:51998,PrivKey:priv,Params:params})
 if err:=srv.Start(); err!=nil{t.Fatal(err)}
 defer srv.Stop()
 if srv.PubKey()!=pub{t.Errorf("server pubkey %s != gen %s",srv.PubKey(),pub)}
}
