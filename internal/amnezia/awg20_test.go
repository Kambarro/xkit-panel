package amnezia

import "testing"

func TestAWG20Params(t *testing.T) {
	p, err := GenParamsVersion("2.0")
	if err != nil { t.Fatal(err) }
	if p.S3 != 0 || p.S4 != 0 || p.RandomTrailers || p.Version != "2.0" { t.Fatalf("2.0 params wrong: %+v", p) }
	peer := Peer{Name: "t", PrivateKey: "x", PublicKey: "y", Address: "10.8.1.2/32", ServerPub: "z", Endpoint: "example.com:443", Params: p, DNS: "1.1.1.1"}
	conf := peer.ClientConf()
	for _, bad := range []string{"S3 =", "S4 =", "I1 =", "RandomTrailers"} {
		if contains(conf, bad) { t.Fatalf("2.0 conf must not contain %q:\n%s", bad, conf) }
	}
	for _, need := range []string{"Jc =", "Jmin =", "Jmax =", "S1 =", "S2 =", "H1 =", "H2 =", "H3 =", "H4 ="} {
		if !contains(conf, need) { t.Fatalf("2.0 conf missing %q", need) }
	}
	p31, _ := GenParamsVersion("3.1")
	if p31.S3 == 0 || !p31.RandomTrailers { t.Fatal("3.1 params wrong") }
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (func() bool { for i := 0; i+len(sub) <= len(s); i++ { if s[i:i+len(sub)] == sub { return true } }; return false })() }
