package tunnel

import (
	"encoding/json"
	"testing"
)

func TestNodeInboundAllTransports(t *testing.T) {
	transports := []Transport{TCPReality, XHTTPReality, WSTLS, GRPCTLS, Hysteria2}
	for _, tr := range transports {
		p := Params{Transport: tr, Host: "node.example", Port: 443, UUID: "uuid-1",
			PublicKey: "pub", PrivateKey: "priv", ShortID: "sid", SNI: "node.example",
			TLSCert: "/etc/cert.pem", TLSKey: "/etc/key.pem", Hy2Pass: "pass", Hy2Obfs: "obfs"}
		ib, err := p.NodeInbound()
		if err != nil {
			t.Errorf("%s: NodeInbound err %v", tr, err)
			continue
		}
		// валидный JSON
		if _, err := json.Marshal(ib); err != nil {
			t.Errorf("%s: marshal %v", tr, err)
		}
		if ib["tag"] != "vless-tunnel" {
			t.Errorf("%s: tag wrong", tr)
		}
		ss, _ := ib["streamSettings"].(map[string]any)
		if ss == nil {
			t.Errorf("%s: no streamSettings", tr)
		}
	}
}

func TestMasterOutboundAllTransports(t *testing.T) {
	transports := []Transport{TCPReality, XHTTPReality, WSTLS, GRPCTLS, Hysteria2}
	for _, tr := range transports {
		p := Params{Transport: tr, Host: "node.example", Port: 443, UUID: "uuid-1",
			PublicKey: "pub", ShortID: "sid", SNI: "node.example", Hy2Pass: "pass"}
		ob, err := p.MasterOutbound("node-1")
		if err != nil {
			t.Errorf("%s: MasterOutbound err %v", tr, err)
			continue
		}
		if ob["tag"] != "node-1" {
			t.Errorf("%s: tag wrong", tr)
		}
		if _, err := json.Marshal(ob); err != nil {
			t.Errorf("%s: marshal %v", tr, err)
		}
	}
}

func TestXHTTPReality(t *testing.T) {
	p := Params{Transport: XHTTPReality, Host: "n", Port: 443, UUID: "u", PublicKey: "pk", PrivateKey: "sk", ShortID: "s", SNI: "n"}
	ib, _ := p.NodeInbound()
	ss := ib["streamSettings"].(map[string]any)
	if ss["network"] != "xhttp" {
		t.Error("xhttp network")
	}
	if ss["security"] != "reality" {
		t.Error("reality security")
	}
	if _, ok := ss["xhttpSettings"]; !ok {
		t.Error("xhttpSettings present")
	}
	ob, _ := p.MasterOutbound("n1")
	obs := ob["streamSettings"].(map[string]any)
	if obs["network"] != "xhttp" {
		t.Error("outbound xhttp")
	}
}

func TestHysteria2(t *testing.T) {
	p := Params{Transport: Hysteria2, Host: "n", Port: 443, Hy2Pass: "secret", Hy2Obfs: "obfs", SNI: "n", TLSCert: "/c", TLSKey: "/k"}
	ib, _ := p.NodeInbound()
	if ib["protocol"] != "hysteria" {
		t.Error("hysteria protocol")
	}
	ss := ib["streamSettings"].(map[string]any)
	// УРОК (live-исследование): obfs в finalmask.udp[] (salamander), НЕ hysteriaSettings.obfs
	fm, ok := ss["finalmask"].(map[string]any)
	if !ok {
		t.Error("finalmask present for obfs")
	} else {
		udps := fm["udp"].([]any)
		first := udps[0].(map[string]any)
		if first["type"] != "salamander" {
			t.Error("salamander mask type")
		}
	}
	// outbound auth в hysteriaSettings.auth (НЕ settings.auth)
	ob, _ := p.MasterOutbound("n1")
	obs := ob["streamSettings"].(map[string]any)
	ohs := obs["hysteriaSettings"].(map[string]any)
	if ohs["auth"] != "secret" {
		t.Error("outbound auth in hysteriaSettings.auth")
	}
	osettings := ob["settings"].(map[string]any)
	if _, has := osettings["auth"]; has {
		t.Error("auth must NOT be in settings (ignored by Xray)")
	}
}

func TestUnknownTransport(t *testing.T) {
	p := Params{Transport: "bogus"}
	if _, err := p.NodeInbound(); err == nil {
		t.Error("unknown transport should error")
	}
	if _, err := p.MasterOutbound("x"); err == nil {
		t.Error("unknown transport outbound should error")
	}
}