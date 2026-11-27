package api

import (
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
)

// Проверка: dns UseIPv4 + freedom settings парсятся штатным Build() xray 26.x.
func TestIPv4DNSParsesInXray(t *testing.T) {
	cfg := `{"log":{"loglevel":"warning"},"dns":{"servers":["1.1.1.1","8.8.8.8"],"queryStrategy":"UseIPv4"},
	"inbounds":[{"tag":"api-in","listen":"127.0.0.1","port":62789,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}}],
	"outbounds":[{"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}},{"tag":"blackhole","protocol":"blackhole"}],
	"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","port":"0-65535","outboundTag":"direct"}]}}`
	if _, err := serial.LoadJSONConfig(stringReader(cfg)); err != nil {
		t.Fatalf("xray Build: %v", err)
	}
}
