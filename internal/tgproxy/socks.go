package tgproxy

import (
	"context"
	"net"

	"golang.org/x/net/proxy"
)

// socksDialer — SOCKS5 dialer через addr (127.0.0.1:port).
func socksDialer(addr string) (proxy.ContextDialer, error) {
	d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return d.(proxy.ContextDialer), nil
}

var _ = context.Background
var _ net.Conn