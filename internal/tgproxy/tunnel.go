package tgproxy

// Транспорт каскада для Telegram-прокси: SOCKS5 через SSH-туннель на живую ноду.
// УРОК (владелец): «нет смысла выбирать страну — пусть ходит через любую ноду,
// может даже лучшую; нода отвалится — пойдёт через другую». Без выбора страны,
// авто-failover. Переиспользует паттерн bot/transport, но ВСЕГДА через туннель
// (Telegram-прокси не должен палить IP мастера даже если Telegram доступен напрямую).

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

// Node — нода-кандидат для туннеля.
type Node struct {
	ID   string
	Host string
}

// Tunnel — SSH -D SOCKS5 на живую ноду с авто-failover.
type Tunnel struct {
	mu       sync.Mutex
	sshCmd   *exec.Cmd
	socksLn  string // 127.0.0.1:port (текущий SOCKS)
	nodeHost string
	sshKey   string
	nodes    func() []Node // живые ноды (из store, отсортированы по quality)
	stopCh   chan struct{}
	wg       sync.WaitGroup
	onSwitch func(socksAddr, nodeHost string) // callback при смене туннеля (перезапуск mtg)
}

// NewTunnel — sshKey путь к ключу нод, nodes — источник живых нод.
func NewTunnel(sshKey string, nodes func() []Node) *Tunnel {
	return &Tunnel{sshKey: sshKey, nodes: nodes, stopCh: make(chan struct{})}
}

// OnSwitch — callback при подъёме/смене туннеля (mtg перезапускается с новым SOCKS).
func (t *Tunnel) OnSwitch(fn func(socksAddr, nodeHost string)) { t.onSwitch = fn }

// SocksAddr — текущий SOCKS5 адрес ("" если туннель не поднят).
func (t *Tunnel) SocksAddr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.socksLn
}

// NodeHost — текущая нода туннеля.
func (t *Tunnel) NodeHost() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.nodeHost
}

// Start — монитор: раз в 20с проверяет туннель; при отвале — переподключает на другую ноду.
func (t *Tunnel) Start(ctx context.Context) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		tick := time.NewTicker(20 * time.Second)
		defer tick.Stop()
		t.check(ctx)
		for {
			select {
			case <-t.stopCh:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
				t.check(ctx)
			}
		}
	}()
}

// Stop — гасит туннель и монитор.
func (t *Tunnel) Stop() {
	close(t.stopCh)
	t.wg.Wait()
	t.kill()
}

func (t *Tunnel) check(ctx context.Context) {
	t.mu.Lock()
	curHost := t.nodeHost
	alive := t.sshCmd != nil && t.sshCmd.Process != nil
	addr := t.socksLn
	t.mu.Unlock()

	// туннель жив? SOCKS-порт отвечает + TCP через него к Telegram DC
	if alive && curHost != "" && addr != "" && socksProbe(ctx, addr) {
		return
	}
	// выбираем ноду (исключая умершую; nodes() уже отсортированы по quality)
	cands := t.nodes()
	var pick *Node
	for i := range cands {
		if cands[i].Host != curHost || !alive {
			pick = &cands[i]
			break
		}
	}
	if pick == nil && len(cands) > 0 {
		pick = &cands[0]
	}
	if pick == nil {
		log.Println("tgproxy-tunnel: живых нод нет — ждём")
		return
	}
	if err := t.dial(pick.Host); err != nil {
		log.Printf("tgproxy-tunnel: туннель через %s не поднялся: %v", pick.Host, err)
		return
	}
	log.Printf("tgproxy-tunnel: SOCKS %s через ноду %s", t.SocksAddr(), pick.Host)
	if t.onSwitch != nil {
		t.onSwitch(t.SocksAddr(), pick.Host)
	}
}

// socksProbe — TCP-соединение через SOCKS5 к Telegram DC (149.154.167.50:443).
func socksProbe(ctx context.Context, addr string) bool {
	dialer, err := socksDialer(addr)
	if err != nil {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(pctx, "tcp", "149.154.167.50:443")
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (t *Tunnel) dial(host string) error {
	t.kill()
	if _, err := os.Stat(t.sshKey); err != nil {
		return fmt.Errorf("SSH-ключ нод не найден: %s", t.sshKey)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	addr := ln.Addr().String()
	ln.Close()

	cmd := exec.Command("ssh",
		"-i", t.sshKey,
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=/var/lib/xkit-panel/known_hosts",
		"-o", "LogLevel=ERROR",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
		"-o", "ConnectTimeout=12",
		"-N", "-D", addr, "root@"+host)
	if err := cmd.Start(); err != nil {
		return err
	}
	up := false
	for i := 0; i < 30; i++ {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			c.Close()
			up = true
			break
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !up {
		cmd.Process.Kill()
		return fmt.Errorf("SOCKS-порт не поднялся")
	}
	t.mu.Lock()
	t.sshCmd = cmd
	t.socksLn = addr
	t.nodeHost = host
	t.mu.Unlock()
	return nil
}

func (t *Tunnel) kill() {
	t.mu.Lock()
	cmd := t.sshCmd
	t.sshCmd = nil
	t.socksLn = ""
	t.nodeHost = ""
	t.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
}