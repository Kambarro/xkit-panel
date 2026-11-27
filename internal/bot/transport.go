package bot

// Транспорт доставки Telegram: прямой HTTPS, а если API недоступен (блокировка
// на мастере) — SOCKS5 через SSH-туннель на живую зарубежную ноду.
// УРОК main XKIT (telegram transport): каналы проверяются и восстанавливаются сами
// (~20с), при недоступности всех — терпеливо ждём подъёма любого, не crash-loop.

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const tgProbeURL = "https://api.telegram.org/"

// transport — переключатель прямой/туннельный клиент + SSH -D процесс.
type transport struct {
	mu       sync.Mutex
	client   *http.Client // текущий активный клиент (direct или socks)
	mode     string       // "direct" | "tunnel" | ""
	nodeHost string       // хост ноды текущего туннеля
	sshCmd   *exec.Cmd
	socksLn  string // 127.0.0.1:port
	sshKey   string
	nodes    func() []tunnelNode // живые ноды-кандидаты (из store)
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

type tunnelNode struct {
	ID   string
	Host string
}

func newTransport(sshKey string, nodes func() []tunnelNode) *transport {
	return &transport{
		client: &http.Client{Timeout: 40 * time.Second},
		mode:   "direct",
		sshKey: sshKey,
		nodes:  nodes,
		stopCh: make(chan struct{}),
	}
}

// httpClient — текущий клиент для всех Telegram-запросов.
func (t *transport) httpClient() *http.Client {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.client
}

func (t *transport) status() (mode, node string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.mode, t.nodeHost
}

// start — монитор канала: раз в 20с проверяет прямой доступ; при отвале поднимает
// SSH -D туннель на лучшую живую ноду; при смерти туннеля/ноды — переподключает.
func (t *transport) start(ctx context.Context) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		tick := time.NewTicker(20 * time.Second)
		defer tick.Stop()
		t.check(ctx) // сразу при старте
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

func (t *transport) stop() {
	close(t.stopCh)
	t.wg.Wait()
	t.killTunnel()
}

// directOK — короткая проба прямого доступа к Telegram API.
func directOK(ctx context.Context) bool {
	c := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", tgProbeURL, nil)
	if err != nil {
		return false
	}
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func (t *transport) check(ctx context.Context) {
	if directOK(ctx) {
		t.mu.Lock()
		wasTunnel := t.mode == "tunnel"
		t.mu.Unlock()
		if wasTunnel {
			// прямой доступ вернулся — гасим туннель, возвращаемся на direct
			t.killTunnel()
			t.mu.Lock()
			t.client = &http.Client{Timeout: 40 * time.Second}
			t.mode = "direct"
			t.nodeHost = ""
			t.mu.Unlock()
			log.Println("bot-transport: прямой доступ к Telegram восстановлен → direct")
		}
		return
	}
	// прямой недоступен: нужен туннель
	t.mu.Lock()
	curHost := t.nodeHost
	alive := t.sshCmd != nil && t.sshCmd.Process != nil
	t.mu.Unlock()

	// туннель жив? проверим SOCKS-порт реальным запросом через него
	if alive && curHost != "" && t.socksOK(ctx) {
		return // всё работает через текущую ноду
	}
	// выбираем ноду-кандидата (исключая умершую)
	cands := t.nodes()
	var pick *tunnelNode
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
		log.Println("bot-transport: Telegram недоступен, живых нод для туннеля нет — ждём")
		return
	}
	if err := t.dialTunnel(pick.Host); err != nil {
		log.Printf("bot-transport: туннель через %s не поднялся: %v", pick.Host, err)
		return
	}
	log.Printf("bot-transport: Telegram через SSH-туннель на %s (SOCKS %s)", pick.Host, t.socksLn)
}

// socksOK — проба Telegram через текущий SOCKS-клиент.
func (t *transport) socksOK(ctx context.Context) bool {
	t.mu.Lock()
	c := t.client
	t.mu.Unlock()
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, "GET", tgProbeURL, nil)
	if err != nil {
		return false
	}
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// dialTunnel — ssh -D 127.0.0.1:<port> -N на ноду + SOCKS5-клиент.
func (t *transport) dialTunnel(host string) error {
	t.killTunnel()
	if _, err := os.Stat(t.sshKey); err != nil {
		return fmt.Errorf("SSH-ключ нод не найден: %s", t.sshKey)
	}
	// свободный локальный порт
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
	// ждём подъёма SOCKS-порта (до 15с)
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
	dialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		cmd.Process.Kill()
		return err
	}
	dc := dialer.(proxy.ContextDialer)
	client := &http.Client{
		Timeout:   40 * time.Second,
		Transport: &http.Transport{DialContext: dc.DialContext},
	}
	t.mu.Lock()
	t.sshCmd = cmd
	t.socksLn = addr
	t.nodeHost = host
	t.client = client
	t.mode = "tunnel"
	t.mu.Unlock()
	// reap: если ssh умрёт сам — пометим (check поднимет новый)
	go func() {
		cmd.Wait()
		t.mu.Lock()
		if t.sshCmd == cmd {
			t.sshCmd = nil
		}
		t.mu.Unlock()
	}()
	return nil
}

func (t *transport) killTunnel() {
	t.mu.Lock()
	cmd := t.sshCmd
	t.sshCmd = nil
	t.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
}