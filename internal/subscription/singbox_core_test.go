package subscription

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// findSingboxBinaries — реальные sing-box для проверки подписки (QA BUG-2:
// «проверять run, не только check»). Порядок: env XKIT_SINGBOX_BIN (список
// через :), затем workspace QA-прогона. Нет бинарей — тест skip (не фейк).
func findSingboxBinaries(t *testing.T) []string {
	t.Helper()
	var out []string
	if env := os.Getenv("XKIT_SINGBOX_BIN"); env != "" {
		for _, p := range strings.Split(env, ":") {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				out = append(out, p)
			}
		}
		return out
	}
	home, _ := os.UserHomeDir()
	for _, ver := range []string{"1.11.15", "1.12.0"} {
		p := filepath.Join(home, ".hermes", "profiles", "qa", "workspace", "xkit-full-qa", "parsers",
			"sing-box-"+ver+"-linux-amd64", "sing-box")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// runSingboxCore — check AND run реальным ядром: процесс обязан стартовать
// («sing-box started») и слушать mixed-port, без FATAL. Порты рандомизируем.
func runSingboxCore(t *testing.T, bin, cfgJSON string) {
	t.Helper()
	verOut, _ := exec.Command(bin, "version").Output()
	ver := strings.SplitN(string(verOut), "\n", 2)[0]
	// свободный порт вместо фиксированного 2080 (параллельные тесты)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfgJSON = strings.ReplaceAll(cfgJSON, `"listen_port": 2080`, fmt.Sprintf(`"listen_port": %d`, port))
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0644); err != nil {
		t.Fatal(err)
	}
	// check
	if out, err := exec.Command(bin, "check", "-c", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("%s check: %v\n%s", ver, err, out)
	}
	// run: ждём «started» или FATAL/exit
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "-c", cfgPath)
	logPath := filepath.Join(dir, "run.log")
	lf, _ := os.Create(logPath)
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		t.Fatalf("%s run start: %v", ver, err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait(); lf.Close() }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		data, _ := os.ReadFile(logPath)
		log := string(data)
		if strings.Contains(log, "FATAL") {
			t.Fatalf("%s run FATAL:\n%s", ver, log)
		}
		if strings.Contains(log, "sing-box started") {
			// и реально слушает
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
			if err == nil {
				conn.Close()
				return
			}
		}
	}
	data, _ := os.ReadFile(logPath)
	t.Fatalf("%s run не стартовал за 10с:\n%s", ver, data)
}