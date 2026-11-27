package subscription

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestClashValidInMihomo — BUG-5: подписка clash обязана проходить проверку
// реальным mihomo (-t). Бинарь QA workspace или env XKIT_MIHOMO_BIN; нет — skip.
func TestClashValidInMihomo(t *testing.T) {
	bin := os.Getenv("XKIT_MIHOMO_BIN")
	if bin == "" {
		home, _ := os.UserHomeDir()
		bin = filepath.Join(home, ".hermes", "profiles", "qa", "workspace", "xkit-full-qa", "parsers", "mihomo")
	}
	if st, err := os.Stat(bin); err != nil || st.IsDir() {
		t.Skip("mihomo не найден (XKIT_MIHOMO_BIN / workspace QA)")
	}
	// валидный reality-ключ (mihomo валидирует pbk); geo-файлы mihomo скачает сам
	const realityPub = "mQghxPkdBvn4HPFr34mUhw0UcQG-t1kbuUZ8Fx1kUxU"
	realityLink := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vpn.example.com:443?encryption=none&security=reality&sni=vpn.example.com&fp=chrome&pbk=" + realityPub + "&sid=ab12&flow=xtls-rprx-vision&type=tcp#Reality"
	cy := ClashYAML([]string{realityLink, testVlessWS, testHy2})
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cy), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-t", "-d", dir, "-f", cfgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("mihomo -t: %v\n%s", err, out)
	}
}