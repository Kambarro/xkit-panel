package api

import (
	"testing"
	"time"
)

func TestPanelReleaseDownloadTag(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"1.0.1", "v1.0.1"},
		{"v1.0.1", "v1.0.1"},
	} {
		if got := panelReleaseDownloadTag(tc.in); got != tc.want {
			t.Errorf("panelReleaseDownloadTag(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPanelUpdateResponseBudget(t *testing.T) {
	const downloadAndVerifyBudget = 120*time.Second + 2*30*time.Second + 10*time.Second
	if apiRequestTimeout < downloadAndVerifyBudget {
		t.Fatalf("API timeout %v меньше бюджета скачивания и проверки %v", apiRequestTimeout, downloadAndVerifyBudget)
	}
	if panelRestartDelay < 200*time.Millisecond {
		t.Fatalf("restart после %v не оставляет времени на HTTP-ответ", panelRestartDelay)
	}
}
