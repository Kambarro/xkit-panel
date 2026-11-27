package api

import "testing"

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
