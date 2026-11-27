package api
import "testing"
func TestNginxCriticalNote(t *testing.T) {
 cases := map[string]bool{"1.24.0":true,"1.30.6":true,"1.30.7":false,"1.31.8":true,"1.31.9":false,"1.28.0":true}
 for v,want := range cases {
  got := nginxCriticalNote(v) != ""
  if got != want { t.Errorf("nginx %s: critical=%v, want %v", v, got, want) }
 }
}
