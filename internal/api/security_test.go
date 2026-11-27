package api

// security_test.go — регрессии аудита SEC-01/02/04/06, BUG-01.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidVersion(t *testing.T) {
	good := []string{"1.0.0", "26.11.9", "0.0.1", "123.45.678"}
	bad := []string{"", "1.0", "1.0.0.0", "v1.0.0", "1.0.0; rm -rf /", "1.0.0'", "$(id)", "1.0.0\nid", "1.0.0`id`", "1.0.0 && id", "x.y.z"}
	for _, v := range good {
		if !validVersion(v) {
			t.Errorf("validVersion(%q) = false, want true", v)
		}
	}
	for _, v := range bad {
		if validVersion(v) {
			t.Errorf("validVersion(%q) = true, want false (injection risk)", v)
		}
	}
}

func TestValidTunnelField(t *testing.T) {
	good := []string{"example.com", "cdn.example.co.uk", "/ws-path", "grpc.Service_name", "a:b/c-d.e", "1.2.3.4"}
	bad := []string{"", "x'EOF", "a b", "a\nXEOF", "$(id)", "a;id", "a`id`", "a|b", "a&b", `a"b`, "a\\b", "a$b"}
	for _, v := range good {
		if !validTunnelField(v) {
			t.Errorf("validTunnelField(%q) = false, want true", v)
		}
	}
	for _, v := range bad {
		if validTunnelField(v) {
			t.Errorf("validTunnelField(%q) = true, want false (heredoc/shell injection)", v)
		}
	}
}

func TestLimitBodyMiddleware(t *testing.T) {
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 2<<20)
		_, err := r.Body.Read(buf)
		if err == nil {
			t.Error("body read beyond 1 MiB should fail")
		}
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest("POST", "/api/x", strings.NewReader(strings.Repeat("a", 2<<20)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
}

// BUG-01: /api/countries и /api/countries/reference — разные маршруты,
// chi не должен паниковать/перезатирать (дубль регистрации).
func TestCountryRoutesNoDuplicate(t *testing.T) {
	s := &Server{}
	r := s.Router() // паника chi при дубле маршрута уронила бы тест
	if r == nil {
		t.Fatal("nil router")
	}
}