package api

import (
	"bytes"
	"net/http"
	"strings"
)

// captureWriter — http.ResponseWriter для внутренних вызовов хендлеров
// (переиспользование кода: пресеты вызывают createInbound напрямую).
type captureWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (c *captureWriter) Header() http.Header { return c.header }
func (c *captureWriter) Write(b []byte) (int, error) {
	if c.status == 0 { c.status = 200 }
	return c.body.Write(b)
}
func (c *captureWriter) WriteHeader(code int) { c.status = code }

func stringReader(s string) *strings.Reader { return strings.NewReader(s) }