package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"osint-check/internal/ioc"
)

func TestRegressionStaleFeodoReportsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	c := NewClient(nil)
	c.Bases = map[string]string{"https://feodotracker.abuse.ch": srv.URL}
	l := feodoList{entries: map[string]feodoEntry{}, fetched: time.Now().Add(-48 * time.Hour)}
	f, err := l.check(context.Background(), c, ioc.Indicator{Type: ioc.IPv4, Value: "8.8.8.8"})
	if err == nil {
		t.Fatalf("48h stale list + HTTP 503 -> verdict=%s, no error or warning", f.Verdict)
	}
}
