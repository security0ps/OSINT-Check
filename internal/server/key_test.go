package server

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"osint-check/internal/engine"
	"osint-check/internal/ioc"
	"osint-check/internal/sources"
)

type statusTransport struct{ code int }

func (s statusTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: s.code, Body: io.NopCloser(strings.NewReader(`{"results":[]}`))}, nil
}

// switchTransport antwortet mit dem jeweils eingestellten Status.
type switchTransport struct{ code *atomic.Int32 }

func (s switchTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"results":[]}`
	if r.Header.Get("X-OTX-API-KEY") == "ungeprueft" {
		body = "<html>Proxy</html>"
	}
	return &http.Response{StatusCode: int(s.code.Load()), Body: io.NopCloser(strings.NewReader(body))}, nil
}

func buildWithTransport(rt http.RoundTripper, opt Options) *Server {
	var cfgs []*engine.SourceConfig
	for _, s := range sources.All() {
		cfgs = append(cfgs, &engine.SourceConfig{Source: s, Key: "", Limiter: engine.NewLimiter(sources.Limit{})})
	}
	return New(engine.New(sources.NewClient(rt), cfgs, ioc.Options{}), opt)
}

func keyServer(t *testing.T, rt http.RoundTripper, base map[string]string) (*Server, *Credentials, string) {
	t.Helper()
	dir := t.TempDir()
	c, err := OpenCredentials(dir, "dummy-team-password")
	if err != nil {
		t.Fatal(err)
	}
	c.ApplyKeys(base)
	var cfgs []*engine.SourceConfig
	for _, s := range sources.All() {
		cfgs = append(cfgs, &engine.SourceConfig{Source: s, Key: base[s.KeyName], Limiter: engine.NewLimiter(sources.Limit{})})
	}
	s := New(engine.New(sources.NewClient(rt), cfgs, ioc.Options{}), Options{Credentials: c, Password: "dummy-team-password"})
	return s, c, dir
}

func engineKey(s *Server, name string) string {
	for _, c := range s.eng.Sources() {
		if c.Source.KeyName == name {
			return c.Key
		}
	}
	return "?"
}

func TestRejectedKeyIsNotSaved(t *testing.T) {
	s, _, dir := keyServer(t, statusTransport{401}, map[string]string{"otx": "env-key"})
	w := authenticatedRequest(s, "PUT", "/api/key", local, `{"name":"otx","value":"falscher-key"}`, nil)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "key_rejected") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "keys.json")); err == nil || engineKey(s, "otx") != "env-key" {
		t.Fatal("abgelehnter Key wurde gespeichert oder aktiviert")
	}
}

// Nur eine 200-Antwort an einer Stelle, die einen Key verlangt, gilt als
// Bestätigung. 404, Störungen oder Limits ersetzen den bisherigen Key nicht.
func TestUnverifiedKeyKeepsWorkingKey(t *testing.T) {
	var code atomic.Int32
	code.Store(200)
	s, _, dir := keyServer(t, switchTransport{&code}, map[string]string{})
	if w := authenticatedRequest(s, "PUT", "/api/key", local, `{"name":"otx","value":"guter-key"}`, nil); w.Code != 200 {
		t.Fatalf("guter Key: %d %s", w.Code, w.Body.String())
	}
	for _, status := range []int32{200, 404, 429, 500} {
		code.Store(status)
		w := authenticatedRequest(s, "PUT", "/api/key", local, `{"name":"otx","value":"ungeprueft"}`, nil)
		if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "key_unverified") || engineKey(s, "otx") != "guter-key" {
			t.Fatalf("HTTP %d: %d %s, aktiver Key %q", status, w.Code, w.Body.String(), engineKey(s, "otx"))
		}
		stored, err := os.ReadFile(filepath.Join(dir, "keys.json"))
		if err != nil || !strings.Contains(string(stored), "guter-key") || strings.Contains(string(stored), "ungeprueft") {
			t.Fatalf("HTTP %d: gespeicherter Key verändert", status)
		}
	}
}

func TestWebKeyRemovalRestoresEnvKey(t *testing.T) {
	s, c, _ := keyServer(t, statusTransport{200}, map[string]string{"otx": "env-key"})
	if w := authenticatedRequest(s, "PUT", "/api/key", local, `{"name":"otx","value":"web-key"}`, nil); w.Code != 200 || engineKey(s, "otx") != "web-key" {
		t.Fatalf("speichern: %d %s", w.Code, w.Body.String())
	}
	if w := authenticatedRequest(s, "GET", "/api/meta", local, "", nil); !strings.Contains(w.Body.String(), `"web_keys":["otx"]`) || strings.Contains(w.Body.String(), "web-key") {
		t.Fatalf("meta: %s", w.Body.String())
	}
	if w := authenticatedRequest(s, "PUT", "/api/key", local, `{"name":"otx","value":""}`, nil); w.Code != 200 || engineKey(s, "otx") != "env-key" {
		t.Fatalf("entfernen: %d %s, Key %q", w.Code, w.Body.String(), engineKey(s, "otx"))
	}
	if len(c.webKeys()) != 0 {
		t.Fatal("Web-Key nicht entfernt")
	}
	if w := authenticatedRequest(s, "PUT", "/api/key", local, `{"name":"otx","value":""}`, nil); w.Code != 400 {
		t.Fatalf("Entfernen ohne Web-Key: %d", w.Code)
	}
}
