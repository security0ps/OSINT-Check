package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"osint-check/internal/engine"
	"osint-check/internal/ioc"
	"osint-check/internal/sources"
)

type offlineTransport struct{}

func (offlineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func build(t *testing.T, opt Options) *Server {
	t.Helper()
	var cfgs []*engine.SourceConfig
	for _, s := range sources.All() {
		cfgs = append(cfgs, &engine.SourceConfig{Source: s, Key: "demo", Limiter: engine.NewLimiter(sources.Limit{})})
	}
	return New(engine.New(sources.NewClient(offlineTransport{}), cfgs, ioc.Options{}), opt)
}

func req(h http.Handler, method, target, host, body string, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Host = host
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const local = "127.0.0.1:8484"

func authenticatedRequest(s *Server, method, path, host, body string, mod func(*http.Request)) *httptest.ResponseRecorder {
	s.mu.Lock()
	s.sess[hashToken("fixture-session")] = time.Now().Add(time.Hour)
	s.mu.Unlock()
	return req(s, method, path, host, body, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "fixture-session"})
		if mod != nil { mod(r) }
	})
}

func TestCrossOriginPostRejected(t *testing.T) {
	s := build(t, Options{})
	w := authenticatedRequest(s, "POST", "/api/check", local, `{"input":"8.8.8.8"}`, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	w = authenticatedRequest(s, "POST", "/api/check", local, `{"input":"8.8.8.8"}`, func(r *http.Request) { r.Header.Set("Origin", "http://"+local) })
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestFormPostRejected(t *testing.T) {
	s := build(t, Options{})
	w := authenticatedRequest(s, "POST", "/api/check", local, `input=8.8.8.8`, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") })
	if w.Code != 415 {
		t.Fatal(w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := build(t, Options{})
	w := req(s, "GET", "/", local, "", nil)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal(w.Code, w.Header())
	}
}

func TestLoginFlow(t *testing.T) {
	s := build(t, Options{Password: "richtig", TrustProxy: true})
	host := "osint.firma.de"
	if w := req(s, "POST", "/api/check", host, `{"input":"8.8.8.8"}`, nil); w.Code != 401 {
		t.Fatal("ohne Anmeldung", w.Code)
	}
	var m map[string]any
	w := req(s, "GET", "/api/meta", host, "", nil)
	json.Unmarshal(w.Body.Bytes(), &m)
	if m["sources"] != nil || m["authenticated"] != false {
		t.Fatalf("Meta gibt ohne Anmeldung zu viel preis: %v", m)
	}
	if w := req(s, "POST", "/api/login", host, `{"password":"falsch"}`, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w = req(s, "POST", "/api/login", host, `{"password":"richtig"}`, func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") })
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("%+v", cookie)
	}
	withCookie := func(r *http.Request) { r.AddCookie(cookie) }
	if w := req(s, "POST", "/api/check", host, `{"input":"8.8.8.8"}`, withCookie); w.Code != 202 {
		t.Fatal(w.Code)
	}
	if w := req(s, "POST", "/api/logout", host, "", withCookie); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := req(s, "POST", "/api/check", host, `{"input":"8.8.8.8"}`, withCookie); w.Code != 401 {
		t.Fatal("Session muss nach Abmeldung ungültig sein", w.Code)
	}
}

func TestLoginThrottle(t *testing.T) {
	s := build(t, Options{Password: "x"})
	var last int
	for i := 0; i < 6; i++ {
		last = req(s, "POST", "/api/login", "a.b", `{"password":"falsch"}`, nil).Code
	}
	if last != 429 {
		t.Fatal(last)
	}
	if c := req(s, "POST", "/api/login", "a.b", `{"password":"x"}`, nil).Code; c != 429 {
		t.Fatal("Auch das richtige Passwort wartet während der Sperre", c)
	}
}

func TestOversizedBody(t *testing.T) {
	s := build(t, Options{})
	big := `{"input":"` + strings.Repeat("a", 2<<20) + `"}`
	if w := authenticatedRequest(s, "POST", "/api/check", local, big, nil); w.Code != 413 {
		t.Fatal(w.Code)
	}
}

func TestJobUnknownID(t *testing.T) {
	s := build(t, Options{})
	if w := authenticatedRequest(s, "GET", "/api/jobs/nix", local, "", nil); w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestStaticAssets(t *testing.T) {
	s := build(t, Options{})
	for _, p := range []string{"/", "/app.js", "/sha256.js", "/style.css"} {
		w := req(s, "GET", p, local, "", nil)
		b, _ := io.ReadAll(w.Body)
		if w.Code != 200 || len(b) == 0 {
			t.Fatal(p, w.Code)
		}
	}
}

func login(s *Server, ip, password string, mod func(*http.Request)) int {
	return req(s, "POST", "/api/login", "a.b", `{"password":"`+password+`"}`, func(r *http.Request) {
		r.Header.Set("X-Forwarded-For", ip)
		if mod != nil {
			mod(r)
		}
	}).Code
}

func TestForgedForwardedHeadersIgnoredWithoutProxy(t *testing.T) {
	s := build(t, Options{Password: "x"})
	w := req(s, "POST", "/api/login", "a.b", `{"password":"x"}`, func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") })
	if c := w.Result().Cookies()[0]; c.Secure {
		t.Fatal("gefälschter Header darf das Verhalten nicht ändern")
	}
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS ohne HTTPS")
	}
	for i := 0; i < 5; i++ {
		login(s, "9.9.9."+string(rune('0'+i)), "falsch", nil)
	}
	if c := login(s, "9.9.9.9", "falsch", nil); c != 429 {
		t.Fatalf("Sperre lässt sich per X-Forwarded-For umgehen: %d", c)
	}
}

func TestProxyLockoutIsPerClient(t *testing.T) {
	s := build(t, Options{Password: "x", TrustProxy: true})
	for i := 0; i < 6; i++ {
		login(s, "198.51.100.1", "falsch", nil)
	}
	if c := login(s, "198.51.100.1", "x", nil); c != 429 {
		t.Fatalf("Angreifer müsste gesperrt sein: %d", c)
	}
	if c := login(s, "198.51.100.2", "x", nil); c != 200 {
		t.Fatalf("Kollegen dürfen nicht mit ausgesperrt werden: %d", c)
	}
	// Selbst eingetragene Werte stehen links, der Proxy hängt die echte IP an.
	if c := login(s, "1.2.3.4, 198.51.100.1", "x", nil); c != 429 {
		t.Fatalf("Gefälschter X-Forwarded-For umgeht die Sperre: %d", c)
	}
}

func TestGlobalLoginLimit(t *testing.T) {
	s := build(t, Options{Password: "x", TrustProxy: true})
	for i := 0; i < loginAttemptsGlobal; i++ {
		login(s, "198.51.100."+strconv.Itoa(i), "falsch", nil)
	}
	if c := login(s, "198.51.100.200", "falsch", nil); c != 429 {
		t.Fatalf("verteilter Angriff wird nicht gebremst: %d", c)
	}
}

func TestSecureHeadersBehindProxy(t *testing.T) {
	s := build(t, Options{TrustProxy: true})
	w := req(s, "GET", "/", "a.b", "", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") })
	if w.Header().Get("Strict-Transport-Security") == "" || w.Header().Get("Cross-Origin-Opener-Policy") == "" {
		t.Fatal(w.Header())
	}
}
