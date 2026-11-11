package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func loginReq(s *Server, ip, pw string, cookies ...*http.Cookie) *http.Response {
	return req(s, http.MethodPost, "/api/login", "osint.example", `{"password":"`+pw+`"}`, func(r *http.Request) {
		r.Header.Set("Origin", "https://osint.example")
		r.Header.Set("X-Forwarded-For", ip)
		r.Header.Set("X-Forwarded-Proto", "https")
		for _, c := range cookies {
			r.AddCookie(c)
		}
	}).Result()
}

func deviceCookieFrom(t *testing.T, res *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range res.Cookies() {
		if c.Name == deviceCookie {
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/api/login" {
				t.Fatalf("Geräte-Cookie unsicher gesetzt: %+v", c)
			}
			return c
		}
	}
	t.Fatal("kein Geräte-Cookie nach erfolgreicher Anmeldung")
	return nil
}

func floodGlobal(t *testing.T, s *Server) {
	t.Helper()
	for i := 1; i <= 6; i++ {
		for k := 0; k < 5; k++ {
			if c := loginReq(s, fmt.Sprintf("10.0.0.%d", i), "falsch").StatusCode; c != http.StatusUnauthorized {
				t.Fatalf("Fehlversuch %d/%d: Status %d", i, k, c)
			}
		}
	}
}

// Verteilte Fehlversuche Unbekannter dürfen Kollegen mit bekanntem Gerät nicht aussperren.
func TestGlobalLimitSparesKnownDevice(t *testing.T) {
	s := build(t, Options{Password: "dummy-secret", TrustProxy: true})
	res := loginReq(s, "203.0.113.7", "dummy-secret")
	if res.StatusCode != 200 {
		t.Fatalf("erste Anmeldung: %d", res.StatusCode)
	}
	dev := deviceCookieFrom(t, res)

	floodGlobal(t, s)

	if c := loginReq(s, "203.0.113.9", "dummy-secret", dev).StatusCode; c != 200 {
		t.Fatalf("bekanntes Gerät trotz richtigem Passwort ausgesperrt: %d", c)
	}
	// Die globale Grenze bleibt für Unbekannte bestehen.
	if c := loginReq(s, "203.0.113.10", "dummy-secret").StatusCode; c != http.StatusTooManyRequests {
		t.Fatalf("unbekanntes Gerät nicht gebremst: %d", c)
	}
	// Gefälschte oder fremde Geräte-Cookies bringen nichts.
	id, _, _ := strings.Cut(dev.Value, ".")
	for _, v := range []string{id + "." + strings.Repeat("0", 64), strings.Repeat("a", 32) + ".x", "kaputt"} {
		forged := &http.Cookie{Name: deviceCookie, Value: v}
		if c := loginReq(s, "203.0.113.11", "dummy-secret", forged).StatusCode; c != http.StatusTooManyRequests {
			t.Fatalf("gefälschtes Geräte-Cookie %q akzeptiert: %d", v, c)
		}
	}
	other := build(t, Options{Password: "dummy-secret", TrustProxy: true})
	floodGlobal(t, other)
	if c := loginReq(other, "203.0.113.12", "dummy-secret", dev).StatusCode; c != http.StatusTooManyRequests {
		t.Fatalf("Geräte-Cookie einer anderen Instanz akzeptiert: %d", c)
	}
}

// Ein bekanntes Gerät hat ein eigenes Kontingent und füllt die globale Grenze nicht.
func TestKnownDeviceOwnBudget(t *testing.T) {
	s := build(t, Options{Password: "dummy-secret", TrustProxy: true})
	dev := deviceCookieFrom(t, loginReq(s, "203.0.113.7", "dummy-secret"))
	for i := 0; i < loginAttempts; i++ {
		if c := loginReq(s, fmt.Sprintf("198.51.100.%d", i+1), "falsch", dev).StatusCode; c != http.StatusUnauthorized {
			t.Fatalf("Fehlversuch %d: %d", i, c)
		}
	}
	if c := loginReq(s, "198.51.100.99", "dummy-secret", dev).StatusCode; c != http.StatusTooManyRequests {
		t.Fatalf("Gerätekontingent greift nicht über IP-Wechsel: %d", c)
	}
	s.mu.Lock()
	global := len(s.all)
	s.mu.Unlock()
	if global != 0 {
		t.Fatalf("Fehlversuche bekannter Geräte zählen global: %d", global)
	}
}
