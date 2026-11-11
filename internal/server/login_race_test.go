package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Gleichzeitige Fehlversuche dürfen die Limits nicht während der langsamen
// Passwortprüfung (PBKDF2) umgehen.
func TestConcurrentLoginsRespectLimits(t *testing.T) {
	dir := t.TempDir()
	c, err := OpenCredentials(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	code, err := os.ReadFile(filepath.Join(dir, "setup-code"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"code": strings.TrimSpace(string(code)), "password": "a long team password"})
	if w := req(build(t, Options{Credentials: c}), "POST", "/api/setup", local, string(payload), nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	burst := func(n int, ip func(int) string) map[int]int {
		s := build(t, Options{Credentials: c, TrustProxy: true})
		var wg sync.WaitGroup
		var mu sync.Mutex
		codes := map[int]int{}
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				w := req(s, "POST", "/api/login", local, `{"password":"falsch"}`, func(r *http.Request) { r.Header.Set("X-Forwarded-For", ip(i)) })
				mu.Lock()
				codes[w.Code]++
				mu.Unlock()
			}(i)
		}
		close(start)
		wg.Wait()
		return codes
	}
	if got := burst(20, func(int) string { return "198.51.100.7" }); got[401] != loginAttempts || got[429] != 20-loginAttempts {
		t.Fatalf("eine IP: %v, erwartet %d geprüft", got, loginAttempts)
	}
	if got := burst(loginAttemptsGlobal+5, func(i int) string { return fmt.Sprintf("10.0.%d.%d", i/200, i%200) }); got[401] != loginAttemptsGlobal || got[429] != 5 {
		t.Fatalf("viele IPs: %v, erwartet %d geprüft", got, loginAttemptsGlobal)
	}
}

// Erfolgreiche Anmeldungen verbrauchen kein Kontingent.
func TestSuccessfulLoginsDoNotUseQuota(t *testing.T) {
	s := build(t, Options{Password: "richtig", TrustProxy: true})
	for i := 0; i < 2*loginAttempts; i++ {
		if w := req(s, "POST", "/api/login", local, `{"password":"richtig"}`, func(r *http.Request) { r.Header.Set("X-Forwarded-For", "198.51.100.8") }); w.Code != 200 {
			t.Fatalf("Anmeldung %d: %d", i+1, w.Code)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.all) != 0 || len(s.fail) != 0 {
		t.Fatalf("Zähler nicht zurückgesetzt: all=%d fail=%d", len(s.all), len(s.fail))
	}
}
