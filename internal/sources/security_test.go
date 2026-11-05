package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"osint-check/internal/ioc"
)

// API-Keys stehen in eigenen Headern. Go entfernt bei Umleitungen auf fremde
// Hosts nur Authorization und Cookie, diese Header müssen wir selbst schützen.
func TestKeyNotForwardedOnCrossHostRedirect(t *testing.T) {
	leaked := ""
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("x-apikey")
		w.WriteHeader(200)
		w.Write([]byte(`{"data":{"attributes":{}}}`))
	}))
	defer foreign.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(foreign.URL, "127.0.0.1", "localhost", 1)+"/steal", http.StatusFound)
	}))
	defer api.Close()
	c := NewClient(nil)
	c.Bases = map[string]string{"https://www.virustotal.com/api/v3": api.URL}
	_, err := checkVT(context.Background(), c, "GEHEIM", ind(t, "evil.com"))
	if leaked != "" {
		t.Fatalf("API-Key an fremden Host weitergegeben: %q", leaked)
	}
	if err == nil {
		t.Fatal("Umleitung auf fremden Host muss als Fehler enden")
	}
}

// Eine unerwartete Antwort darf nie wie „nicht gefunden“ aussehen.
func TestThreatFoxUnexpectedDataIsErrorNotClean(t *testing.T) {
	c, _ := fake(t, "https://threatfox-api.abuse.ch/api/v1", 200,
		`{"query_status":"ok","data":[{"id":"7","ioc":"evil.com","confidence_level":"hoch"}]}`)
	f, err := checkThreatFox(context.Background(), c, "K", ind(t, "evil.com"))
	if err == nil {
		t.Fatalf("Formatfehler wurde verschluckt: %+v", f)
	}
}

// Fremde Personen können harmlose Scans einreichen. Das Fehlen einer
// Markierung ist deshalb keine Entlastung.
func TestURLScanWithoutFlagIsNotClean(t *testing.T) {
	c, _ := fake(t, "https://urlscan.io/api/v1", 200, `{"total":1,"results":[{"_id":"a","verdicts":{"overall":{"malicious":false}}}]}`)
	f, err := checkURLScan(context.Background(), c, "K", ioc.Indicator{Type: ioc.Domain, Value: "evil.com"})
	if err != nil || f.Verdict != Info {
		t.Fatalf("%+v %v", f, err)
	}
}
