package sources

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"osint-check/internal/ioc"
)

func rdapServer(t *testing.T, domains map[string]string, bootStatus int) (*Client, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch {
		case r.URL.Path == "/rdap/dns.json":
			if bootStatus != 200 {
				w.WriteHeader(bootStatus)
				return
			}
			fmt.Fprintf(w, `{"services":[[["com","net"],["http://insecure.example/","%[1]s/com/"]],[["uk"],["%[1]s/uk"]]]}`, srv.URL)
		case strings.HasPrefix(r.URL.Path, "/com/domain/"), strings.HasPrefix(r.URL.Path, "/uk/domain/"):
			name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			body, ok := domains[name]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Type", "application/rdap+json")
			fmt.Fprint(w, body)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	c := NewClient(nil)
	c.HTTP.Transport = srv.Client().Transport
	c.Bases = map[string]string{"https://data.iana.org/rdap": srv.URL + "/rdap"}
	return c, &hits
}

func rdapBody(name string, registered time.Time) string {
	return fmt.Sprintf(`{"ldhName":"%s","events":[{"eventAction":"registration","eventDate":"%s"},{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}]}`, strings.ToUpper(name), registered.UTC().Format(time.RFC3339))
}

func TestRDAPDomainAge(t *testing.T) {
	c, _ := rdapServer(t, map[string]string{
		"neu-phish.com":  rdapBody("neu-phish.com", time.Now().Add(-5*24*time.Hour)),
		"alt-firma.com":  rdapBody("alt-firma.com", time.Date(2005, 3, 1, 0, 0, 0, 0, time.UTC)),
		"ohne-datum.com": `{"ldhName":"ohne-datum.com","events":[]}`,
		"shop.co.uk":     rdapBody("shop.co.uk", time.Now().Add(-2*24*time.Hour)),
		// Die Registry kennt auch "co.uk" selbst; das darf nie gewinnen.
		"co.uk": rdapBody("co.uk", time.Date(1985, 1, 1, 0, 0, 0, 0, time.UTC)),
		// Antwort mit dem übergeordneten Namen statt der Subdomain.
		"login.alt-firma.com": rdapBody("alt-firma.com", time.Now().Add(-1*24*time.Hour)),
		// Antwort passt zu keinem angefragten Namen.
		"falsch.com": rdapBody("anders.com", time.Now()),
	}, 200)
	s := newRDAP()
	for _, tc := range []struct {
		in      string
		verdict Verdict
		summary string
	}{
		{"neu-phish.com", Suspicious, "Neu registriert am"},
		{"login.neu-phish.com", Suspicious, "(5 Tage alt)"},
		{"https://login.alt-firma.com/x?y=1", Info, "Registriert am 2005-03-01"},
		{"falsch.com", NotFound, "nicht gefunden"},
		{"ohne-datum.com", Info, "nicht veröffentlicht"},
		{"www.shop.co.uk", Suspicious, "Neu registriert"},
		{"www.fehlt.co.uk", NotFound, "nicht gefunden"},
		{"co.uk", NotFound, "Kein Domainname"},
		{"gibtsnicht.com", NotFound, "nicht gefunden"},
		{"beispiel.zz", Info, "keinen RDAP-Dienst"},
	} {
		f, err := s.Check(context.Background(), c, "", ind(t, tc.in))
		if err != nil || f.Verdict != tc.verdict || !strings.Contains(f.Summary, tc.summary) {
			t.Fatalf("%s: %+v %v", tc.in, f, err)
		}
	}
}

func TestRDAPSkipsIPHostsAndNonHTTPSRegistries(t *testing.T) {
	c, hits := rdapServer(t, map[string]string{}, 200)
	s := newRDAP()
	f, err := s.Check(context.Background(), c, "", ind(t, "https://8.8.8.8/login"))
	if err != nil || f.Verdict != NotFound || hits.Load() != 0 {
		t.Fatalf("IP-Host: %+v %v, Anfragen %d", f, err, hits.Load())
	}
	l := &rdapDirectory{sem: make(chan struct{}, 1)}
	servers, err := l.load(context.Background(), c)
	if err != nil || strings.HasPrefix(servers["com"], "http://") {
		t.Fatalf("Registry ohne HTTPS übernommen: %v %v", servers, err)
	}
}

// Nach einem Fehler der IANA-Liste nicht bei jeder Prüfung neu laden.
func TestRDAPBootstrapBacksOff(t *testing.T) {
	c, hits := rdapServer(t, nil, 503)
	s := newRDAP()
	for i := 0; i < 5; i++ {
		if _, err := s.Check(context.Background(), c, "", ind(t, "beispiel.com")); err == nil {
			t.Fatal("Fehler nicht gemeldet")
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("%d Downloads statt 1", n)
	}
}

func TestRDAPCheckDoesNotRunForInternal(t *testing.T) {
	in, ok := ioc.Classify("intranet.corp", ioc.Options{})
	if !ok || !in.Internal {
		t.Fatal("interne Domain nicht als intern erkannt; die Engine sendet interne Werte nie")
	}
}
