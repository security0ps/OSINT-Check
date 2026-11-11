package sources

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"osint-check/internal/ioc"
)

const (
	dropV4 = `{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"62.60.226.0/24","sblid":"SBL111111","rir":"ripencc"}
{"type":"metadata","timestamp":1794224642,"size":120,"records":2,"copyright":"(c) 2026 The Spamhaus Project SLU"}
`
	dropV6 = `{"cidr":"2001:678:254::/48","sblid":"SBL697648","rir":"ripencc"}
{"type":"metadata","timestamp":1794224642,"size":60,"records":1}
`
)

func dropServer(t *testing.T, status *atomic.Int32, hits *atomic.Int32) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if s := status.Load(); s != 200 {
			w.WriteHeader(int(s))
			return
		}
		switch r.URL.Path {
		case "/drop_v4.json":
			io.WriteString(w, dropV4)
		case "/drop_v6.json":
			io.WriteString(w, dropV6)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	c := NewClient(nil)
	c.Bases = map[string]string{"https://www.spamhaus.org/drop": srv.URL}
	return c
}

func TestSpamhausDrop(t *testing.T) {
	var status, hits atomic.Int32
	status.Store(200)
	c := dropServer(t, &status, &hits)
	s := newSpamhausDrop()
	for _, tc := range []struct {
		in   string
		want Verdict
		sbl  string
	}{
		{"1.10.20.5", Malicious, "SBL256894"},
		{"62.60.226.255", Malicious, "SBL111111"},
		{"2001:678:254:1::5", Malicious, "SBL697648"},
		{"8.8.8.8", NotFound, ""},
		{"2001:4860:4860::8888", NotFound, ""},
	} {
		f, err := s.Check(context.Background(), c, "", ind(t, tc.in))
		if err != nil || f.Verdict != tc.want {
			t.Fatalf("%s: %+v %v", tc.in, f, err)
		}
		if tc.sbl != "" && !strings.Contains(strings.Join(func() []string {
			var v []string
			for _, d := range f.Details {
				v = append(v, d.V)
			}
			return v
		}(), " "), tc.sbl) {
			t.Fatalf("%s: SBL-ID fehlt: %+v", tc.in, f.Details)
		}
	}
	// Beide Listen werden genau einmal geladen und danach zwischengespeichert.
	if n := hits.Load(); n != 2 {
		t.Fatalf("Spamhaus wurde %d-mal abgefragt, erwartet 2", n)
	}
}

// Nach einem Fehler darf nicht jede Prüfung einen neuen Download auslösen,
// sonst sperrt Spamhaus die eigene IP.
func TestSpamhausDropBacksOffAfterFailure(t *testing.T) {
	var status, hits atomic.Int32
	status.Store(503)
	c := dropServer(t, &status, &hits)
	s := newSpamhausDrop()
	for i := 0; i < 5; i++ {
		if _, err := s.Check(context.Background(), c, "", ind(t, "8.8.8.8")); err == nil {
			t.Fatal("Fehler der Liste wurde nicht gemeldet")
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("nach einem Fehler %d Downloads statt 1", n)
	}
}

func TestSpamhausDropRetriesPartialDownloadAfterOneHour(t *testing.T) {
	var hits atomic.Int32
	var v6Ready atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/drop_v4.json":
			io.WriteString(w, dropV4)
		case "/drop_v6.json":
			if !v6Ready.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			io.WriteString(w, dropV6)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c := NewClient(nil)
	c.Bases = map[string]string{"https://www.spamhaus.org/drop": srv.URL}
	list := &dropList{sem: make(chan struct{}, 1)}
	ctx := context.Background()
	if _, err := list.load(ctx, c); err == nil || hits.Load() != 2 {
		t.Fatalf("Teilabruf: Fehler %v, Anfragen %d", err, hits.Load())
	}

	v6Ready.Store(true)
	list.failedAt = time.Now().Add(-59 * time.Minute)
	if _, err := list.load(ctx, c); err == nil || hits.Load() != 2 {
		t.Fatalf("vor Ablauf der Stunde: Fehler %v, Anfragen %d", err, hits.Load())
	}
	list.failedAt = time.Now().Add(-time.Hour)
	if entries, err := list.load(ctx, c); err != nil || len(entries) != 3 || hits.Load() != 4 {
		t.Fatalf("nach Ablauf der Stunde: Fehler %v, Einträge %d, Anfragen %d", err, len(entries), hits.Load())
	}
}

// Eine veraltete Liste wird nicht als aktuelle Prüfung ausgegeben.
func TestSpamhausDropStaleListReportsFailure(t *testing.T) {
	var status, hits atomic.Int32
	status.Store(503)
	c := dropServer(t, &status, &hits)
	l := &dropList{sem: make(chan struct{}, 1), entries: []dropEntry{}, fetched: time.Now().Add(-48 * time.Hour)}
	if f, err := l.check(context.Background(), c, ioc.Indicator{Type: ioc.IPv4, Value: "8.8.8.8"}); err == nil {
		t.Fatalf("veraltete Liste lieferte %s ohne Fehler", f.Verdict)
	}
}

func TestSpamhausDropRejectsBadFormat(t *testing.T) {
	for _, body := range []string{"", "<html>", `{"cidr":"kein-netz","sblid":"SBL1"}`, `{"type":"metadata"}`} {
		c, _ := fake(t, "https://www.spamhaus.org/drop", 200, body)
		if _, err := newSpamhausDrop().Check(context.Background(), c, "", ind(t, "8.8.8.8")); err == nil {
			t.Fatalf("Antwort %q nicht als Fehler erkannt", body)
		}
	}
}

func TestSpamhausDropWaitIsCancellable(t *testing.T) {
	l := &dropList{sem: make(chan struct{}, 1)}
	l.sem <- struct{}{} // ein anderer Download läuft
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := l.check(ctx, NewClient(nil), ioc.Indicator{Type: ioc.IPv4, Value: "8.8.8.8"}); err == nil {
		t.Fatal("Warten auf den Download ignoriert den Abbruch")
	}
}
