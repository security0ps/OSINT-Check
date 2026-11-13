// Package sources enthält die Anbindungen an die OSINT-Dienste.
package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"osint-check/internal/ioc"
)

// Verdict ist die Einschätzung einer einzelnen Quelle.
type Verdict string

const (
	Malicious  Verdict = "malicious"  // Quelle stuft als bösartig ein
	Suspicious Verdict = "suspicious" // deutliche Hinweise
	Weak       Verdict = "weak"       // schwache Hinweise
	Clean      Verdict = "clean"      // Quelle kennt den Wert als unauffällig
	Info       Verdict = "info"       // bekannt, aber ohne Einstufung
	NotFound   Verdict = "not_found"  // Quelle kennt den Wert nicht
)

// Status beschreibt den Ablauf der Abfrage.
type Status string

const (
	StatusPending Status = "pending"
	StatusWaiting Status = "waiting" // wartet auf freies Abfragelimit
	StatusOK      Status = "ok"
	StatusError   Status = "error"
	StatusNoKey   Status = "no_key"
	StatusLimit   Status = "limit"
	StatusSkipped Status = "skipped"
)

// KV ist ein Detailfeld.
type KV struct {
	K string `json:"k"`
	V string `json:"v"`
}

// Finding ist das Ergebnis einer Abfrage.
type Finding struct {
	Verdict  Verdict  `json:"verdict,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	Details  []KV     `json:"details,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Link     string   `json:"link,omitempty"`
}

// Limit beschreibt Abfragegrenzen (0 = unbegrenzt).
type Limit struct {
	PerMinute int `json:"per_minute"`
	PerDay    int `json:"per_day"`
}

// Source ist die Beschreibung eines Dienstes.
type Source struct {
	ID      string
	Name    string
	Group   string // Quellen einer Gruppe zählen als eine unabhängige Stimme
	KeyName string // leer = ohne API-Key nutzbar
	Types   []ioc.Type
	Limit   Limit
	License string // Hinweis zu Gratis-Nutzung
	Signup  string
	Check   func(ctx context.Context, c *Client, key string, in ioc.Indicator) (Finding, error)
	// Verify prüft einen Key an einer Stelle, die einen gültigen Key verlangt.
	Verify func(ctx context.Context, c *Client, key string) error
}

// Supports meldet, ob die Quelle den Typ abfragen kann.
func (s *Source) Supports(t ioc.Type) bool {
	for _, x := range s.Types {
		if x == t {
			return true
		}
	}
	return false
}

// ErrUnauthorized signalisiert, dass der Dienst den API-Key abgelehnt hat.
var ErrUnauthorized = errors.New("API-Key ungültig oder ohne Berechtigung")

// ErrRateLimited signalisiert HTTP 429.
var ErrRateLimited = errors.New("Abfragelimit des Dienstes erreicht")

const maxBody = 32 << 20

// Client führt HTTP-Anfragen aus; Bases erlaubt Umleitung in Tests.
type Client struct {
	HTTP  *http.Client
	Bases map[string]string
}

// NewClient erzeugt einen Client mit festen Zeitlimits.
func NewClient(transport http.RoundTripper) *Client {
	return &Client{HTTP: &http.Client{Timeout: 25 * time.Second, Transport: transport, CheckRedirect: sameHostRedirect}}
}

// Go entfernt bei Umleitungen nur Authorization und Cookie. Unsere Keys stehen
// in eigenen Headern und dürfen daher nie zu einem anderen Ziel gelangen.
func sameHostRedirect(req *http.Request, via []*http.Request) error {
	first := via[0].URL
	if len(via) >= 3 || req.URL.Host != first.Host || req.URL.Scheme != first.Scheme {
		return http.ErrUseLastResponse
	}
	return nil
}

func (c *Client) base(def string) string {
	if b, ok := c.Bases[def]; ok {
		return b
	}
	return def
}

func (c *Client) do(ctx context.Context, method, url string, headers map[string]string, body io.Reader) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "OSINT-Check/1.0")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue interface{ Timeout() bool }
		if errors.As(err, &ue) && ue.Timeout() {
			return 0, nil, errors.New("Zeitüberschreitung beim Dienst")
		}
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		return 0, nil, fmt.Errorf("Dienst nicht erreichbar: %s", hostOnly(url))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return 0, nil, errors.New("Antwort konnte nicht gelesen werden")
	}
	return resp.StatusCode, data, nil
}

func hostOnly(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexByte(u, '/'); i >= 0 {
		return u[:i]
	}
	return u
}

// httpError übersetzt Statuscodes. notFound wird vom Aufrufer vorher behandelt.
func httpError(code int) error {
	switch {
	case code == 200:
		return nil
	case code == 401 || code == 403:
		return ErrUnauthorized
	case code == 429:
		return ErrRateLimited
	case code >= 500:
		return fmt.Errorf("Dienst meldet Störung (HTTP %d)", code)
	}
	return fmt.Errorf("unerwartete Antwort (HTTP %d)", code)
}

func decode(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return errors.New("Antwort des Dienstes hat ein unerwartetes Format")
	}
	return nil
}

func addKV(list []KV, k, v string) []KV {
	if strings.TrimSpace(v) == "" {
		return list
	}
	return append(list, KV{K: k, V: v})
}

func unixDate(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04 UTC")
}

func capList(in []string, n int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, n)
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
		if len(out) == n {
			break
		}
	}
	return out
}

// All liefert alle bekannten Quellen in Anzeigereihenfolge.
func All() []*Source {
	return []*Source{virusTotal(), abuseIPDB(), urlscan(), urlhaus(), malwareBazaar(), threatFox(), otx(), circl(), newFeodo(), newRDAP()}
}
