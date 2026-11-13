package sources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"osint-check/internal/ioc"
)

// RDAP liefert öffentliche Registrierungsdaten einer Domain direkt von der
// zuständigen Registry. Welche Registry für welche Endung zuständig ist,
// steht in der offiziellen Liste der IANA. Ohne API-Key.
const (
	rdapBootstrapTTL = 24 * time.Hour
	rdapRetry        = 15 * time.Minute
	rdapYoung        = 30 // Tage: jüngere Domains gelten als verdächtig
)

type rdapDirectory struct {
	sem      chan struct{}
	servers  map[string]string // Endung -> Basis-URL der Registry
	fetched  time.Time
	failedAt time.Time
	lastErr  error
}

func newRDAP() *Source {
	dir := &rdapDirectory{sem: make(chan struct{}, 1)}
	return &Source{
		ID: "rdap", Name: "Domain-Alter (RDAP)", Group: "rdap",
		Types:   []ioc.Type{ioc.Domain, ioc.URL},
		Limit:   Limit{PerMinute: 30},
		License: "Öffentliche Registry-Daten, ohne API-Key",
		Check: func(ctx context.Context, c *Client, _ string, in ioc.Indicator) (Finding, error) {
			return dir.check(ctx, c, in)
		},
	}
}

func (d *rdapDirectory) load(ctx context.Context, c *Client) (map[string]string, error) {
	select {
	case d.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-d.sem }()
	if d.servers != nil && time.Since(d.fetched) < rdapBootstrapTTL {
		return d.servers, nil
	}
	if d.lastErr != nil && time.Since(d.failedAt) < rdapRetry {
		return nil, d.lastErr
	}
	servers, err := fetchRDAPBootstrap(ctx, c)
	if err != nil {
		if ctx.Err() == nil {
			d.failedAt, d.lastErr = time.Now(), fmt.Errorf("RDAP-Verzeichnis der IANA konnte nicht geladen werden: %w", err)
			return nil, d.lastErr
		}
		return nil, err
	}
	d.servers, d.fetched, d.lastErr = servers, time.Now(), nil
	return servers, nil
}

func fetchRDAPBootstrap(ctx context.Context, c *Client) (map[string]string, error) {
	code, data, err := c.do(ctx, http.MethodGet, c.base("https://data.iana.org/rdap")+"/dns.json", nil, nil)
	if err == nil {
		err = httpError(code)
	}
	if err != nil {
		return nil, err
	}
	var boot struct {
		Services [][][]string `json:"services"`
	}
	if err := decode(data, &boot); err != nil {
		return nil, err
	}
	servers := map[string]string{}
	for _, svc := range boot.Services {
		if len(svc) != 2 {
			continue
		}
		base := ""
		for _, u := range svc[1] {
			// Nur HTTPS-Server der Registries, keine anderen Schemata.
			if p, err := url.Parse(u); err == nil && p.Scheme == "https" && p.Host != "" && p.User == nil {
				base = strings.TrimSuffix(u, "/") + "/"
				break
			}
		}
		if base == "" {
			continue
		}
		for _, tld := range svc[0] {
			servers[strings.ToLower(tld)] = base
		}
	}
	if len(servers) == 0 {
		return nil, errors.New("Verzeichnis ist leer")
	}
	return servers, nil
}

type rdapDomain struct {
	LDHName string `json:"ldhName"`
	Events  []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
}

func (d *rdapDirectory) check(ctx context.Context, c *Client, in ioc.Indicator) (Finding, error) {
	host := in.Value
	if in.Type == ioc.URL {
		host = in.Host
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	name, suffixErr := publicsuffix.EffectiveTLDPlusOne(host)
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil || suffixErr != nil {
		return Finding{Verdict: NotFound, Summary: "Kein Domainname"}, nil
	}
	servers, err := d.load(ctx, c)
	if err != nil {
		return Finding{}, err
	}
	base, ok := servers[name[strings.LastIndexByte(name, '.')+1:]]
	if !ok {
		return Finding{Verdict: Info, Summary: "Für diese Endung gibt es keinen RDAP-Dienst"}, nil
	}
	code, data, err := c.do(ctx, http.MethodGet, base+"domain/"+url.PathEscape(name), map[string]string{"Accept": "application/rdap+json, application/json"}, nil)
	if err != nil {
		return Finding{}, err
	}
	if code == http.StatusNotFound {
		return Finding{Verdict: NotFound, Summary: "Domain bei der Registry nicht gefunden"}, nil
	}
	if err := httpError(code); err != nil {
		return Finding{}, err
	}
	var r rdapDomain
	if err := decode(data, &r); err != nil {
		return Finding{}, err
	}
	if !strings.EqualFold(strings.TrimSuffix(r.LDHName, "."), name) {
		return Finding{Verdict: NotFound, Summary: "Domain bei der Registry nicht gefunden"}, nil
	}
	return rdapFinding(name, r, time.Now()), nil
}

func rdapFinding(name string, r rdapDomain, now time.Time) Finding {
	var registered, expires time.Time
	for _, e := range r.Events {
		t, err := time.Parse(time.RFC3339, e.Date)
		if err != nil {
			continue
		}
		switch e.Action {
		case "registration":
			registered = t
		case "expiration":
			expires = t
		}
	}
	f := Finding{}
	f.Details = addKV(f.Details, "Domain", name)
	if registered.IsZero() {
		f.Verdict, f.Summary = Info, "Registrierungsdatum nicht veröffentlicht"
		return f
	}
	days := int(now.Sub(registered).Hours() / 24)
	date := registered.UTC().Format("2006-01-02")
	f.Details = addKV(f.Details, "Registriert", date)
	if !expires.IsZero() {
		f.Details = addKV(f.Details, "Läuft ab", expires.UTC().Format("2006-01-02"))
	}
	if days < rdapYoung {
		f.Verdict, f.Summary = Suspicious, fmt.Sprintf("Neu registriert am %s (%d Tage alt)", date, days)
		return f
	}
	f.Verdict, f.Summary = Info, fmt.Sprintf("Registriert am %s (%d Tage alt)", date, days)
	return f
}
