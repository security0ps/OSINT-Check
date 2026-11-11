package sources

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"osint-check/internal/ioc"
)

// Spamhaus DROP ("Don't Route Or Peer") listet Netzbereiche, die von
// Kriminellen kontrolliert werden. Die Liste ist laut Spamhaus für jeden
// kostenlos. Automatische Downloads höchstens stündlich, sonst droht eine
// Sperre der eigenen IP. Deshalb Cache von 12 h und Pause nach Fehlern.
const (
	dropTTL   = 12 * time.Hour
	dropRetry = 15 * time.Minute
)

type dropEntry struct {
	prefix netip.Prefix
	sblID  string
	rir    string
}

type dropList struct {
	sem      chan struct{} // nur ein Download zur Zeit, abbrechbar
	entries  []dropEntry
	fetched  time.Time
	failedAt time.Time
	lastErr  error
}

func newSpamhausDrop() *Source {
	list := &dropList{sem: make(chan struct{}, 1)}
	return &Source{
		ID: "spamhaus_drop", Name: "Spamhaus DROP", Group: "spamhaus",
		Types:   []ioc.Type{ioc.IPv4, ioc.IPv6},
		Limit:   Limit{PerMinute: 120},
		License: "Kostenlos, auch für Firmen; Download höchstens stündlich",
		Signup:  "https://www.spamhaus.org/drop/",
		Check: func(ctx context.Context, c *Client, _ string, in ioc.Indicator) (Finding, error) {
			return list.check(ctx, c, in)
		},
	}
}

func (l *dropList) load(ctx context.Context, c *Client) ([]dropEntry, error) {
	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-l.sem }()
	if l.entries != nil && time.Since(l.fetched) < dropTTL {
		return l.entries, nil
	}
	// Nach einem Fehler nicht bei jeder Prüfung erneut laden.
	if l.lastErr != nil && time.Since(l.failedAt) < dropRetry {
		return nil, l.lastErr
	}
	var all []dropEntry
	var err error
	for _, file := range []string{"drop_v4.json", "drop_v6.json"} {
		var part []dropEntry
		if part, err = fetchDrop(ctx, c, file); err != nil {
			break
		}
		all = append(all, part...)
	}
	if err != nil {
		if ctx.Err() == nil { // ein abgebrochener Auftrag ist kein Fehler der Liste
			l.failedAt, l.lastErr = time.Now(), fmt.Errorf("Spamhaus-DROP-Liste konnte nicht geladen werden: %w", err)
			return nil, l.lastErr
		}
		return nil, err
	}
	l.entries, l.fetched, l.lastErr = all, time.Now(), nil
	return l.entries, nil
}

func fetchDrop(ctx context.Context, c *Client, file string) ([]dropEntry, error) {
	code, data, err := c.do(ctx, http.MethodGet, c.base("https://www.spamhaus.org/drop")+"/"+file, nil, nil)
	if err == nil {
		err = httpError(code)
	}
	if err != nil {
		return nil, err
	}
	// Eine Zeile je Eintrag (JSON Lines), am Ende eine Metadaten-Zeile.
	var out []dropEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			CIDR  string `json:"cidr"`
			SBLID string `json:"sblid"`
			RIR   string `json:"rir"`
			Type  string `json:"type"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, errors.New("Antwort hat ein unerwartetes Format")
		}
		if rec.Type == "metadata" {
			continue
		}
		p, err := netip.ParsePrefix(rec.CIDR)
		if err != nil {
			return nil, errors.New("Antwort enthält einen ungültigen Netzbereich")
		}
		out = append(out, dropEntry{prefix: p.Masked(), sblID: capString(rec.SBLID, 32), rir: capString(rec.RIR, 32)})
	}
	if err := sc.Err(); err != nil {
		return nil, errors.New("Antwort hat ein unerwartetes Format")
	}
	if len(out) == 0 {
		return nil, errors.New("Liste ist leer")
	}
	return out, nil
}

func capString(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (l *dropList) check(ctx context.Context, c *Client, in ioc.Indicator) (Finding, error) {
	addr, err := netip.ParseAddr(in.Value)
	if err != nil {
		return Finding{}, errors.New("keine IP-Adresse")
	}
	addr = addr.Unmap()
	entries, err := l.load(ctx, c)
	if err != nil {
		return Finding{}, err
	}
	for _, e := range entries {
		if e.prefix.Contains(addr) {
			f := Finding{Verdict: Malicious, Summary: "Netz auf der Spamhaus-DROP-Liste (von Kriminellen kontrolliert)",
				Link: "https://check.spamhaus.org/"}
			f.Details = addKV(f.Details, "Netzbereich", e.prefix.String())
			f.Details = addKV(f.Details, "SBL-Eintrag", e.sblID)
			f.Details = addKV(f.Details, "Registry", e.rir)
			return f, nil
		}
	}
	return Finding{Verdict: NotFound, Summary: "Nicht auf der Spamhaus-DROP-Liste"}, nil
}
