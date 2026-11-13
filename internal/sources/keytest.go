package sources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Ein Key gilt nur als geprüft, wenn der Dienst eine Anfrage, die einen
// gültigen Key verlangt, mit HTTP 200 beantwortet. 404, Netzfehler oder
// andere Antworten bestätigen nichts.

// ErrKeyUnverified bedeutet: Der Dienst hat weder angenommen noch abgelehnt.
var ErrKeyUnverified = errors.New("Key konnte nicht geprüft werden")

func verifyStatus(code int, err error) error {
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKeyUnverified, err)
	}
	if code == http.StatusOK {
		return nil
	}
	if e := httpError(code); errors.Is(e, ErrUnauthorized) {
		return ErrUnauthorized
	} else if e != nil {
		return fmt.Errorf("%w: %w", ErrKeyUnverified, e)
	}
	return ErrKeyUnverified
}

func verifyVT(ctx context.Context, c *Client, key string) error {
	code, _, err := c.do(ctx, http.MethodGet, c.base("https://www.virustotal.com/api/v3")+"/domains/example.com", map[string]string{"x-apikey": key}, nil)
	return verifyStatus(code, err)
}

func verifyAbuseIPDB(ctx context.Context, c *Client, key string) error {
	q := url.Values{"ipAddress": {"8.8.8.8"}, "maxAgeInDays": {"1"}}
	code, _, err := c.do(ctx, http.MethodGet, c.base("https://api.abuseipdb.com/api/v2")+"/check?"+q.Encode(), map[string]string{"Key": key}, nil)
	return verifyStatus(code, err)
}

func verifyURLscan(ctx context.Context, c *Client, key string) error {
	code, _, err := c.do(ctx, http.MethodGet, c.base("https://urlscan.io/api/v1")+"/quotas", map[string]string{"API-Key": key}, nil)
	return verifyStatus(code, err)
}

func verifyOTX(ctx context.Context, c *Client, key string) error {
	code, _, err := c.do(ctx, http.MethodGet, c.base("https://otx.alienvault.com/api/v1")+"/pulses/subscribed?limit=1", map[string]string{"X-OTX-API-KEY": key}, nil)
	return verifyStatus(code, err)
}

// abuse.ch: Eine Host-Abfrage bei URLhaus verlangt den Auth-Key. Nur eine
// reguläre Antwort (Treffer oder kein Treffer) bestätigt den Key.
func verifyAbuseCh(ctx context.Context, c *Client, key string) error {
	form := url.Values{"host": {"example.com"}}
	code, data, err := c.do(ctx, http.MethodPost, c.base("https://urlhaus-api.abuse.ch/v1")+"/host/", formHeaders(key), strings.NewReader(form.Encode()))
	if err := verifyStatus(code, err); err != nil {
		return err
	}
	var r struct {
		Status string `json:"query_status"`
	}
	if decode(data, &r) != nil {
		return ErrKeyUnverified
	}
	switch {
	case r.Status == "ok" || r.Status == "no_results":
		return nil
	case strings.Contains(r.Status, "auth"):
		return ErrUnauthorized
	}
	return ErrKeyUnverified
}
