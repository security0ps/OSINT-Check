package sources

import (
	"context"
	"errors"
	"testing"
)

func TestVerifyNeedsAcceptedKey(t *testing.T) {
	cases := []struct {
		name   string
		base   string
		verify func(context.Context, *Client, string) error
	}{
		{"VirusTotal", "https://www.virustotal.com/api/v3", verifyVT},
		{"AbuseIPDB", "https://api.abuseipdb.com/api/v2", verifyAbuseIPDB},
		{"urlscan", "https://urlscan.io/api/v1", verifyURLscan},
		{"OTX", "https://otx.alienvault.com/api/v1", verifyOTX},
	}
	for _, tc := range cases {
		for _, step := range []struct {
			status int
			want   error
		}{{200, nil}, {401, ErrUnauthorized}, {403, ErrUnauthorized}, {404, ErrKeyUnverified}, {429, ErrKeyUnverified}, {500, ErrKeyUnverified}} {
			c, got := fake(t, tc.base, step.status, `{}`)
			err := tc.verify(context.Background(), c, "dummy-key")
			if (step.want == nil) != (err == nil) || (step.want != nil && !errors.Is(err, step.want)) {
				t.Fatalf("%s HTTP %d: %v", tc.name, step.status, err)
			}
			if len(got.Headers) == 0 || !headerHasKey(got.Headers, "dummy-key") {
				t.Fatalf("%s: Key nicht gesendet", tc.name)
			}
		}
	}
	c := NewClient(nil)
	c.Bases = map[string]string{"https://www.virustotal.com/api/v3": "http://127.0.0.1:1"}
	if err := verifyVT(context.Background(), c, "K"); !errors.Is(err, ErrKeyUnverified) {
		t.Fatalf("Netzfehler: %v", err)
	}
}

func headerHasKey(h map[string][]string, key string) bool {
	for _, v := range h {
		for _, x := range v {
			if x == key {
				return true
			}
		}
	}
	return false
}

func TestVerifyAbuseCh(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{200, `{"query_status":"no_results"}`, nil},
		{200, `{"query_status":"ok"}`, nil},
		{200, `{"query_status":"unknown_auth_key"}`, ErrUnauthorized},
		{200, `{"query_status":"something_else"}`, ErrKeyUnverified},
		{401, `{}`, ErrUnauthorized},
		{404, `{}`, ErrKeyUnverified},
	} {
		c, _ := fake(t, "https://urlhaus-api.abuse.ch/v1", tc.status, tc.body)
		err := verifyAbuseCh(context.Background(), c, "dummy-key")
		if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Fatalf("%d %s: %v", tc.status, tc.body, err)
		}
	}
}
