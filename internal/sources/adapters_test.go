package sources

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"osint-check/internal/ioc"
)

type capture struct {
	Path    string
	Query   url.Values
	Headers http.Header
	Body    string
	Method  string
}

func fake(t *testing.T, base string, status int, payload string) (*Client, *capture) {
	t.Helper()
	got := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*got = capture{Path: r.URL.EscapedPath(), Query: r.URL.Query(), Headers: r.Header.Clone(), Body: string(b), Method: r.Method}
		w.WriteHeader(status)
		io.WriteString(w, payload)
	}))
	t.Cleanup(srv.Close)
	c := NewClient(nil)
	c.Bases = map[string]string{base: srv.URL}
	return c, got
}

func ind(t *testing.T, s string) ioc.Indicator {
	t.Helper()
	i, ok := ioc.Classify(s, ioc.Options{})
	if !ok {
		t.Fatalf("%s nicht erkannt", s)
	}
	return i
}

const sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

func TestVirusTotalURLIdentifierAndVerdict(t *testing.T) {
	c, got := fake(t, "https://www.virustotal.com/api/v3", 200,
		`{"data":{"attributes":{"last_analysis_stats":{"malicious":6,"suspicious":0,"harmless":60,"undetected":20},"reputation":-5}}}`)
	f, err := checkVT(context.Background(), c, "KEY", ind(t, "http://evil.com/x?y=1"))
	if err != nil {
		t.Fatal(err)
	}
	// base64url ohne Padding von "http://evil.com/x?y=1"
	if got.Path != "/urls/aHR0cDovL2V2aWwuY29tL3g_eT0x" {
		t.Errorf("Pfad: %s", got.Path)
	}
	if got.Headers.Get("x-apikey") != "KEY" {
		t.Error("API-Key-Header fehlt")
	}
	if f.Verdict != Malicious {
		t.Errorf("Verdict %s", f.Verdict)
	}
}

func TestVTVerdictThresholds(t *testing.T) {
	cases := []struct {
		typ  ioc.Type
		mal  int
		want Verdict
	}{
		{ioc.SHA256, 15, Malicious}, {ioc.SHA256, 14, Suspicious}, {ioc.SHA256, 5, Suspicious},
		{ioc.SHA256, 4, Weak}, {ioc.SHA256, 0, Clean},
		{ioc.URL, 5, Malicious}, {ioc.URL, 2, Suspicious}, {ioc.URL, 1, Weak}, {ioc.Domain, 0, Clean},
	}
	for _, c := range cases {
		if got := vtVerdict(c.typ, c.mal, 0, 0); got != c.want {
			t.Errorf("%s/%d: %s, want %s", c.typ, c.mal, got, c.want)
		}
	}
}

func TestVT404IsNotFound(t *testing.T) {
	c, _ := fake(t, "https://www.virustotal.com/api/v3", 404, `{}`)
	f, err := checkVT(context.Background(), c, "K", ind(t, sha))
	if err != nil || f.Verdict != NotFound {
		t.Fatalf("%v %v", f, err)
	}
}

func TestAuthAndRateErrors(t *testing.T) {
	c, _ := fake(t, "https://www.virustotal.com/api/v3", 401, `{}`)
	if _, err := checkVT(context.Background(), c, "K", ind(t, sha)); err == nil || !strings.Contains(err.Error(), "API-Key") {
		t.Fatalf("got %v", err)
	}
	c, _ = fake(t, "https://www.virustotal.com/api/v3", 429, `{}`)
	if _, err := checkVT(context.Background(), c, "K", ind(t, sha)); err != ErrRateLimited {
		t.Fatalf("got %v", err)
	}
}

func TestAbuseIPDB(t *testing.T) {
	c, got := fake(t, "https://api.abuseipdb.com/api/v2", 200,
		`{"data":{"abuseConfidenceScore":71,"totalReports":3,"usageType":"Content Delivery Network","isTor":true}}`)
	f, err := checkAbuseIPDB(context.Background(), c, "K", ind(t, "8.8.8.8"))
	if err != nil {
		t.Fatal(err)
	}
	if f.Verdict != Malicious || len(f.Warnings) != 2 {
		t.Fatalf("%+v", f)
	}
	if got.Query.Get("ipAddress") != "8.8.8.8" || got.Headers.Get("Key") != "K" {
		t.Errorf("%+v", got)
	}
}

func TestURLScanQueryEscaping(t *testing.T) {
	in := ioc.Indicator{Type: ioc.URL, Value: `http://evil.com/"x`}
	if q := urlscanQuery(in); !strings.Contains(q, `\"x`) {
		t.Fatal(q)
	}
	c, got := fake(t, "https://urlscan.io/api/v1", 200,
		`{"total":2,"results":[{"_id":"abc","verdicts":{"overall":{"malicious":true}}},{"_id":"def","verdicts":{"overall":{"malicious":false}}}]}`)
	f, err := checkURLScan(context.Background(), c, "K", ind(t, "evil.com"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Query.Get("q") != `page.domain:"evil.com"` || got.Headers.Get("API-Key") != "K" {
		t.Errorf("%+v", got)
	}
	if f.Verdict != Malicious || f.Link != "https://urlscan.io/result/abc/" {
		t.Errorf("%+v", f)
	}
}

func TestURLScanNoVerdictField(t *testing.T) {
	c, _ := fake(t, "https://urlscan.io/api/v1", 200, `{"total":1,"results":[{"_id":"abc"}]}`)
	f, _ := checkURLScan(context.Background(), c, "K", ind(t, "evil.com"))
	if f.Verdict != Info {
		t.Fatalf("%+v", f)
	}
}

func TestURLhaus(t *testing.T) {
	c, got := fake(t, "https://urlhaus-api.abuse.ch/v1", 200,
		`{"query_status":"ok","url_status":"online","threat":"malware_download","urlhaus_reference":"https://urlhaus.abuse.ch/url/1/","tags":null}`)
	f, err := checkURLhaus(context.Background(), c, "K", ind(t, "http://evil.com/x"))
	if err != nil || f.Verdict != Malicious {
		t.Fatalf("%+v %v", f, err)
	}
	if got.Path != "/url/" || got.Method != "POST" || got.Headers.Get("Auth-Key") != "K" || !strings.Contains(got.Body, "url=http") {
		t.Errorf("%+v", got)
	}
	c, got = fake(t, "https://urlhaus-api.abuse.ch/v1", 200, `{"query_status":"no_results"}`)
	f, _ = checkURLhaus(context.Background(), c, "K", ind(t, sha))
	if f.Verdict != NotFound || got.Path != "/payload/" || !strings.Contains(got.Body, "sha256_hash=") {
		t.Errorf("%+v %+v", f, got)
	}
	c, _ = fake(t, "https://urlhaus-api.abuse.ch/v1", 200, `{"query_status":"ok","urls":[{"url_status":"offline"},{"url_status":"offline"}]}`)
	f, _ = checkURLhaus(context.Background(), c, "K", ind(t, "evil.com"))
	if f.Verdict != Suspicious {
		t.Errorf("Host nur offline: %+v", f)
	}
}

func TestBazaarBothShapes(t *testing.T) {
	c, _ := fake(t, "https://mb-api.abuse.ch/api/v1", 200,
		`{"query_status":"ok","data":[{"sha256_hash":"`+sha+`","signature":"Emotet","tags":["exe"]}]}`)
	f, err := checkBazaar(context.Background(), c, "K", ind(t, sha))
	if err != nil || f.Verdict != Malicious || !strings.Contains(f.Summary, "Emotet") {
		t.Fatalf("%+v %v", f, err)
	}
	c, _ = fake(t, "https://mb-api.abuse.ch/api/v1", 200, `{"sha256_hash":"`+sha+`","signature":"Adwind"}`)
	f, err = checkBazaar(context.Background(), c, "K", ind(t, sha))
	if err != nil || !strings.Contains(f.Summary, "Adwind") {
		t.Fatalf("%+v %v", f, err)
	}
	c, _ = fake(t, "https://mb-api.abuse.ch/api/v1", 200, `{"query_status":"hash_not_found"}`)
	f, _ = checkBazaar(context.Background(), c, "K", ind(t, sha))
	if f.Verdict != NotFound {
		t.Fatalf("%+v", f)
	}
}

func TestThreatFox(t *testing.T) {
	c, got := fake(t, "https://threatfox-api.abuse.ch/api/v1", 200,
		`{"query_status":"ok","data":[{"id":"7","ioc":"8.8.8.8:443","malware_printable":"Cobalt Strike","confidence_level":80},{"id":"8","ioc":"8.8.8.80:1","confidence_level":100}]}`)
	f, err := checkThreatFox(context.Background(), c, "K", ind(t, "8.8.8.8"))
	if err != nil {
		t.Fatal(err)
	}
	if f.Verdict != Malicious || f.Link != "https://threatfox.abuse.ch/ioc/7/" {
		t.Fatalf("Teiltreffer 8.8.8.80 darf nicht zählen: %+v", f)
	}
	var body map[string]any
	json.Unmarshal([]byte(got.Body), &body)
	if body["query"] != "search_ioc" || body["exact_match"] != false {
		t.Errorf("%+v", body)
	}
	c, _ = fake(t, "https://threatfox-api.abuse.ch/api/v1", 200, `{"query_status":"no_result","data":"Your search did not yield any results"}`)
	f, err = checkThreatFox(context.Background(), c, "K", ind(t, sha))
	if err != nil || f.Verdict != NotFound {
		t.Fatalf("%+v %v", f, err)
	}
}

func TestOTXPaths(t *testing.T) {
	c, got := fake(t, "https://otx.alienvault.com/api/v1", 200, `{"pulse_info":{"count":6,"pulses":[{"name":"P","malware_families":[{"display_name":"Fam"}]}]},"validation":[]}`)
	f, err := checkOTX(context.Background(), c, "K", ind(t, "https://evil.com/a"))
	if err != nil || f.Verdict != Suspicious {
		t.Fatalf("%+v %v", f, err)
	}
	if got.Path != "/indicators/url/https:%2F%2Fevil.com%2Fa/general" || got.Headers.Get("X-OTX-API-KEY") != "K" {
		t.Errorf("%+v", got)
	}
	if a, _ := otxPath(ind(t, "a.evil.com")); a != "hostname/a.evil.com" {
		t.Error(a)
	}
	if a, _ := otxPath(ind(t, "evil.com")); a != "domain/evil.com" {
		t.Error(a)
	}
	if a, _ := otxPath(ind(t, "2606:4700::1")); a != "IPv6/2606:4700::1" {
		t.Error(a)
	}
}

func TestOTXValidationIsClean(t *testing.T) {
	c, _ := fake(t, "https://otx.alienvault.com/api/v1", 200, `{"pulse_info":{"count":9,"pulses":[]},"validation":[{"source":"alexa","message":"Top 1000"}]}`)
	f, _ := checkOTX(context.Background(), c, "K", ind(t, "google.com"))
	if f.Verdict != Clean {
		t.Fatalf("%+v", f)
	}
}

func TestCIRCL(t *testing.T) {
	c, got := fake(t, "https://hashlookup.circl.lu", 200, `{"FileName":"cmd.exe","hashlookup:trust":75,"source":["NSRL"]}`)
	f, err := checkCIRCL(context.Background(), c, "", ind(t, sha))
	if err != nil || f.Verdict != Clean {
		t.Fatalf("%+v %v", f, err)
	}
	if got.Path != "/lookup/sha256/"+sha {
		t.Error(got.Path)
	}
	c, _ = fake(t, "https://hashlookup.circl.lu", 200, `{"KnownMalicious":"misp"}`)
	f, _ = checkCIRCL(context.Background(), c, "", ind(t, sha))
	if f.Verdict != Malicious {
		t.Fatalf("%+v", f)
	}
}

func TestFeodo(t *testing.T) {
	c, _ := fake(t, "https://feodotracker.abuse.ch", 200, `[{"ip_address":"8.8.8.8","port":447,"status":"online","malware":"QakBot"}]`)
	s := newFeodo()
	f, err := s.Check(context.Background(), c, "", ind(t, "8.8.8.8"))
	if err != nil || f.Verdict != Malicious {
		t.Fatalf("%+v %v", f, err)
	}
	f, _ = s.Check(context.Background(), c, "", ind(t, "1.1.1.1"))
	if f.Verdict != NotFound {
		t.Fatalf("%+v", f)
	}
}

func TestErrorsDoNotLeakKeyOrURL(t *testing.T) {
	c := NewClient(nil)
	c.Bases = map[string]string{"https://api.abuseipdb.com/api/v2": "http://127.0.0.1:1"}
	_, err := checkAbuseIPDB(context.Background(), c, "GEHEIM", ind(t, "8.8.8.8"))
	if err == nil || strings.Contains(err.Error(), "GEHEIM") || strings.Contains(err.Error(), "ipAddress") {
		t.Fatalf("got %v", err)
	}
}

func TestEverySourceComplete(t *testing.T) {
	for _, s := range All() {
		if s.ID == "" || s.Name == "" || s.Group == "" || s.Check == nil || len(s.Types) == 0 || s.License == "" {
			t.Errorf("%+v unvollständig", s)
		}
	}
}
