package sources

import (
	"bytes"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

// DemoSamples sind Beispielwerte für den Demo-Modus.
const DemoSamples = `hxxp://phish-demo[.]example/login
phish-demo.example
203.0.113.66
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
d41d8cd98f00b204e9800998ecf8427e
example.com
192.168.1.10`

// DemoTransport beantwortet API-Aufrufe mit erfundenen Daten. So laufen im
// Demo-Modus die echten Adapter, aber keine Anfrage verlässt den Rechner.
type DemoTransport struct{}

func (DemoTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	time.Sleep(time.Duration(150+rand.IntN(900)) * time.Millisecond)
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	status, payload := demoResponse(r, string(body))
	return &http.Response{StatusCode: status, Header: http.Header{}, Request: r,
		Body: io.NopCloser(bytes.NewBufferString(payload))}, nil
}

func demoResponse(r *http.Request, body string) (int, string) {
	target := r.URL.RequestURI() + " " + body
	bad := strings.Contains(target, "phish-demo") || strings.Contains(target, "phish%2Ddemo") ||
		strings.Contains(target, "aHR0cDovL3BoaXNoLWRlbW8") || strings.Contains(target, "203.0.113.66") ||
		strings.Contains(target, "275a021b")
	clean := strings.Contains(target, "example.com")
	switch r.URL.Host {
	case "www.virustotal.com":
		switch {
		case bad && strings.Contains(target, "/files/"):
			return 200, `{"data":{"attributes":{"last_analysis_stats":{"malicious":61,"suspicious":0,"harmless":0,"undetected":11},"reputation":-12,"last_analysis_date":1793000000,"meaningful_name":"eicar.com","type_description":"Text","tags":["demo","testfile"],"popular_threat_classification":{"suggested_threat_label":"virus.eicar/test"}}}}`
		case bad:
			return 200, `{"data":{"attributes":{"last_analysis_stats":{"malicious":14,"suspicious":2,"harmless":58,"undetected":20},"reputation":-31,"last_analysis_date":1793000000,"as_owner":"Demo Hosting Ltd","country":"XX"}}}`
		case clean:
			return 200, `{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":68,"undetected":26},"reputation":12,"last_analysis_date":1793000000}}}`
		}
		return 404, `{}`
	case "api.abuseipdb.com":
		return 200, `{"data":{"abuseConfidenceScore":96,"totalReports":412,"numDistinctUsers":87,"countryCode":"XX","usageType":"Data Center/Web Hosting/Transit","isp":"Demo Hosting Ltd","domain":"demo-hosting.example","isTor":false,"lastReportedAt":"2026-11-04T18:21:07+00:00"}}`
	case "urlscan.io":
		if bad {
			return 200, `{"total":6,"results":[{"_id":"00000000-0000-4000-8000-000000000001","task":{"time":"2026-11-04T09:12:00Z"},"page":{"domain":"phish-demo.example","country":"XX","asnname":"Demo Hosting Ltd"},"verdicts":{"overall":{"malicious":true,"score":100}}}]}`
		}
		if clean {
			return 200, `{"total":3,"results":[{"_id":"00000000-0000-4000-8000-000000000002","task":{"time":"2026-11-02T10:00:00Z"},"page":{"domain":"example.com","country":"US"},"verdicts":{"overall":{"malicious":false,"score":0}}}]}`
		}
		return 200, `{"total":0,"results":[]}`
	case "urlhaus-api.abuse.ch":
		if strings.Contains(target, "phish-demo") && strings.Contains(target, "/url/") {
			return 200, `{"query_status":"ok","urlhaus_reference":"https://urlhaus.abuse.ch/url/0/","url_status":"online","threat":"malware_download","date_added":"2026-11-03 07:40:11 UTC","tags":["demo","loader"]}`
		}
		return 200, `{"query_status":"no_results"}`
	case "mb-api.abuse.ch":
		if bad {
			return 200, `{"query_status":"ok","data":[{"sha256_hash":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","signature":"Demo-Familie","file_name":"eicar.com","file_type":"com","first_seen":"2026-01-01 00:00:00","tags":["demo"]}]}`
		}
		return 200, `{"query_status":"hash_not_found"}`
	case "threatfox-api.abuse.ch":
		if strings.Contains(target, "203.0.113.66") {
			return 200, `{"query_status":"ok","data":[{"id":"1","ioc":"203.0.113.66:443","threat_type_desc":"Command-and-Control-Server (Demo)","malware_printable":"Demo-Stealer","confidence_level":90,"first_seen":"2026-10-28 11:00:00 UTC","tags":["demo","c2"]}]}`
		}
		return 200, `{"query_status":"no_result","data":"Your search did not yield any results"}`
	case "otx.alienvault.com":
		switch {
		case bad:
			return 200, `{"pulse_info":{"count":7,"pulses":[{"name":"Demo-Kampagne","tags":["phishing"],"malware_families":[{"display_name":"Demo-Stealer"}]}]},"validation":[]}`
		case clean:
			return 200, `{"pulse_info":{"count":0,"pulses":[]},"validation":[{"source":"demo","message":"Bekannte Beispiel-Domain"}]}`
		}
		return 404, `{}`
	case "hashlookup.circl.lu":
		return 404, `{}`
	case "www.spamhaus.org":
		if strings.HasSuffix(r.URL.Path, "drop_v6.json") {
			return 200, "{\"cidr\":\"2001:db8:bad::/48\",\"sblid\":\"SBL000002\",\"rir\":\"demo\"}\n{\"type\":\"metadata\",\"records\":1}\n"
		}
		return 200, "{\"cidr\":\"203.0.113.64/26\",\"sblid\":\"SBL000001\",\"rir\":\"demo\"}\n{\"type\":\"metadata\",\"records\":1}\n"
	case "feodotracker.abuse.ch":
		return 200, `[{"ip_address":"203.0.113.66","port":443,"status":"online","malware":"Demo-Botnet","as_name":"Demo Hosting Ltd","country":"XX","last_online":"2026-11-04"}]`
	}
	return 500, `{}`
}
