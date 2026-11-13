package sources

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"osint-check/internal/ioc"
)

const nonCommercial = "Gratis-Zugang nur für nicht-kommerzielle Nutzung"

// --- VirusTotal ---------------------------------------------------------

func virusTotal() *Source {
	return &Source{
		ID: "virustotal", Name: "VirusTotal", Group: "virustotal", KeyName: "virustotal",
		Types:   []ioc.Type{ioc.MD5, ioc.SHA1, ioc.SHA256, ioc.URL, ioc.Domain, ioc.IPv4, ioc.IPv6},
		Limit:   Limit{PerMinute: 4, PerDay: 500},
		License: "Public API nicht für kommerzielle Produkte und Geschäftsprozesse",
		Signup:  "https://www.virustotal.com/gui/join-us",
		Check:   checkVT,
		Verify:  verifyVT,
	}
}

func checkVT(ctx context.Context, c *Client, key string, in ioc.Indicator) (Finding, error) {
	var path, gui string
	switch {
	case in.Type.IsHash():
		path, gui = "/files/"+in.Value, "file/"+in.Value
	case in.Type == ioc.URL:
		path = "/urls/" + base64.RawURLEncoding.EncodeToString([]byte(in.Value))
		sum := sha256.Sum256([]byte(in.Value))
		gui = "url/" + hex.EncodeToString(sum[:])
	case in.Type == ioc.Domain:
		path, gui = "/domains/"+in.Value, "domain/"+in.Value
	default:
		path, gui = "/ip_addresses/"+in.Value, "ip-address/"+in.Value
	}
	code, data, err := c.do(ctx, http.MethodGet, c.base("https://www.virustotal.com/api/v3")+path, map[string]string{"x-apikey": key}, nil)
	if err != nil {
		return Finding{}, err
	}
	if code == 404 {
		return Finding{Verdict: NotFound, Summary: "Bei VirusTotal nicht bekannt"}, nil
	}
	if err := httpError(code); err != nil {
		return Finding{}, err
	}
	var r struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				Reputation int      `json:"reputation"`
				Date       int64    `json:"last_analysis_date"`
				Name       string   `json:"meaningful_name"`
				FileType   string   `json:"type_description"`
				ASOwner    string   `json:"as_owner"`
				Country    string   `json:"country"`
				Tags       []string `json:"tags"`
				Threat     struct {
					Label string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := decode(data, &r); err != nil {
		return Finding{}, err
	}
	a := r.Data.Attributes
	s := a.Stats
	total := s.Malicious + s.Suspicious + s.Harmless + s.Undetected
	f := Finding{Link: "https://www.virustotal.com/gui/" + gui, Tags: capList(a.Tags, 8)}
	f.Verdict = vtVerdict(in.Type, s.Malicious, s.Suspicious, a.Reputation)
	f.Summary = fmt.Sprintf("%d von %d Engines melden bösartig", s.Malicious, total)
	if total == 0 {
		f.Verdict, f.Summary = Info, "Bekannt, aber noch keine Engine-Analyse vorhanden"
	}
	f.Details = addKV(f.Details, "Verdächtig", nonZero(s.Suspicious))
	f.Details = addKV(f.Details, "Community-Reputation", strconv.Itoa(a.Reputation))
	f.Details = addKV(f.Details, "Bedrohung", a.Threat.Label)
	f.Details = addKV(f.Details, "Dateiname", a.Name)
	f.Details = addKV(f.Details, "Dateityp", a.FileType)
	f.Details = addKV(f.Details, "AS-Betreiber", a.ASOwner)
	f.Details = addKV(f.Details, "Land", a.Country)
	f.Details = addKV(f.Details, "Letzte Analyse", unixDate(a.Date))
	return f, nil
}

// Dateien werden von deutlich mehr Engines bewertet als URLs, Domains und IPs.
func vtVerdict(t ioc.Type, mal, susp, reputation int) Verdict {
	high, mid := 5, 2
	if t.IsHash() {
		high, mid = 15, 5
	}
	switch {
	case mal >= high:
		return Malicious
	case mal >= mid:
		return Suspicious
	case mal > 0 || susp > 0 || reputation < -10:
		return Weak
	}
	return Clean
}

func nonZero(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// --- AbuseIPDB ----------------------------------------------------------

func abuseIPDB() *Source {
	return &Source{
		ID: "abuseipdb", Name: "AbuseIPDB", Group: "abuseipdb", KeyName: "abuseipdb",
		Types:   []ioc.Type{ioc.IPv4, ioc.IPv6},
		Limit:   Limit{PerMinute: 60, PerDay: 1000},
		License: nonCommercial,
		Signup:  "https://www.abuseipdb.com/register?plan=free",
		Check:   checkAbuseIPDB,
		Verify:  verifyAbuseIPDB,
	}
}

func checkAbuseIPDB(ctx context.Context, c *Client, key string, in ioc.Indicator) (Finding, error) {
	q := url.Values{"ipAddress": {in.Value}, "maxAgeInDays": {"90"}}
	code, data, err := c.do(ctx, http.MethodGet, c.base("https://api.abuseipdb.com/api/v2")+"/check?"+q.Encode(), map[string]string{"Key": key}, nil)
	if err != nil {
		return Finding{}, err
	}
	if err := httpError(code); err != nil {
		return Finding{}, err
	}
	var r struct {
		Data struct {
			Score    int    `json:"abuseConfidenceScore"`
			Reports  int    `json:"totalReports"`
			Users    int    `json:"numDistinctUsers"`
			Country  string `json:"countryCode"`
			Usage    string `json:"usageType"`
			ISP      string `json:"isp"`
			Domain   string `json:"domain"`
			IsTor    bool   `json:"isTor"`
			LastSeen string `json:"lastReportedAt"`
		} `json:"data"`
	}
	if err := decode(data, &r); err != nil {
		return Finding{}, err
	}
	d := r.Data
	f := Finding{Link: "https://www.abuseipdb.com/check/" + in.Value}
	switch {
	case d.Score >= 70:
		f.Verdict = Malicious
	case d.Score >= 40:
		f.Verdict = Suspicious
	case d.Score > 0 || d.Reports > 0:
		f.Verdict = Weak
	default:
		f.Verdict = Clean
	}
	f.Summary = fmt.Sprintf("Abuse-Score %d/100 aus %d Meldungen", d.Score, d.Reports)
	f.Details = addKV(f.Details, "Melder", nonZero(d.Users))
	f.Details = addKV(f.Details, "ISP", d.ISP)
	f.Details = addKV(f.Details, "Nutzungsart", d.Usage)
	f.Details = addKV(f.Details, "Domain", d.Domain)
	f.Details = addKV(f.Details, "Land", d.Country)
	f.Details = addKV(f.Details, "Letzte Meldung", d.LastSeen)
	if d.IsTor {
		f.Tags = append(f.Tags, "Tor")
		f.Warnings = append(f.Warnings, "Tor-Exit-Node: wird von vielen Personen genutzt")
	}
	if strings.Contains(d.Usage, "Content Delivery") {
		f.Warnings = append(f.Warnings, "CDN-Adresse: Eine Blockade kann viele legitime Websites treffen")
	}
	return f, nil
}

// --- urlscan.io ---------------------------------------------------------

func urlscan() *Source {
	return &Source{
		ID: "urlscan", Name: "urlscan.io", Group: "urlscan", KeyName: "urlscan",
		Types:   []ioc.Type{ioc.URL, ioc.Domain, ioc.IPv4, ioc.IPv6, ioc.SHA256},
		Limit:   Limit{PerMinute: 30},
		License: "Kommerzielle Nutzung braucht laut AGB eine schriftliche Erlaubnis",
		Signup:  "https://urlscan.io/user/signup/",
		Check:   checkURLScan,
		Verify:  verifyURLscan,
	}
}

var esEscape = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func urlscanQuery(in ioc.Indicator) string {
	v := `"` + esEscape.Replace(in.Value) + `"`
	switch {
	case in.Type == ioc.URL:
		return "task.url.keyword:" + v + " OR page.url.keyword:" + v
	case in.Type == ioc.Domain:
		return "page.domain:" + v
	case in.Type == ioc.SHA256:
		return "hash:" + v
	}
	return "page.ip:" + v
}

func checkURLScan(ctx context.Context, c *Client, key string, in ioc.Indicator) (Finding, error) {
	query := urlscanQuery(in)
	q := url.Values{"q": {query}, "size": {"20"}}
	code, data, err := c.do(ctx, http.MethodGet, c.base("https://urlscan.io/api/v1")+"/search/?"+q.Encode(), map[string]string{"API-Key": key}, nil)
	if err != nil {
		return Finding{}, err
	}
	if err := httpError(code); err != nil {
		return Finding{}, err
	}
	var r struct {
		Total   int `json:"total"`
		Results []struct {
			ID   string `json:"_id"`
			Task struct {
				Time string `json:"time"`
			} `json:"task"`
			Page struct {
				Domain  string `json:"domain"`
				Country string `json:"country"`
				ASN     string `json:"asnname"`
			} `json:"page"`
			Verdicts *struct {
				Overall struct {
					Malicious bool `json:"malicious"`
					Score     int  `json:"score"`
				} `json:"overall"`
			} `json:"verdicts"`
		} `json:"results"`
	}
	if err := decode(data, &r); err != nil {
		return Finding{}, err
	}
	if len(r.Results) == 0 {
		return Finding{Verdict: NotFound, Summary: "Keine vorhandenen Scans gefunden"}, nil
	}
	mal := 0
	for _, x := range r.Results {
		if x.Verdicts != nil && x.Verdicts.Overall.Malicious {
			mal++
		}
	}
	n := len(r.Results)
	f := Finding{Link: "https://urlscan.io/result/" + url.PathEscape(r.Results[0].ID) + "/"}
	switch {
	case mal*3 >= n: // mindestens ein Drittel der letzten Scans
		f.Verdict = Malicious
	case mal > 0:
		f.Verdict = Suspicious
	default:
		f.Verdict = Info
	}
	f.Summary = fmt.Sprintf("%d Scans gefunden, von den letzten %d sind %d als bösartig markiert", max(r.Total, n), n, mal)
	if mal == 0 {
		f.Summary = fmt.Sprintf("%d Scans gefunden, keiner der letzten %d als bösartig markiert", max(r.Total, n), n)
	}
	first := r.Results[0]
	f.Details = addKV(f.Details, "Letzter Scan", first.Task.Time)
	f.Details = addKV(f.Details, "Domain", first.Page.Domain)
	f.Details = addKV(f.Details, "Hoster", first.Page.ASN)
	f.Details = addKV(f.Details, "Land", first.Page.Country)
	return f, nil
}

// --- abuse.ch -----------------------------------------------------------

const abuseChLicense = "Gratis für nicht gewinnorientierte Nutzung, Firmen brauchen ggf. ein Abo"

func abuseKey(key string) map[string]string { return map[string]string{"Auth-Key": key} }

func formHeaders(key string) map[string]string {
	h := abuseKey(key)
	h["Content-Type"] = "application/x-www-form-urlencoded"
	return h
}

func urlhaus() *Source {
	return &Source{
		ID: "urlhaus", Name: "URLhaus", Group: "abuse.ch", KeyName: "abusech",
		Types:   []ioc.Type{ioc.URL, ioc.Domain, ioc.IPv4, ioc.IPv6, ioc.MD5, ioc.SHA256},
		Limit:   Limit{PerMinute: 60},
		License: abuseChLicense,
		Signup:  "https://auth.abuse.ch/",
		Check:   checkURLhaus,
		Verify:  verifyAbuseCh,
	}
}

func checkURLhaus(ctx context.Context, c *Client, key string, in ioc.Indicator) (Finding, error) {
	var endpoint string
	form := url.Values{}
	switch {
	case in.Type == ioc.URL:
		endpoint = "/url/"
		form.Set("url", in.Value)
	case in.Type == ioc.MD5:
		endpoint = "/payload/"
		form.Set("md5_hash", in.Value)
	case in.Type == ioc.SHA256:
		endpoint = "/payload/"
		form.Set("sha256_hash", in.Value)
	default:
		endpoint = "/host/"
		form.Set("host", in.Value)
	}
	code, data, err := c.do(ctx, http.MethodPost, c.base("https://urlhaus-api.abuse.ch/v1")+endpoint, formHeaders(key), strings.NewReader(form.Encode()))
	if err != nil {
		return Finding{}, err
	}
	if err := httpError(code); err != nil {
		return Finding{}, err
	}
	var r struct {
		Status    string   `json:"query_status"`
		Reference string   `json:"urlhaus_reference"`
		URLStatus string   `json:"url_status"`
		Threat    string   `json:"threat"`
		Added     string   `json:"date_added"`
		First     string   `json:"firstseen"`
		URLCount  any      `json:"url_count"`
		Tags      []string `json:"tags"`
		Signature string   `json:"signature"`
		FileType  string   `json:"file_type"`
		URLs      []struct {
			Status string `json:"url_status"`
		} `json:"urls"`
	}
	if err := decode(data, &r); err != nil {
		return Finding{}, err
	}
	switch r.Status {
	case "ok":
	case "no_results":
		return Finding{Verdict: NotFound, Summary: "Nicht bei URLhaus gelistet"}, nil
	default:
		return Finding{}, fmt.Errorf("URLhaus meldet: %s", r.Status)
	}
	f := Finding{Link: r.Reference, Tags: capList(r.Tags, 8)}
	switch {
	case in.Type == ioc.URL:
		f.Verdict = Malicious
		f.Summary = "Als Malware-URL gelistet, Status: " + statusDE(r.URLStatus)
	case in.Type.IsHash():
		f.Verdict = Malicious
		f.Summary = "Als Malware-Payload gelistet"
		f.Details = addKV(f.Details, "Malware-Familie", r.Signature)
		f.Details = addKV(f.Details, "Dateityp", r.FileType)
	default:
		online := 0
		for _, u := range r.URLs {
			if u.Status == "online" {
				online++
			}
		}
		f.Verdict = Suspicious
		if online > 0 {
			f.Verdict = Malicious
		}
		f.Summary = fmt.Sprintf("%d gelistete Malware-URLs auf diesem Host, %d aktiv", len(r.URLs), online)
	}
	f.Details = addKV(f.Details, "Bedrohung", r.Threat)
	f.Details = addKV(f.Details, "Erfasst", firstNonEmpty(r.Added, r.First))
	return f, nil
}

func statusDE(s string) string {
	switch s {
	case "online":
		return "aktiv"
	case "offline":
		return "offline"
	}
	return "unbekannt"
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func malwareBazaar() *Source {
	return &Source{
		ID: "malwarebazaar", Name: "MalwareBazaar", Group: "abuse.ch", KeyName: "abusech",
		Types:   []ioc.Type{ioc.MD5, ioc.SHA1, ioc.SHA256},
		Limit:   Limit{PerMinute: 60},
		License: abuseChLicense,
		Signup:  "https://auth.abuse.ch/",
		Check:   checkBazaar,
	}
}

type bazaarSample struct {
	SHA256    string   `json:"sha256_hash"`
	Signature string   `json:"signature"`
	FileName  string   `json:"file_name"`
	FileType  string   `json:"file_type"`
	FirstSeen string   `json:"first_seen"`
	Tags      []string `json:"tags"`
}

func checkBazaar(ctx context.Context, c *Client, key string, in ioc.Indicator) (Finding, error) {
	form := url.Values{"query": {"get_info"}, "hash": {in.Value}}
	code, data, err := c.do(ctx, http.MethodPost, c.base("https://mb-api.abuse.ch/api/v1")+"/", formHeaders(key), strings.NewReader(form.Encode()))
	if err != nil {
		return Finding{}, err
	}
	if err := httpError(code); err != nil {
		return Finding{}, err
	}
	var r struct {
		Status string          `json:"query_status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := decode(data, &r); err != nil {
		return Finding{}, err
	}
	switch r.Status {
	case "hash_not_found", "no_results":
		return Finding{Verdict: NotFound, Summary: "Nicht in MalwareBazaar"}, nil
	case "ok", "":
	default:
		return Finding{}, fmt.Errorf("MalwareBazaar meldet: %s", r.Status)
	}
	var sample bazaarSample
	var list []bazaarSample
	if json.Unmarshal(r.Data, &list) == nil && len(list) > 0 {
		sample = list[0]
	} else if err := decode(data, &sample); err != nil || sample.SHA256 == "" {
		return Finding{}, errors.New("Antwort des Dienstes hat ein unerwartetes Format")
	}
	f := Finding{Verdict: Malicious, Summary: "Malware-Sample bekannt", Tags: capList(sample.Tags, 8),
		Link: "https://bazaar.abuse.ch/sample/" + sample.SHA256 + "/"}
	if sample.Signature != "" {
		f.Summary = "Malware-Sample bekannt: " + sample.Signature
	}
	f.Details = addKV(f.Details, "Dateiname", sample.FileName)
	f.Details = addKV(f.Details, "Dateityp", sample.FileType)
	f.Details = addKV(f.Details, "Erstmals gesehen", sample.FirstSeen)
	return f, nil
}

func threatFox() *Source {
	return &Source{
		ID: "threatfox", Name: "ThreatFox", Group: "abuse.ch", KeyName: "abusech",
		Types:   []ioc.Type{ioc.URL, ioc.Domain, ioc.IPv4, ioc.IPv6, ioc.MD5, ioc.SHA256},
		Limit:   Limit{PerMinute: 60},
		License: abuseChLicense,
		Signup:  "https://auth.abuse.ch/",
		Check:   checkThreatFox,
	}
}

type foxIOC struct {
	ID         json.Number `json:"id"`
	IOC        string      `json:"ioc"`
	ThreatType string      `json:"threat_type_desc"`
	Malware    string      `json:"malware_printable"`
	Confidence int         `json:"confidence_level"`
	FirstSeen  string      `json:"first_seen"`
	Tags       []string    `json:"tags"`
}

func checkThreatFox(ctx context.Context, c *Client, key string, in ioc.Indicator) (Finding, error) {
	body := map[string]any{"query": "search_ioc", "search_term": in.Value, "exact_match": true}
	if in.Type.IsHash() {
		body = map[string]any{"query": "search_hash", "hash": in.Value}
	}
	if in.Type.IsIP() { // ThreatFox speichert IPs meist als ip:port
		body["exact_match"] = false
	}
	raw, _ := json.Marshal(body)
	h := abuseKey(key)
	h["Content-Type"] = "application/json"
	code, data, err := c.do(ctx, http.MethodPost, c.base("https://threatfox-api.abuse.ch/api/v1")+"/", h, strings.NewReader(string(raw)))
	if err != nil {
		return Finding{}, err
	}
	if err := httpError(code); err != nil {
		return Finding{}, err
	}
	var r struct {
		Status string          `json:"query_status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := decode(data, &r); err != nil {
		return Finding{}, err
	}
	notFound := Finding{Verdict: NotFound, Summary: "Nicht bei ThreatFox gelistet (Treffer bis 6 Monate zurück)"}
	if r.Status == "no_result" || r.Status == "no_results" {
		return notFound, nil
	}
	if r.Status != "ok" {
		return Finding{}, fmt.Errorf("ThreatFox meldet: %s", r.Status)
	}
	if trimmed := bytes.TrimSpace(r.Data); len(trimmed) == 0 || trimmed[0] != '[' {
		return notFound, nil // bei null Treffern ist data ein Text
	}
	var list []foxIOC
	if err := decode(r.Data, &list); err != nil {
		return Finding{}, err // nie als „nicht gefunden“ ausgeben
	}
	if in.Type.IsIP() {
		var exact []foxIOC
		for _, x := range list {
			if x.IOC == in.Value || strings.HasPrefix(x.IOC, in.Value+":") || strings.HasPrefix(x.IOC, "["+in.Value+"]:") {
				exact = append(exact, x)
			}
		}
		list = exact
	}
	if len(list) == 0 {
		return notFound, nil
	}
	best := list[0]
	for _, x := range list {
		if x.Confidence > best.Confidence {
			best = x
		}
	}
	f := Finding{Verdict: Suspicious, Tags: capList(best.Tags, 8)}
	if best.Confidence >= 75 {
		f.Verdict = Malicious
	}
	if best.ID != "" {
		f.Link = "https://threatfox.abuse.ch/ioc/" + best.ID.String() + "/"
	}
	f.Summary = fmt.Sprintf("Gelistet als %s (Konfidenz %d %%)", firstNonEmpty(best.Malware, "Malware-IOC"), best.Confidence)
	f.Details = addKV(f.Details, "Bedrohungsart", best.ThreatType)
	f.Details = addKV(f.Details, "Treffer", strconv.Itoa(len(list)))
	f.Details = addKV(f.Details, "Erstmals gesehen", best.FirstSeen)
	return f, nil
}

// --- AlienVault OTX -----------------------------------------------------

func otx() *Source {
	return &Source{
		ID: "otx", Name: "AlienVault OTX", Group: "otx", KeyName: "otx",
		Types:   []ioc.Type{ioc.MD5, ioc.SHA1, ioc.SHA256, ioc.URL, ioc.Domain, ioc.IPv4, ioc.IPv6},
		Limit:   Limit{PerMinute: 60},
		License: nonCommercial,
		Signup:  "https://otx.alienvault.com/",
		Check:   checkOTX,
		Verify:  verifyOTX,
	}
}

func otxPath(in ioc.Indicator) (api, web string) {
	switch {
	case in.Type.IsHash():
		return "file/" + in.Value, "file/" + in.Value
	case in.Type == ioc.URL:
		esc := url.PathEscape(in.Value)
		return "url/" + esc, "url/" + esc
	case in.Type == ioc.IPv4:
		return "IPv4/" + in.Value, "ip/" + in.Value
	case in.Type == ioc.IPv6:
		return "IPv6/" + in.Value, "ip/" + in.Value
	case strings.Count(in.Value, ".") > 1:
		return "hostname/" + in.Value, "hostname/" + in.Value
	}
	return "domain/" + in.Value, "domain/" + in.Value
}

func checkOTX(ctx context.Context, c *Client, key string, in ioc.Indicator) (Finding, error) {
	api, web := otxPath(in)
	code, data, err := c.do(ctx, http.MethodGet, c.base("https://otx.alienvault.com/api/v1")+"/indicators/"+api+"/general",
		map[string]string{"X-OTX-API-KEY": key}, nil)
	if err != nil {
		return Finding{}, err
	}
	if code == 404 {
		return Finding{Verdict: NotFound, Summary: "Bei OTX nicht bekannt"}, nil
	}
	if err := httpError(code); err != nil {
		return Finding{}, err
	}
	var r struct {
		Pulses struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name     string   `json:"name"`
				Tags     []string `json:"tags"`
				Families []struct {
					Name string `json:"display_name"`
				} `json:"malware_families"`
			} `json:"pulses"`
		} `json:"pulse_info"`
		Validation []struct {
			Source  string `json:"source"`
			Message string `json:"message"`
		} `json:"validation"`
	}
	if err := decode(data, &r); err != nil {
		return Finding{}, err
	}
	var tags, families []string
	for _, p := range r.Pulses.Pulses {
		tags = append(tags, p.Tags...)
		for _, fam := range p.Families {
			families = append(families, fam.Name)
		}
	}
	f := Finding{Link: "https://otx.alienvault.com/indicator/" + web, Tags: capList(tags, 6)}
	n := r.Pulses.Count
	f.Summary = fmt.Sprintf("In %d Threat-Pulses erwähnt", n)
	switch {
	case len(r.Validation) > 0:
		f.Verdict = Clean
		f.Summary = "Von OTX als bekannt unbedenklich geführt"
		f.Details = addKV(f.Details, "Grund", r.Validation[0].Message)
	case n >= 5:
		f.Verdict = Suspicious
	case n > 0:
		f.Verdict = Weak
	default:
		f.Verdict = NotFound
		f.Summary = "In keinem Threat-Pulse erwähnt"
	}
	f.Details = addKV(f.Details, "Malware-Familien", strings.Join(capList(families, 5), ", "))
	if len(r.Pulses.Pulses) > 0 {
		f.Details = addKV(f.Details, "Beispiel-Pulse", r.Pulses.Pulses[0].Name)
	}
	return f, nil
}

// --- CIRCL hashlookup ---------------------------------------------------

func circl() *Source {
	return &Source{
		ID: "circl", Name: "CIRCL hashlookup", Group: "circl",
		Types:   []ioc.Type{ioc.MD5, ioc.SHA1, ioc.SHA256},
		Limit:   Limit{PerMinute: 60},
		License: "Öffentlicher Dienst ohne API-Key",
		Signup:  "https://www.circl.lu/services/hashlookup/",
		Check:   checkCIRCL,
	}
}

func checkCIRCL(ctx context.Context, c *Client, _ string, in ioc.Indicator) (Finding, error) {
	code, data, err := c.do(ctx, http.MethodGet, c.base("https://hashlookup.circl.lu")+"/lookup/"+string(in.Type)+"/"+in.Value, nil, nil)
	if err != nil {
		return Finding{}, err
	}
	if code == 404 {
		return Finding{Verdict: NotFound, Summary: "Nicht in der Datenbank bekannter Dateien"}, nil
	}
	if err := httpError(code); err != nil {
		return Finding{}, err
	}
	var r struct {
		FileName string   `json:"FileName"`
		Size     any      `json:"FileSize"`
		Trust    *int     `json:"hashlookup:trust"`
		KnownMal any      `json:"KnownMalicious"`
		Sources  []string `json:"source"`
	}
	if err := decode(data, &r); err != nil {
		return Finding{}, err
	}
	f := Finding{Verdict: Info, Summary: "Datei ist in Referenzdaten bekannter Software erfasst"}
	if r.KnownMal != nil && r.KnownMal != "" {
		f.Verdict = Malicious
		f.Summary = "In CIRCL als bekannt bösartig markiert"
	} else if r.Trust != nil && *r.Trust >= 50 {
		f.Verdict = Clean
		f.Summary = fmt.Sprintf("Als bekannte Datei geführt (Vertrauen %d/100)", *r.Trust)
	}
	f.Details = addKV(f.Details, "Dateiname", r.FileName)
	f.Details = addKV(f.Details, "Quellen", strings.Join(capList(r.Sources, 4), ", "))
	return f, nil
}

// --- Feodo Tracker ------------------------------------------------------

type feodoEntry struct {
	IP       string `json:"ip_address"`
	Port     int    `json:"port"`
	Status   string `json:"status"`
	Malware  string `json:"malware"`
	AS       string `json:"as_name"`
	Country  string `json:"country"`
	LastSeen string `json:"last_online"`
}

type feodoList struct {
	mu      sync.Mutex
	entries map[string]feodoEntry
	fetched time.Time
}

func newFeodo() *Source {
	list := &feodoList{}
	return &Source{
		ID: "feodo", Name: "Feodo Tracker", Group: "abuse.ch",
		Types:   []ioc.Type{ioc.IPv4},
		Limit:   Limit{PerMinute: 120},
		License: "CC0, frei nutzbar und ohne API-Key",
		Signup:  "https://feodotracker.abuse.ch/",
		Check: func(ctx context.Context, c *Client, _ string, in ioc.Indicator) (Finding, error) {
			return list.check(ctx, c, in)
		},
	}
}

func (l *feodoList) load(ctx context.Context, c *Client) (map[string]feodoEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries != nil && time.Since(l.fetched) < time.Hour {
		return l.entries, nil
	}
	code, data, err := c.do(ctx, http.MethodGet, c.base("https://feodotracker.abuse.ch")+"/downloads/ipblocklist.json", nil, nil)
	if err == nil {
		err = httpError(code)
	}
	var list []feodoEntry
	if err == nil {
		err = decode(data, &list)
	}
	if err != nil {
		return nil, fmt.Errorf("Feodo-Liste konnte nicht aktualisiert werden: %w", err)
	}
	l.entries = make(map[string]feodoEntry, len(list))
	for _, e := range list {
		l.entries[e.IP] = e
	}
	l.fetched = time.Now()
	return l.entries, nil
}

var reSafeIP = regexp.MustCompile(`^[0-9.]+$`)

func (l *feodoList) check(ctx context.Context, c *Client, in ioc.Indicator) (Finding, error) {
	entries, err := l.load(ctx, c)
	if err != nil {
		return Finding{}, err
	}
	e, ok := entries[in.Value]
	if !ok {
		return Finding{Verdict: NotFound, Summary: "Nicht auf der Botnet-C2-Blockliste"}, nil
	}
	f := Finding{Verdict: Malicious, Summary: "Botnet-C2-Server: " + firstNonEmpty(e.Malware, "unbekannte Familie")}
	if reSafeIP.MatchString(in.Value) {
		f.Link = "https://feodotracker.abuse.ch/browse/host/" + in.Value + "/"
	}
	f.Details = addKV(f.Details, "Status", e.Status)
	f.Details = addKV(f.Details, "Port", nonZero(e.Port))
	f.Details = addKV(f.Details, "Hoster", e.AS)
	f.Details = addKV(f.Details, "Land", e.Country)
	f.Details = addKV(f.Details, "Zuletzt aktiv", e.LastSeen)
	return f, nil
}
