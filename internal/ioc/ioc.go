// Package ioc erkennt und normalisiert Indikatoren (URLs, Hashes, IPs, Domains).
package ioc

import (
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

type Type string

const (
	IPv4   Type = "ipv4"
	IPv6   Type = "ipv6"
	Domain Type = "domain"
	URL    Type = "url"
	MD5    Type = "md5"
	SHA1   Type = "sha1"
	SHA256 Type = "sha256"
)

// IsHash meldet, ob der Typ ein Datei-Hash ist.
func (t Type) IsHash() bool { return t == MD5 || t == SHA1 || t == SHA256 }

// IsIP meldet, ob der Typ eine IP-Adresse ist.
func (t Type) IsIP() bool { return t == IPv4 || t == IPv6 }

// Indicator ist ein normalisierter Prüfwert.
type Indicator struct {
	Type     Type     `json:"type"`
	Value    string   `json:"value"`
	Defanged string   `json:"defanged"`
	Host     string   `json:"host,omitempty"`
	Internal bool     `json:"internal"`
	Notes    []string `json:"notes,omitempty"`
}

// Options steuert die Erkennung.
type Options struct {
	// MaxItems begrenzt die Anzahl der Indikatoren (0 = unbegrenzt).
	MaxItems int
	// InternalDomains sind eigene Domains, die nie an Dritte gesendet werden.
	InternalDomains []string
	// AllowDocumentation lässt Dokumentationsnetze und .example zu (Demo-Modus).
	AllowDocumentation bool
}

// ParseResult ist das Ergebnis von Parse.
type ParseResult struct {
	Indicators []Indicator `json:"indicators"`
	Unknown    []string    `json:"unknown"`
	Truncated  int         `json:"truncated"`
}

var (
	reMD5    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	reSHA1   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	reSHA256 = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	reDomain = regexp.MustCompile(`^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$`)
	reEmail  = regexp.MustCompile(`^[^@\s/]+@([^@\s/]+)$`)
	reHxxp   = regexp.MustCompile(`(?i)^h[x*t]{2}p(s?)://`)

	refanger = strings.NewReplacer(
		"[://]", "://", "[:]//", "://", "[.]", ".", "(.)", ".", "{.}", ".",
		"[dot]", ".", "(dot)", ".", "[DOT]", ".", "(DOT)", ".",
		"[@]", "@", "(@)", "@", "[at]", "@", "(at)", "@", "[:]", ":",
	)

	// Keine echten TLDs, aber typische Dateiendungen.
	fileExtensions = map[string]bool{
		"exe": true, "dll": true, "pdf": true, "doc": true, "docx": true, "docm": true,
		"xls": true, "xlsx": true, "xlsm": true, "ppt": true, "pptx": true, "txt": true,
		"png": true, "jpg": true, "jpeg": true, "gif": true, "bat": true, "cmd": true,
		"ps1": true, "vbs": true, "msi": true, "tmp": true, "log": true, "csv": true,
		"json": true, "xml": true, "html": true, "htm": true, "iso": true, "lnk": true,
		"rar": true, "gz": true, "sys": true, "ini": true,
	}

	internalTLDs = map[string]bool{
		"local": true, "lan": true, "internal": true, "intranet": true, "corp": true,
		"home": true, "localdomain": true, "localhost": true, "invalid": true,
		"test": true, "example": true, "arpa": true,
	}

	sensitiveParams = []string{"token", "pass", "pwd", "secret", "session", "sid", "auth", "key", "email", "mail", "code"}

	specialNets = mustPrefixes("0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4")
	docNets     = mustPrefixes("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// Parse zerlegt Freitext in eindeutige Indikatoren.
func Parse(input string, opt Options) ParseResult {
	res := ParseResult{Indicators: []Indicator{}, Unknown: []string{}}
	seen := map[string]bool{}
	seenUnknown := map[string]bool{}
	for _, tok := range tokenize(input) {
		ind, ok := Classify(tok, opt)
		if !ok {
			if !seenUnknown[tok] && len(res.Unknown) < 50 {
				seenUnknown[tok] = true
				res.Unknown = append(res.Unknown, truncate(tok, 120))
			}
			continue
		}
		key := string(ind.Type) + "|" + ind.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		if opt.MaxItems > 0 && len(res.Indicators) >= opt.MaxItems {
			res.Truncated++
			continue
		}
		res.Indicators = append(res.Indicators, ind)
	}
	return res
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func tokenize(input string) []string {
	var out []string
	for _, field := range strings.Fields(input) {
		if strings.Contains(field, "://") || strings.Contains(strings.ToLower(field), "hxxp") {
			out = append(out, field)
			continue
		}
		for _, part := range strings.FieldsFunc(field, func(r rune) bool { return r == ',' || r == ';' || r == '|' }) {
			out = append(out, part)
		}
	}
	return out
}

func trimDecor(s string) string {
	s = strings.TrimLeft(s, "<(\"'`{")
	s = strings.TrimRight(s, ">)\"'`},;!?")
	for strings.HasSuffix(s, ".") && !strings.HasSuffix(s, "..") {
		s = strings.TrimSuffix(s, ".")
	}
	return s
}

// Refang macht entschärfte Schreibweisen wieder maschinenlesbar.
func Refang(s string) string {
	s = strings.TrimSpace(s)
	return reHxxp.ReplaceAllString(refanger.Replace(s), "http$1://")
}

// Classify erkennt einen einzelnen Wert.
func Classify(raw string, opt Options) (Indicator, bool) {
	s := trimDecor(Refang(trimDecor(raw)))
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") { // z. B. [1.2.3.4]
		s = s[1 : len(s)-1]
	}
	if s == "" || len(s) > 4096 {
		return Indicator{}, false
	}
	switch {
	case reSHA256.MatchString(s):
		return hashIndicator(SHA256, s), true
	case reSHA1.MatchString(s):
		return hashIndicator(SHA1, s), true
	case reMD5.MatchString(s):
		return hashIndicator(MD5, s), true
	}
	if addr, err := netip.ParseAddr(s); err == nil && addr.Zone() == "" {
		return ipIndicator(addr, opt, nil), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ipIndicator(ap.Addr(), opt, []string{"Port entfernt"}), true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return Indicator{}, false // Netzbereiche werden nicht abgefragt
	}
	if strings.Contains(s, "://") {
		return urlIndicator(s, opt)
	}
	if m := reEmail.FindStringSubmatch(s); m != nil {
		host, ok := normHost(m[1])
		if !ok {
			return Indicator{}, false
		}
		return domainIndicator(host, opt, []string{"Domain aus E-Mail-Adresse, die Adresse selbst wird nicht übertragen"}), true
	}
	if strings.ContainsAny(s, "/?") {
		return urlIndicator("http://"+s, opt)
	}
	if host, ok := normHost(s); ok {
		return domainIndicator(host, opt, nil), true
	}
	return Indicator{}, false
}

func hashIndicator(t Type, s string) Indicator {
	v := strings.ToLower(s)
	return Indicator{Type: t, Value: v, Defanged: v}
}

func ipIndicator(addr netip.Addr, opt Options, notes []string) Indicator {
	addr = addr.Unmap()
	t := IPv4
	if addr.Is6() {
		t = IPv6
	}
	v := addr.String()
	return Indicator{Type: t, Value: v, Defanged: Defang(t, v), Internal: isInternalAddr(addr, opt), Notes: notes}
}

func domainIndicator(host string, opt Options, notes []string) Indicator {
	return Indicator{Type: Domain, Value: host, Host: host, Defanged: Defang(Domain, host), Internal: isInternalDomain(host, opt), Notes: notes}
}

func urlIndicator(s string, opt Options) (Indicator, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return Indicator{}, false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "ftp" {
		return Indicator{}, false
	}
	var notes []string
	if u.User != nil {
		u.User = nil
		notes = append(notes, "Zugangsdaten aus der URL entfernt")
	}
	u.Fragment = ""
	internal := false
	hostname := u.Hostname()
	host := hostname
	if addr, err := netip.ParseAddr(hostname); err == nil {
		addr = addr.Unmap()
		host = addr.String()
		internal = isInternalAddr(addr, opt)
	} else {
		h, ok := normHost(hostname)
		if !ok {
			return Indicator{}, false
		}
		host = h
		internal = isInternalDomain(h, opt)
	}
	hostport := host
	if strings.Contains(host, ":") {
		hostport = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		hostport += ":" + p
	}
	u.Host = hostport
	for name := range u.Query() {
		lower := strings.ToLower(name)
		if containsAny(lower, sensitiveParams) {
			notes = append(notes, "URL enthält evtl. sensible Parameter und wird trotzdem an die Dienste übertragen")
			break
		}
	}
	v := u.String()
	return Indicator{Type: URL, Value: v, Host: host, Defanged: Defang(URL, v), Internal: internal, Notes: notes}, true
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func normHost(host string) (string, bool) {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	ascii, err := toASCII(h)
	if err != nil || len(ascii) > 253 || !reDomain.MatchString(ascii) {
		return "", false
	}
	labels := strings.Split(ascii, ".")
	if fileExtensions[labels[len(labels)-1]] {
		return "", false
	}
	return ascii, true
}

func isInternalAddr(a netip.Addr, opt Options) bool {
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range specialNets {
		if p.Contains(a) {
			return true
		}
	}
	if !opt.AllowDocumentation {
		for _, p := range docNets {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

func isInternalDomain(d string, opt Options) bool {
	tld := d[strings.LastIndexByte(d, '.')+1:]
	if internalTLDs[tld] && !(opt.AllowDocumentation && tld == "example") {
		return true
	}
	for _, own := range opt.InternalDomains {
		own = normalizeOwnDomain(own)
		if own != "" && (d == own || strings.HasSuffix(d, "."+own)) {
			return true
		}
	}
	return false
}

// normalizeOwnDomain nimmt auch *.firma.de, Umlaute und ganze URLs an. Ein
// Eintrag, der still nicht greift, würde interne Namen an Dritte senden.
func normalizeOwnDomain(own string) string {
	own = strings.ToLower(strings.TrimSpace(own))
	if strings.Contains(own, "://") {
		if u, err := url.Parse(own); err == nil {
			own = u.Hostname()
		}
	}
	own = strings.Trim(strings.TrimPrefix(own, "*."), ".")
	if ascii, err := toASCII(own); err == nil {
		return ascii
	}
	return own
}

// Defang entschärft einen Wert für die sichere Anzeige.
func Defang(t Type, v string) string {
	switch t {
	case IPv4, Domain:
		return strings.ReplaceAll(v, ".", "[.]")
	case IPv6:
		return strings.ReplaceAll(v, ":", "[:]")
	case URL:
		out := strings.ReplaceAll(strings.ReplaceAll(v, ".", "[.]"), "`", "%60")
		out = strings.Replace(out, "https://", "hxxps://", 1)
		return strings.Replace(out, "http://", "hxxp://", 1)
	}
	return v
}
