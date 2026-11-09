package ioc

import (
	"reflect"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		in       string
		wantType Type
		want     string
		internal bool
	}{
		{"44D88612FEA8A8F36DE82E1278ABB02F", MD5, "44d88612fea8a8f36de82e1278abb02f", false},
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", false},
		{"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", SHA256, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", false},
		{"8.8.8.8", IPv4, "8.8.8.8", false},
		{"8[.]8[.]8[.]8", IPv4, "8.8.8.8", false},
		{"8.8.8.8:443", IPv4, "8.8.8.8", false},
		{"192.168.0.1", IPv4, "192.168.0.1", true},
		{"100.64.1.1", IPv4, "100.64.1.1", true},
		{"203.0.113.5", IPv4, "203.0.113.5", true},
		{"2606:4700:4700::1111", IPv6, "2606:4700:4700::1111", false},
		{"fe80::1", IPv6, "fe80::1", true},
		{"::ffff:8.8.4.4", IPv4, "8.8.4.4", false},
		{"Evil.COM.", Domain, "evil.com", false},
		{"evil[.]com", Domain, "evil.com", false},
		{"evil(dot)com", Domain, "evil.com", false},
		{"server.corp", Domain, "server.corp", true},
		{"bücher.de", Domain, "xn--bcher-kva.de", false},
		{"müller.de", Domain, "xn--mller-kva.de", false},
		{"hxxps://evil[.]com/a?b=1", URL, "https://evil.com/a?b=1", false},
		{"hXXp://evil[.]com/", URL, "http://evil.com/", false},
		{"hxxp[://]evil[.]com/x", URL, "http://evil.com/x", false},
		{"https://user:geheim@evil.com/x#frag", URL, "https://evil.com/x", false},
		{"http://10.0.0.1/admin", URL, "http://10.0.0.1/admin", true},
		{"http://[2606:4700::1]:8080/x", URL, "http://[2606:4700::1]:8080/x", false},
		{"evil.com/pfad", URL, "http://evil.com/pfad", false},
		{"<https://evil.com/x>,", URL, "https://evil.com/x", false},
		{"admin@evil.com", Domain, "evil.com", false},
	}
	for _, c := range cases {
		got, ok := Classify(c.in, Options{})
		if !ok {
			t.Errorf("%q: nicht erkannt", c.in)
			continue
		}
		if got.Type != c.wantType || got.Value != c.want || got.Internal != c.internal {
			t.Errorf("%q: got %s %q internal=%v, want %s %q internal=%v", c.in, got.Type, got.Value, got.Internal, c.wantType, c.want, c.internal)
		}
	}
}

func TestClassifyRejects(t *testing.T) {
	for _, in := range []string{"hallo", "setup.exe", "report.pdf", "10.0.0.0/8", "javascript:alert(1)", "file:///etc/passwd", "C:\\Windows\\cmd.exe", "abc123", "ftp://", "usr/bin/env"} {
		if got, ok := Classify(in, Options{}); ok {
			t.Errorf("%q sollte abgelehnt werden, wurde aber %+v", in, got)
		}
	}
}

func TestInternalDomainsConfigured(t *testing.T) {
	opt := Options{InternalDomains: []string{"firma.de"}}
	for in, want := range map[string]bool{"firma.de": true, "intranet.firma.de": true, "notfirma.de": false} {
		got, ok := Classify(in, opt)
		if !ok || got.Internal != want {
			t.Errorf("%s: internal=%v, want %v", in, got.Internal, want)
		}
	}
	u, _ := Classify("https://vpn.firma.de/login", opt)
	if !u.Internal {
		t.Error("URL auf eigener Domain muss intern sein")
	}
}

func TestAllowDocumentation(t *testing.T) {
	opt := Options{AllowDocumentation: true}
	if ip, _ := Classify("203.0.113.5", opt); ip.Internal {
		t.Error("Doku-Netz soll im Demo-Modus erlaubt sein")
	}
	if ip, _ := Classify("10.0.0.1", opt); !ip.Internal {
		t.Error("RFC1918 bleibt intern")
	}
	if d, _ := Classify("phish.example", opt); d.Internal {
		t.Error(".example soll im Demo-Modus erlaubt sein")
	}
}

func TestParseDedupesAndLimits(t *testing.T) {
	res := Parse("8.8.8.8, 8[.]8[.]8[.]8; evil.com\nquatsch 1.1.1.1", Options{MaxItems: 2})
	if len(res.Indicators) != 2 || res.Truncated != 1 {
		t.Fatalf("got %+v", res)
	}
	if !reflect.DeepEqual(res.Unknown, []string{"quatsch"}) {
		t.Fatalf("unknown = %v", res.Unknown)
	}
}

func TestSensitiveURLNote(t *testing.T) {
	got, _ := Classify("https://evil.com/reset?token=abc", Options{})
	if len(got.Notes) == 0 {
		t.Fatal("Hinweis auf sensible Parameter fehlt")
	}
}

func TestDefang(t *testing.T) {
	got, _ := Classify("https://evil.com/a.b", Options{})
	if got.Defanged != "hxxps://evil[.]com/a[.]b" {
		t.Fatal(got.Defanged)
	}
}

func TestInternalDomainVariants(t *testing.T) {
	cases := []struct{ own, in string }{
		{"müller.de", "müller.de"},
		{"müller.de", "https://vpn.müller.de/login"},
		{"*.firma.de", "intranet.firma.de"},
		{"*.firma.de", "firma.de"},
		{" FIRMA.de. ", "a.firma.de"},
	}
	for _, c := range cases {
		got, ok := Classify(c.in, Options{InternalDomains: []string{c.own}})
		if !ok || !got.Internal {
			t.Errorf("own=%q in=%q: würde an Dritte gesendet (%+v)", c.own, c.in, got)
		}
	}
}

func TestSpecialRangesInternal(t *testing.T) {
	for _, in := range []string{"0.1.2.3", "169.254.169.254", "fd00::1", "http://[::1]/x", "http://169.254.169.254/latest/meta-data"} {
		got, ok := Classify(in, Options{})
		if !ok || !got.Internal {
			t.Errorf("%s: %+v", in, got)
		}
	}
}

func TestDefangHasNoBackticks(t *testing.T) {
	got, _ := Classify("https://evil.com/?a=`x`", Options{})
	for _, r := range got.Defanged {
		if r == '`' {
			t.Fatal(got.Defanged)
		}
	}
}
