package ioc

import (
	"strings"
	"testing"
)

func TestRegressionPreserveURLValue(t *testing.T) {
	for _, raw := range []string{"https://example.org/download?token=abc!", "https://example.org/path.", "https://example.org/a(b)", "https://example.org/a;", "https://example.org/a,", "https://example.org/?", "https://example.org/?token=a'"} {
		got, ok := Classify(raw, Options{})
		if !ok || got.Value != raw {
			t.Errorf("input %q became %q", raw, got.Value)
		}
	}
}

// Überlange Labels werden vor der quadratischen Punycode-Kodierung abgelehnt.
func TestOverlongLabelRejectedEarly(t *testing.T) {
	var tok strings.Builder
	for r := rune(0x4E00); r < 0x4E00+1365; r++ {
		tok.WriteRune(r)
	}
	calls := 0
	hostToASCII = func(h string) (string, error) { calls++; return toASCII(h) }
	defer func() { hostToASCII = toASCII }()
	for _, in := range []string{tok.String(), "user@" + tok.String() + ".de", "https://" + tok.String() + ".de/x", strings.Repeat("ü", 64) + ".de"} {
		if _, ok := Classify(in, Options{}); ok {
			t.Fatalf("überlanges Label erkannt: %.20q", in)
		}
	}
	if calls != 0 {
		t.Fatalf("Punycode lief %d-mal für überlange Labels", calls)
	}
	for _, s := range []string{"münchen.de", "bücher.example.com", strings.Repeat("a", 63) + ".com"} {
		if _, ok := Classify(s, Options{AllowDocumentation: true}); !ok {
			t.Fatalf("%q nicht mehr erkannt", s)
		}
	}
	if _, ok := Classify(strings.Repeat("a", 64)+".com", Options{}); ok {
		t.Fatal("Label mit 64 Zeichen erkannt")
	}
}
