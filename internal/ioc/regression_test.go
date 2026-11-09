package ioc

import "testing"

func TestRegressionPreserveURLValue(t *testing.T) {
	for _, raw := range []string{"https://example.org/download?token=abc!", "https://example.org/path.", "https://example.org/a(b)", "https://example.org/a;", "https://example.org/a,", "https://example.org/?", "https://example.org/?token=a'"} {
		got, ok := Classify(raw, Options{})
		if !ok || got.Value != raw {
			t.Errorf("input %q became %q", raw, got.Value)
		}
	}
}
