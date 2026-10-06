package redact

import (
	"net/url"
	"testing"
)

func TestURL_UnparsableURL(t *testing.T) {
	// For a URL-shaped entry that url.Parse rejects, everything before the
	// last "@" in the authority becomes "redacted" and the rest is kept. An
	// unparsable entry with no "@" in the authority, or with no "://", is
	// returned unchanged.
	cases := []struct{ in, want string }{
		{"https://user:pass@1.1.1.1:bad/dns-query", "https://redacted@1.1.1.1:bad/dns-query"},
		{"https://user:pass@[::1/x", "https://redacted@[::1/x"},
		{"https://us er:pass@1.1.1.1/x", "https://redacted@1.1.1.1/x"},
		{"https://a@b:pass@[::1", "https://redacted@[::1"},
		{"https://[::1", "https://[::1"},
		{"https://[::1/a@b", "https://[::1/a@b"},
		{"1.1.1.1:", "1.1.1.1:"}, // no "://": logged unchanged
		{"a@b:c:53", "a@b:c:53"}, // no "://", "@" is not in an authority
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if _, err := url.Parse(tc.in); err == nil {
				t.Fatalf("url.Parse(%q) succeeded; this case must be unparsable", tc.in)
			}
			if got := URL(tc.in); got != tc.want {
				t.Errorf("URL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
