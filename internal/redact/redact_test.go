package redact

import (
	"net/url"
	"strings"
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

func TestURL_ParsableURL(t *testing.T) {
	// R1: in a URL that url.Parse accepts, the user info becomes "redacted"
	// and a query string becomes "redacted". The host, port, and path stay,
	// so an operator can still tell which list or upstream a line is about.
	cases := []struct {
		in, want string
		secrets  []string
	}{
		{"https://alice:s3cret@lists.example/hosts.txt", "https://redacted@lists.example/hosts.txt", []string{"alice", "s3cret"}},
		{"https://tokenuser@lists.example:8443/a", "https://redacted@lists.example:8443/a", []string{"tokenuser"}},
		{"https://alice:@lists.example/a", "https://redacted@lists.example/a", []string{"alice"}},
		{"https://lists.example/hosts.txt?key=abc123&x=1", "https://lists.example/hosts.txt?redacted", []string{"abc123", "key="}},
		{"https://9.9.9.9/dns-query?dns=AAAB", "https://9.9.9.9/dns-query?redacted", []string{"AAAB"}},
		{"https://bob:pw9@lists.example/l?token=t0k", "https://redacted@lists.example/l?redacted", []string{"bob", "pw9", "t0k"}},
		{"http://bob:pw9@[2001:db8::1]:8080/l?token=t0k", "http://redacted@[2001:db8::1]:8080/l?redacted", []string{"bob", "pw9", "t0k"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if _, err := url.Parse(tc.in); err != nil {
				t.Fatalf("url.Parse(%q) = %v; this case must be parsable", tc.in, err)
			}
			got := URL(tc.in)
			if got != tc.want {
				t.Errorf("URL(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for _, s := range tc.secrets {
				if strings.Contains(got, s) {
					t.Errorf("URL(%q) = %q still holds %q", tc.in, got, s)
				}
			}
		})
	}
}

func TestURL_NothingToHideIsUnchanged(t *testing.T) {
	// R1: a URL with neither user info nor a query string is returned exactly
	// as given, even where url.URL.String would write it differently. A string
	// without "://" (a plain host:port upstream) is unchanged too.
	for _, in := range []string{
		"https://9.9.9.9/dns-query",
		"https://lists.example/hosts.txt",
		"HTTPS://Lists.Example/Hosts.txt",
		"https://lists.example/a%2Fb",
		"https://lists.example/hosts.txt#frag",
		"https://lists.example/l?",
		"9.9.9.9:53",
		"[2001:db8::1]:53",
		"lists.example",
		"",
	} {
		if got := URL(in); got != in {
			t.Errorf("URL(%q) = %q, want it unchanged", in, got)
		}
	}
}
