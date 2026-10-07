package blocklist

import (
	"strconv"
	"strings"
	"testing"
)

// FuzzValidDomain feeds the domain validator arbitrary input. It asserts
// that the function never panics and that every name it accepts has the
// shape the rules give (see checkDomainShape). The existing positive and
// negative test cases form the seed corpus.
//
// Run with `go test -fuzz=FuzzValidDomain -fuzztime=30s ./internal/blocklist/`.
func FuzzValidDomain(f *testing.F) {
	seeds := []string{
		"example.com", "sub.example.com", "a-b.example.com",
		"_dmarc.example.com", "no-dot", "",
		"has space.com", "slash/path.com", "control\x00char.com",
		strings.Repeat("a", 250) + ".com",
		// CL 95: wildcard lines, empty labels, and hyphen-edged labels.
		"*.example.com", "*.com", "example.com.", "example.com..", "a..com",
		"-ads.example.com", "ads-.example.com", "a.-b.com", "a.b-.com",
		"a.com-", "a.com-.", "-728.90.", "xn--bcher-kva.de", "a--b.example.com",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidDomain(s) {
			if msg := checkDomainShape(s); msg != "" {
				t.Fatalf("ValidDomain(%q) = true, but %s", s, msg)
			}
		}
	})
}

// checkDomainShape returns "" when s has the shape of a name ValidDomain may
// accept, or a reason when it does not: at most 253 characters, an optional
// root dot, then at least two labels, each non-empty, made of letters,
// digits, "-", and "_", and not starting or ending with "-" (CL 95, W3).
func checkDomainShape(s string) string {
	if len(s) > 253 {
		return "it is longer than 253 characters"
	}
	labels := strings.Split(strings.TrimSuffix(s, "."), ".")
	if len(labels) < 2 {
		return "it has fewer than two labels"
	}
	for _, l := range labels {
		if l == "" {
			return "it has an empty label"
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "label " + strconv.Quote(l) + " starts or ends with a hyphen"
		}
		for _, r := range l {
			ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_'
			if !ok {
				return "label " + strconv.Quote(l) + " has the character " + strconv.QuoteRune(r)
			}
		}
	}
	return ""
}

// FuzzParseHostsFormat feeds the parser arbitrary text and asserts every
// emitted domain itself passes ValidDomain. This catches a class of
// regression where a parser bypass admits malformed tokens. It also checks
// the CL 95 skipped count: each line is read on its own, so the whole input
// gives the sum of its lines, and a line counts as skipped only when it is
// not blank, not a "#" comment, and gives no domain.
func FuzzParseHostsFormat(f *testing.F) {
	seeds := []string{
		"0.0.0.0 ads.example.com\n",
		"127.0.0.1 tracker.example.net\n",
		"# comment\nads.example.com\n",
		"plain.example.com\n",
		"",
		"0.0.0.0 localhost\n", // dropped self-entry
		"\t\n  \n",            // whitespace-only
		// CL 95: wildcard lines, hyphen-edged labels, and an Adblock list.
		"*.example.com\n",
		"  *.ads.example.com  \r\n",
		"*.com\n*.\n*\n**.example.com\n*.*.example.com\n",
		"0.0.0.0 *.example.com\n",
		"-ads.example.com\nads-.example.com\n0.0.0.0 a.-b.com\n:: a.com-\n",
		"[Adblock Plus 2.0]\n! comment\n||ads.com^\n##.banner\n-728.90.\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		domains, skipped, err := parseHostsFormat(strings.NewReader(input))
		if err != nil {
			return // EOF / scanner errors are acceptable here
		}
		for _, d := range domains {
			if !ValidDomain(d) {
				t.Fatalf("parseHostsFormat emitted invalid domain %q from input %q",
					d, input)
			}
		}
		var lineDomains, lineSkipped int
		for _, line := range strings.Split(input, "\n") {
			d, s, err := parseHostsFormat(strings.NewReader(line))
			if err != nil {
				return
			}
			trimmed := strings.TrimSpace(line)
			quiet := trimmed == "" || strings.HasPrefix(trimmed, "#")
			wantSkipped := 0
			if !quiet && len(d) == 0 {
				wantSkipped = 1
			}
			if s != wantSkipped {
				t.Fatalf("line %q: skipped = %d, want %d", line, s, wantSkipped)
			}
			if quiet && len(d) != 0 {
				t.Fatalf("blank or comment line %q gave domains %v", line, d)
			}
			lineDomains += len(d)
			lineSkipped += s
		}
		if len(domains) != lineDomains || skipped != lineSkipped {
			t.Fatalf("input %q: %d domains, %d skipped; its lines one by one give %d and %d",
				input, len(domains), skipped, lineDomains, lineSkipped)
		}
	})
}

// FuzzCacheFilename asserts every produced filename is platform-safe:
// no path separators, no characters that would interfere with rename
// on NTFS, always the blocklist_ prefix.
func FuzzCacheFilename(f *testing.F) {
	seeds := []string{
		"https://example.com/list.txt",
		"http://127.0.0.1:8080/path?x=1",
		"https://a.b.c/d.txt",
		"",
		"   ",
		"file://with/lots/of/slashes",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, url string) {
		name := cacheFilename(url)
		if !strings.HasPrefix(name, "blocklist_") {
			t.Errorf("cacheFilename(%q) = %q, want blocklist_ prefix", url, name)
		}
		// No characters that can be parsed as a path separator on any
		// of our target OSes. We replace ':' so NTFS rename works (R9
		// regression for the embedded-port URL case).
		for _, bad := range []string{"/", "\\", ":"} {
			if strings.Contains(name, bad) {
				t.Errorf("cacheFilename(%q) = %q contains unsafe char %q",
					url, name, bad)
			}
		}
	})
}
