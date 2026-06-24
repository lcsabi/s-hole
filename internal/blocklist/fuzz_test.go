package blocklist

import (
	"strings"
	"testing"
)

// FuzzValidDomain feeds the domain validator arbitrary input and asserts
// the function never panics. The existing positive/negative test cases
// in store_test.go form the seed corpus.
//
// Run with `go test -fuzz=FuzzValidDomain -fuzztime=30s ./internal/blocklist/`.
func FuzzValidDomain(f *testing.F) {
	seeds := []string{
		"example.com", "sub.example.com", "a-b.example.com",
		"_dmarc.example.com", "no-dot", "",
		"has space.com", "slash/path.com", "control\x00char.com",
		strings.Repeat("a", 250) + ".com",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// ValidDomain is a pure predicate: any input must produce a bool
		// without panicking. A regression that breaks that invariant
		// would be a corruption of the rune-iteration logic.
		_ = ValidDomain(s)
	})
}

// FuzzParseHostsFormat feeds the parser arbitrary text and asserts every
// emitted domain itself passes ValidDomain. This catches a class of
// regression where a parser bypass admits malformed tokens.
func FuzzParseHostsFormat(f *testing.F) {
	seeds := []string{
		"0.0.0.0 ads.example.com\n",
		"127.0.0.1 tracker.example.net\n",
		"# comment\nads.example.com\n",
		"plain.example.com\n",
		"",
		"0.0.0.0 localhost\n", // dropped self-entry
		"\t\n  \n",            // whitespace-only
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		domains, err := parseHostsFormat(strings.NewReader(input))
		if err != nil {
			return // EOF / scanner errors are acceptable here
		}
		for _, d := range domains {
			if !ValidDomain(d) {
				t.Fatalf("parseHostsFormat emitted invalid domain %q from input %q",
					d, input)
			}
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
