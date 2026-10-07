package blocklist

import (
	"strings"
	"testing"
)

// parseOne runs parseHostsFormat on input and fails the test on a read error.
func parseOne(t *testing.T, input string) (domains []string, skipped int) {
	t.Helper()
	domains, skipped, err := parseHostsFormat(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseHostsFormat(%q): %v", input, err)
	}
	return domains, skipped
}

func TestParseHostsFormat_WildcardLine(t *testing.T) {
	// CL 95 (W1): a "*.example.com" line, one field after the spaces are
	// trimmed, adds example.com. It is a domain read, not a skipped line.
	cases := map[string]string{
		"wildcard":            "*.example.com\n",
		"no final newline":    "*.example.com",
		"leading spaces":      "   *.example.com\n",
		"trailing spaces":     "*.example.com   \n",
		"tabs":                "\t*.example.com\t\n",
		"CRLF line ending":    "*.example.com\r\n",
		"deeper wildcard":     "*.ads.example.com\n",
		"hyphen inside label": "*.a-b.example.com\n",
	}
	want := map[string]string{
		"deeper wildcard":     "ads.example.com",
		"hyphen inside label": "a-b.example.com",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			wantDomain := "example.com"
			if w, ok := want[name]; ok {
				wantDomain = w
			}
			got, skipped := parseOne(t, input)
			if !equalSlices(got, []string{wantDomain}) {
				t.Errorf("parseHostsFormat(%q) = %v, want [%s]", input, got, wantDomain)
			}
			if skipped != 0 {
				t.Errorf("parseHostsFormat(%q) skipped = %d, want 0", input, skipped)
			}
		})
	}
}

func TestParseHostsFormat_InvalidWildcardLinesDropped(t *testing.T) {
	// CL 95 (W1): the part after "*." must pass ValidDomain, or the line is
	// dropped. "*.com" would block a whole TLD. A wildcard in a hosts line is
	// not supported. Each dropped line is a skipped line (W2).
	for _, line := range []string{
		"*.",
		"*",
		"*.com",
		"*.com.",
		"*.*.example.com",
		"*example.com",
		"**.example.com",
		".example.com",
		"*..example.com",
		"*.-ads.example.com",
		"*.ads-.example.com",
		"0.0.0.0 *.example.com",
		"127.0.0.1 *.example.com",
		":: *.example.com",
	} {
		t.Run(line, func(t *testing.T) {
			got, skipped := parseOne(t, line+"\n")
			if len(got) != 0 {
				t.Errorf("parseHostsFormat(%q) = %v, want no domain", line, got)
			}
			if skipped != 1 {
				t.Errorf("parseHostsFormat(%q) skipped = %d, want 1", line, skipped)
			}
		})
	}
}

func TestParseHostsFormat_PlainHostsCommentsUnchanged(t *testing.T) {
	// CL 95 (W1): plain lines, the three sinkhole hosts forms, comments, and
	// blank lines keep their behavior. Comments and blank lines are not
	// skipped lines (W2).
	input := "# a comment\n" +
		"\n" +
		"   \n" +
		"  # an indented comment\n" +
		"plain.example.com\n" +
		"0.0.0.0 zero.example.com\n" +
		"127.0.0.1 loop.example.com\n" +
		":: six.example.com\n"
	got, skipped := parseOne(t, input)
	want := []string{"plain.example.com", "zero.example.com", "loop.example.com", "six.example.com"}
	if !equalSlices(got, want) {
		t.Errorf("parseHostsFormat = %v, want %v", got, want)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0 (comments and blank lines do not count)", skipped)
	}
}

// oisdWildcardBody is shaped like oisd's "domainswild" list: a block of "#"
// header lines, then one "*." line per entry.
const oisdWildcardBody = `# Title: oisd big
# Description: Block. Don't break.
# Syntax: Wildcard domains
# Version: 202610070102
# Last modified: 2026-10-07T01:02:03+0000
# Expires: 1 hours
# License: https://github.com/sjhgvr/oisd/blob/main/LICENSE
# Maintainer: Stephan van Ruth
# Homepage: https://oisd.nl
# Contact: contact@oisd.nl
# Entries: 6

*.0-0-0-checkmy-account.com
*.000webhostapp-ads.com
*.ads.example.co.uk
*.doubleclick.net
*.xn--80ak6aa92e.com
*._tracker.example.org
`

func TestParseHostsFormat_OisdWildcardList(t *testing.T) {
	// CL 95 (W1): a real oisd "domainswild" body loads every entry, with LF
	// or CRLF line endings, and skips nothing.
	want := []string{
		"0-0-0-checkmy-account.com",
		"000webhostapp-ads.com",
		"ads.example.co.uk",
		"doubleclick.net",
		"xn--80ak6aa92e.com",
		"_tracker.example.org",
	}
	for name, body := range map[string]string{
		"LF":   oisdWildcardBody,
		"CRLF": strings.ReplaceAll(oisdWildcardBody, "\n", "\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			got, skipped := parseOne(t, body)
			if !equalSlices(got, want) {
				t.Errorf("parseHostsFormat = %v, want %v", got, want)
			}
			if skipped != 0 {
				t.Errorf("skipped = %d, want 0", skipped)
			}
		})
	}
}

func TestParseHostsFormat_MixedFormats(t *testing.T) {
	// CL 95 (W1): one list that mixes plain, hosts, and wildcard lines loads
	// every valid entry, in order; the invalid lines are skipped.
	input := "# mixed list\n" +
		"0.0.0.0 hosts.example.com\n" +
		"*.wild.example.com\n" +
		"plain.example.com\n" +
		"*.com\n" + // skipped: would block a TLD
		"127.0.0.1 loop.example.com\n" +
		"0.0.0.0 *.hostwild.example.com\n" + // skipped: wildcard in a hosts line
		":: six.example.com\n" +
		"  *.spaced.example.com  \n" +
		"-junk.example.com\n" // skipped: W3
	got, skipped := parseOne(t, input)
	want := []string{
		"hosts.example.com",
		"wild.example.com",
		"plain.example.com",
		"loop.example.com",
		"six.example.com",
		"spaced.example.com",
	}
	if !equalSlices(got, want) {
		t.Errorf("parseHostsFormat = %v, want %v", got, want)
	}
	if skipped != 3 {
		t.Errorf("skipped = %d, want 3", skipped)
	}
}

func TestUpdate_WildcardLineBlocksDomainAndSubdomains(t *testing.T) {
	// CL 95 (W1), oisd's definition: "*.example.com" blocks example.com and
	// its subdomains, not notexample.com and not example.com.evil.
	srv, _ := listServer(t, "# wildcard list\n*.example.com\n")
	store := NewStore()
	if err := Update(store, []string{srv.URL}, t.TempDir(), DownloadFirst); err != nil {
		t.Fatalf("Update: %v", err)
	}
	for _, tc := range []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"a.example.com", true},
		{"a.b.example.com", true},
		{"notexample.com", false},
		{"example.com.evil", false},
		{"com", false},
		{"other.com", false},
	} {
		if got := store.IsBlocked(tc.domain); got != tc.want {
			t.Errorf("IsBlocked(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
	if src := sourceByURL(store)[srv.URL]; src.Count != 1 {
		t.Errorf("source Count = %d, want 1", src.Count)
	}
}

func TestValidDomain_LabelRules(t *testing.T) {
	// CL 95 (W3): an empty label is invalid, and so is a label that starts or
	// ends with "-", in any position. Hyphens inside a label, underscore
	// labels, and one trailing root dot stay valid.
	tests := []struct {
		in   string
		want bool
	}{
		// Empty labels.
		{"a..com", false},
		{"example.com..", false},
		{"a.b..c.com", false},
		{"..example.com", false},
		{"example..", false},
		// Hyphen at a label edge.
		{"-ads.example.com", false},
		{"ads-.example.com", false},
		{"a.-b.com", false},
		{"a.b-.com", false},
		{"a.com-", false},
		{"a.com-.", false},
		{"a.-com", false},
		{"a.-", false},
		{"-.example.com", false},
		{"a.-.com", false},
		{"xn--.com", false},
		{"-728.90.", false}, // an EasyList URL rule
		{"-ADS.EXAMPLE.COM", false},
		// Still valid.
		{"a-b.example.com", true},
		{"a--b.example.com", true},
		{"xn--bcher-kva.de", true},
		{"_dmarc.example.com", true},
		{"example.com.", true},
		{"a.b", true},
		{"1-2.example.com", true},
		{"ex-ample.co-m", true},
		{"A-B.Example.COM", true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := ValidDomain(tc.in); got != tc.want {
				t.Errorf("ValidDomain(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseHostsFormat_DropsBadLabels(t *testing.T) {
	// CL 95 (W3): a blocklist line whose domain has an empty label or a
	// hyphen at a label edge is dropped, in every line format.
	bad := []string{
		"-ads.example.com",
		"ads-.example.com",
		"a..com",
		"example.com..",
		"-728.90.",
		"0.0.0.0 a.-b.com",
		"127.0.0.1 a.b-.com",
		":: a.com-",
		"0.0.0.0 a.com-.",
		"*.-ads.example.com",
	}
	good := []string{
		"a-b.example.com",
		"0.0.0.0 xn--bcher-kva.de",
		"127.0.0.1 _dmarc.example.com",
		"example.com.",
	}
	input := strings.Join(append(append([]string{}, bad...), good...), "\n") + "\n"
	got, skipped := parseOne(t, input)
	want := []string{"a-b.example.com", "xn--bcher-kva.de", "_dmarc.example.com", "example.com."}
	if !equalSlices(got, want) {
		t.Errorf("parseHostsFormat = %v, want %v", got, want)
	}
	if skipped != len(bad) {
		t.Errorf("skipped = %d, want %d", skipped, len(bad))
	}
}
