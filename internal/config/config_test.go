package config

import (
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestFilterAllowlist(t *testing.T) {
	// Allowlist entries are suffix-matched (CL 30): a bare label like a TLD
	// would exempt its whole subtree. filterAllowlist drops invalid entries
	// (Load reports them as problems) instead of aborting startup, and a dropped entry
	// fails safe: the domain stays blockable.
	// "com." is the b/040 case: a bare TLD with a trailing root dot must be
	// dropped, or normalize would store bare "com" and exempt the whole TLD.
	in := []string{"safe.doubleclick.net", "com", "com.", "example.com", "bad host"}
	valid, dropped := filterAllowlist(in)

	wantValid := []string{"safe.doubleclick.net", "example.com"}
	if !reflect.DeepEqual(valid, wantValid) {
		t.Errorf("valid = %v, want %v", valid, wantValid)
	}
	wantDropped := []string{"com", "com.", "bad host"}
	if !reflect.DeepEqual(dropped, wantDropped) {
		t.Errorf("dropped = %v, want %v", dropped, wantDropped)
	}
}

func TestFilterAllowlist_Empty(t *testing.T) {
	valid, dropped := filterAllowlist(nil)
	if valid != nil || dropped != nil {
		t.Errorf("filterAllowlist(nil) = (%v, %v), want (nil, nil)", valid, dropped)
	}
}

func TestLoad_DropsInvalidAllowlistEntries(t *testing.T) {
	path := writeTemp(t, "blocking:\n  allowlist:\n    - example.com\n    - com\n")
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("Load = %v, want nil", err)
	}
	want := []string{"example.com"}
	if !reflect.DeepEqual(cfg.Blocking.Allowlist, want) {
		t.Errorf("cfg.Blocking.Allowlist = %v, want %v", cfg.Blocking.Allowlist, want)
	}
}

func TestFilterClientNames(t *testing.T) {
	// A key is an exact IP or a CIDR; anything else is dropped as a problem in
	// Load. The label map is a display cosmetic, so a bad key must not abort
	// startup. Values (labels) are never validated.
	in := map[string]string{
		"192.168.1.42": "kids-ipad",
		"10.0.5.0/24":  "iot-vlan",
		"fd00::/8":     "ula",
		"not-an-ip":    "bad",
		"":             "empty-key",
	}
	valid, dropped := filterClientNames(in)

	wantValid := map[string]string{
		"192.168.1.42": "kids-ipad",
		"10.0.5.0/24":  "iot-vlan",
		"fd00::/8":     "ula",
	}
	if !reflect.DeepEqual(valid, wantValid) {
		t.Errorf("valid = %v, want %v", valid, wantValid)
	}
	sort.Strings(dropped)
	wantDropped := []string{"", "not-an-ip"}
	if !reflect.DeepEqual(dropped, wantDropped) {
		t.Errorf("dropped = %v, want %v", dropped, wantDropped)
	}
}

func TestFilterClientNames_Empty(t *testing.T) {
	// A nil map and an all-invalid map both collapse to nil ("attribution off").
	if valid, dropped := filterClientNames(nil); valid != nil || dropped != nil {
		t.Errorf("filterClientNames(nil) = (%v, %v), want (nil, nil)", valid, dropped)
	}
	if valid, _ := filterClientNames(map[string]string{"nope": "x"}); valid != nil {
		t.Errorf("all-invalid valid = %v, want nil", valid)
	}
}

func TestLoad_DropsInvalidClientNames(t *testing.T) {
	path := writeTemp(t, "query_log:\n  client_names:\n    \"192.168.1.42\": kids-ipad\n    bogus: nope\n")
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("Load = %v, want nil", err)
	}
	want := map[string]string{"192.168.1.42": "kids-ipad"}
	if !reflect.DeepEqual(cfg.QueryLog.ClientNames, want) {
		t.Errorf("cfg.QueryLog.ClientNames = %v, want %v", cfg.QueryLog.ClientNames, want)
	}
}

func TestFilterUpstreams(t *testing.T) {
	// Upstreams must be host:port. A bare address (no port), a missing host,
	// and a missing port are all dropped; order is preserved. This is a shape
	// check only, so a syntactically valid but unreachable address is kept.
	in := []string{"1.1.1.1:53", "1.1.1.1", "8.8.8.8:53", ":53", "1.1.1.1:", "[2001:4860:4860::8888]:53"}
	valid, dropped := filterUpstreams(in)

	wantValid := []string{"1.1.1.1:53", "8.8.8.8:53", "[2001:4860:4860::8888]:53"}
	if !reflect.DeepEqual(valid, wantValid) {
		t.Errorf("valid = %v, want %v", valid, wantValid)
	}
	wantDropped := []string{"1.1.1.1", ":53", "1.1.1.1:"}
	if !reflect.DeepEqual(dropped, wantDropped) {
		t.Errorf("dropped = %v, want %v", dropped, wantDropped)
	}
}

func TestFilterUpstreams_Empty(t *testing.T) {
	valid, dropped := filterUpstreams(nil)
	if valid != nil || dropped != nil {
		t.Errorf("filterUpstreams(nil) = (%v, %v), want (nil, nil)", valid, dropped)
	}
}

func TestFilterUpstreams_DoH(t *testing.T) {
	// A DoH endpoint with an IP host is accepted and kept in the mixed list; a
	// DoH URL with a hostname or a non-https scheme is dropped. Order (DoH
	// first, plain fallback) is preserved. TestFilterUpstreams_DoHNormalizationAndDrops
	// covers the other drop cases, a malformed URL among them.
	in := []string{
		"https://1.1.1.1/dns-query",                // IP host: accepted
		"1.1.1.1:53",                               // plain fallback: accepted
		"https://cloudflare-dns.com/dns-query",     // hostname host: dropped
		"http://9.9.9.9/dns-query",                 // not https: dropped
		"https://[2606:4700:4700::1111]/dns-query", // IPv6 host: accepted
	}
	valid, dropped := filterUpstreams(in)

	wantValid := []string{"https://1.1.1.1/dns-query", "1.1.1.1:53", "https://[2606:4700:4700::1111]/dns-query"}
	if !reflect.DeepEqual(valid, wantValid) {
		t.Errorf("valid = %v, want %v", valid, wantValid)
	}
	wantDropped := []string{"https://cloudflare-dns.com/dns-query", "http://9.9.9.9/dns-query"}
	if !reflect.DeepEqual(dropped, wantDropped) {
		t.Errorf("dropped = %v, want %v", dropped, wantDropped)
	}
}

func TestLoad_AcceptsDoHUpstream(t *testing.T) {
	// A DoH IP-literal endpoint survives Load next to a plain fallback, so an
	// operator can order "DoH first, plain fallback" in one list.
	path := writeTemp(t, "dns:\n  upstreams:\n    - https://1.1.1.1/dns-query\n    - 1.1.1.1:53\n")
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("Load = %v, want nil", err)
	}
	want := []string{"https://1.1.1.1/dns-query", "1.1.1.1:53"}
	if !reflect.DeepEqual(cfg.DNS.Upstreams, want) {
		t.Errorf("cfg.DNS.Upstreams = %v, want %v", cfg.DNS.Upstreams, want)
	}
}

func TestLoad_DropsMalformedUpstreams(t *testing.T) {
	// A malformed entry is dropped (Load reports it as a problem) and the valid ones remain,
	// so one fat-finger does not take down a working config.
	path := writeTemp(t, "dns:\n  upstreams:\n    - 1.1.1.1:53\n    - 8.8.8.8\n")
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("Load = %v, want nil", err)
	}
	want := []string{"1.1.1.1:53"}
	if !reflect.DeepEqual(cfg.DNS.Upstreams, want) {
		t.Errorf("cfg.DNS.Upstreams = %v, want %v", cfg.DNS.Upstreams, want)
	}
}

func TestFilterUpstreams_DoHNormalizationAndDrops(t *testing.T) {
	// b/067: the forwarder picks DoH by the exact "https://" prefix, so an
	// accepted DoH entry must be stored with a lowercase scheme. Entries with
	// user info, no path, a root path, a hostname, a non-https scheme, or a
	// URL that url.Parse rejects are dropped.
	cases := []struct {
		in       string
		wantNorm string // "" means dropped
	}{
		{"HTTPS://1.1.1.1/dns-query", "https://1.1.1.1/dns-query"},
		{"Https://1.1.1.1/dns-query", "https://1.1.1.1/dns-query"},
		{"https://1.1.1.1/dns-query", "https://1.1.1.1/dns-query"},
		{"HTTPS://[2606:4700:4700::1111]/dns-query", "https://[2606:4700:4700::1111]/dns-query"},
		{"https://user:pass@1.1.1.1/dns-query", ""},
		{"https://user@1.1.1.1/dns-query", ""},
		{"https://1.1.1.1", ""},
		{"https://1.1.1.1/", ""},
		{"HTTPS://1.1.1.1/", ""},
		{"https://dns.google/dns-query", ""},
		{"http://1.1.1.1/dns-query", ""},
		{"HTTP://1.1.1.1/dns-query", ""},
		{"tls://1.1.1.1/dns-query", ""},
		{"https://[::1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			valid, dropped := filterUpstreams([]string{tc.in})
			if tc.wantNorm == "" {
				if len(valid) != 0 || !reflect.DeepEqual(dropped, []string{tc.in}) {
					t.Errorf("filterUpstreams(%q) = (%v, %v), want dropped", tc.in, valid, dropped)
				}
				return
			}
			if !reflect.DeepEqual(valid, []string{tc.wantNorm}) || len(dropped) != 0 {
				t.Errorf("filterUpstreams(%q) = (%v, %v), want valid [%s]", tc.in, valid, dropped, tc.wantNorm)
			}
			if !strings.HasPrefix(valid[0], "https://") {
				t.Errorf("stored %q does not start with the forwarder's DoH prefix", valid[0])
			}
		})
	}
}

func TestFilterUpstreams_MalformedURLReallyFailsParse(t *testing.T) {
	// Guard the malformed-URL case above: "https://[::1" must make url.Parse
	// fail, so the drop comes from the parse error and not a later check.
	malformed := "https://[::1"
	if _, err := url.Parse(malformed); err == nil { //nolint:staticcheck // SA1007: malformed on purpose
		t.Fatal("url.Parse(\"https://[::1\") succeeded; pick another malformed URL")
	}
	_, dropped := filterUpstreams([]string{malformed})
	if !reflect.DeepEqual(dropped, []string{malformed}) {
		t.Errorf("dropped = %v, want [https://[::1]", dropped)
	}
}

func TestLoad_NormalizesDoHAndReportsDrops(t *testing.T) {
	// b/067: Load stores the normalized DoH URL and reports one problem for
	// each dropped entry. Plain host:port entries pass through unchanged. The
	// problem must not show user info: it is replaced by "redacted", and the
	// user name and password appear nowhere in it. This holds for an entry that
	// url.Parse rejects too. Entries with no user info, parsable or not, are
	// shown as written.
	path := writeTemp(t, "dns:\n  upstreams:\n"+
		"    - HTTPS://1.1.1.1/dns-query\n"+
		"    - https://s3cretuser:hunter2pw@1.1.1.1/dns-query\n"+
		"    - https://onlyuserx@8.8.8.8/dns-query\n"+
		"    - \"https://u1sec:p1sec@1.1.1.1:bad/dns-query\"\n"+
		"    - \"https://u2sec:p2sec@[::1/x\"\n"+
		"    - \"https://us er:p3sec@1.1.1.1/x\"\n"+
		"    - https://1.1.1.1/\n"+
		"    - \"https://[::1\"\n"+
		"    - 9.9.9.9:53\n")
	cfg, probs, err := Load(path)
	if err != nil {
		t.Fatalf("Load = %v", err)
	}
	want := []string{"https://1.1.1.1/dns-query", "9.9.9.9:53"}
	if !reflect.DeepEqual(cfg.DNS.Upstreams, want) {
		t.Errorf("cfg.DNS.Upstreams = %v, want %v", cfg.DNS.Upstreams, want)
	}

	var all []string
	for _, p := range probs {
		all = append(all, p.String())
	}
	out := strings.Join(all, "\n")
	for _, secret := range []string{"s3cretuser", "hunter2pw", "onlyuserx", "u1sec", "p1sec", "u2sec", "p2sec", "us er", "p3sec"} {
		if strings.Contains(out, secret) {
			t.Errorf("problems contain user info %q:\n%s", secret, out)
		}
	}
	wantShown := []string{
		"https://redacted@1.1.1.1/dns-query",
		"https://redacted@8.8.8.8/dns-query",
		"https://redacted@1.1.1.1:bad/dns-query",
		"https://redacted@[::1/x",
		"https://redacted@1.1.1.1/x",
		"https://1.1.1.1/",
		"https://[::1",
	}
	if len(probs) != len(wantShown) {
		t.Fatalf("got %d problems, want %d:\n%s", len(probs), len(wantShown), out)
	}
	for i, w := range wantShown {
		if probs[i].Key != "dns.upstreams" || !strings.Contains(probs[i].Detail, strconv.Quote(w)) {
			t.Errorf("problem %d = %q, want dns.upstreams naming %q", i, probs[i], w)
		}
	}
}

func TestRedactURL_UnparsableURL(t *testing.T) {
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
			if got := RedactURL(tc.in); got != tc.want {
				t.Errorf("RedactURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
