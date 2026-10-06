package main

import (
	"reflect"
	"strings"
	"testing"
)

// bannerLines prints the Router setup banner and returns its DNS server
// lines (the text after the arrow) and its other lines. It skips the test
// when the machine has no LAN IPv4 address, because the banner then prints
// nothing.
func bannerLines(t *testing.T, ascii bool, dnsHost, dnsPort, dotPort, apiHost string) (dns, other []string) {
	t.Helper()
	t.Setenv("S_HOLE_LOG_FORMAT", "")
	arrow := " → "
	if ascii {
		t.Setenv("S_HOLE_ASCII_BANNER", "1")
		arrow = " -> "
	} else {
		t.Setenv("S_HOLE_ASCII_BANNER", "")
	}
	out := captureStdout(t, func() {
		printNetworkHint(dnsHost, dnsPort, dotPort, apiHost, "8080", true)
	})
	if !strings.Contains(out, "Router setup") {
		t.Skipf("no LAN interface in test env; banner skipped (got: %q)", out)
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.Contains(line, "DNS server") {
			_, after, ok := strings.Cut(line, arrow)
			if !ok {
				t.Fatalf("DNS line %q has no %q arrow", line, arrow)
			}
			dns = append(dns, after)
			continue
		}
		other = append(other, line)
	}
	return dns, other
}

func TestPrintNetworkHint_DNSLinesFollowListenHost(t *testing.T) {
	// b/088: the DNS server lines follow the host part of dns.listen. A
	// wildcard lists every LAN IPv4 address, a specific address lists only
	// itself, and a loopback address lists itself with "(this machine only)".
	// IPv6 addresses show in brackets. The ASCII and Unicode banners follow
	// the same rule.
	lan := lanIPv4s(systemInterfaces())
	var wildcard []string
	for _, ip := range lan {
		wildcard = append(wildcard, ip+":53")
	}
	cases := []struct {
		dnsHost string
		want    []string
	}{
		{"", wildcard},
		{"0.0.0.0", wildcard},
		{"::", wildcard},
		{"192.0.2.10", []string{"192.0.2.10:53"}},
		{"2001:db8::10", []string{"[2001:db8::10]:53"}},
		{"127.0.0.1", []string{"127.0.0.1:53 (this machine only)"}},
		{"127.0.0.53", []string{"127.0.0.53:53 (this machine only)"}},
		{"::1", []string{"[::1]:53 (this machine only)"}},
	}
	if len(lan) > 0 {
		// One of the machine's own LAN addresses is still a single line.
		cases = append(cases, struct {
			dnsHost string
			want    []string
		}{lan[0], []string{lan[0] + ":53"}})
	}
	for _, ascii := range []bool{false, true} {
		for _, tc := range cases {
			name := "unicode/" + tc.dnsHost
			if ascii {
				name = "ascii/" + tc.dnsHost
			}
			t.Run(name, func(t *testing.T) {
				dns, _ := bannerLines(t, ascii, tc.dnsHost, "53", "", "127.0.0.1")
				if !reflect.DeepEqual(dns, tc.want) {
					t.Errorf("DNS lines = %q, want %q", dns, tc.want)
				}
			})
		}
	}
}

func TestPrintNetworkHint_DNSLineUsesThePort(t *testing.T) {
	// b/088: the bound address is shown with the dns.listen port.
	dns, _ := bannerLines(t, false, "192.0.2.10", "5353", "", "127.0.0.1")
	if !reflect.DeepEqual(dns, []string{"192.0.2.10:5353"}) {
		t.Errorf("DNS lines = %q, want [192.0.2.10:5353]", dns)
	}
	dns, _ = bannerLines(t, true, "::1", "5353", "", "127.0.0.1")
	if !reflect.DeepEqual(dns, []string{"[::1]:5353 (this machine only)"}) {
		t.Errorf("DNS lines = %q, want [[::1]:5353 (this machine only)]", dns)
	}
}

func TestPrintNetworkHint_OtherLinesDoNotChange(t *testing.T) {
	// b/088: the Admin UI lines and the DoT line do not depend on dnsHost.
	for _, ascii := range []bool{false, true} {
		for _, apiHost := range []string{"0.0.0.0", "127.0.0.1"} {
			_, base := bannerLines(t, ascii, "", "53", "853", apiHost)
			for _, dnsHost := range []string{"0.0.0.0", "192.0.2.10", "127.0.0.1", "::1"} {
				_, other := bannerLines(t, ascii, dnsHost, "53", "853", apiHost)
				if !reflect.DeepEqual(other, base) {
					t.Errorf("ascii=%v apiHost=%s dnsHost=%s: other lines = %q, want %q", ascii, apiHost, dnsHost, other, base)
				}
			}
			if !strings.Contains(strings.Join(base, "\n"), "port 853") {
				t.Errorf("ascii=%v: no DoT line in %q", ascii, base)
			}
		}
	}
}
