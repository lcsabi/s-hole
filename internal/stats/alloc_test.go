//go:build !race

// This file is excluded from -race builds on purpose. The race detector's
// instrumentation allocates, so testing.AllocsPerRun reports non-zero under
// -race and the zero-alloc assertion below would flake.

package stats

import "testing"

// TestRecordQuery_ZeroAlloc pins S2: the per-minute timeline keeps
// RecordQuery allocation-free on the hot path. The keys exist already, so
// the tally maps do not grow, and an empty client and domain are not tallied.
func TestRecordQuery_ZeroAlloc(t *testing.T) {
	c := New()
	c.RecordQuery("192.168.1.5", "ads.example.com.", true)
	cases := []struct {
		name, client, domain string
		blocked              bool
	}{
		{"blocked, tallied", "192.168.1.5", "ads.example.com.", true},
		{"allowed, tallied", "192.168.1.5", "ok.example.com.", false},
		{"not recorded", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(1000, func() {
				c.RecordQuery(tc.client, tc.domain, tc.blocked)
			})
			if allocs != 0 {
				t.Errorf("RecordQuery allocated %v times per call, want 0", allocs)
			}
		})
	}
	for name, fn := range map[string]func(){
		"RecordCacheHit":       c.RecordCacheHit,
		"RecordForwardFailure": c.RecordForwardFailure,
		"RecordUpstreamError":  c.RecordUpstreamError,
	} {
		if allocs := testing.AllocsPerRun(1000, fn); allocs != 0 {
			t.Errorf("%s allocated %v times per call, want 0", name, allocs)
		}
	}
}
