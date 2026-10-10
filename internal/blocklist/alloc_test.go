//go:build !race

// This file is excluded from -race builds on purpose. The race detector's
// instrumentation allocates, so testing.AllocsPerRun reports non-zero under
// -race and the zero-alloc assertion below would flake. The test still runs
// in the normal suite (make test, make check) and in CI's non-race job.

package blocklist

import "testing"

// TestStore_IsBlocked_ZeroAlloc pins the documented zero-per-query allocation
// property of the suffix walk (DESIGN: the walk "reslices the name in place").
// It guards both hot-path shapes: a hit that returns early, and a miss that
// walks every label to the TLD (the common allowed-query path).
//
// The probes are already lowercased with no trailing dot, so normalize hits
// its allocation-free path (strings.ToLower returns an all-lowercase ASCII
// string unchanged, and the trailing-dot trim is a reslice). A mixed-case or
// FQDN-dotted name allocates in ToLower; that is a normalize concern, separate
// from the walk this test pins.
func TestStore_IsBlocked_ZeroAlloc(t *testing.T) {
	s := NewStore()
	s.Replace([]string{"ads.example.com"})

	cases := []struct {
		name  string
		probe string
	}{
		{"hit", "ads.example.com"},
		{"miss_deep_walk", "deep.sub.domain.example.org"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sink bool
			allocs := testing.AllocsPerRun(1000, func() {
				sink = s.IsBlocked(tc.probe)
			})
			// Keep sink observable so the call cannot be optimized away.
			if sink && tc.name == "miss_deep_walk" {
				t.Fatalf("probe %q was unexpectedly blocked", tc.probe)
			}
			if allocs != 0 {
				t.Errorf("IsBlocked(%q) allocated %v times per call, want 0", tc.probe, allocs)
			}
		})
	}
}

// TestStore_IsAllowlisted_ZeroAlloc pins the CL 117 req 12 property that
// IsAllowlisted does not allocate: the DNS handler calls it for every served
// answer with a CNAME chain. It covers a hit on a parent (an early return
// after one step), a miss that walks every label, and the lowercase FQDN with
// a trailing dot that the handler passes.
func TestStore_IsAllowlisted_ZeroAlloc(t *testing.T) {
	s := NewStore()
	s.Replace([]string{"tracker.example.com"})
	s.SetAllowlist([]string{"shop.example"})

	cases := []struct {
		probe string
		want  bool
	}{
		{"metrics.shop.example", true},
		{"metrics.shop.example.", true},
		{"deep.sub.domain.example.org", false},
		{"deep.sub.domain.example.org.", false},
	}
	for _, tc := range cases {
		t.Run(tc.probe, func(t *testing.T) {
			var got bool
			allocs := testing.AllocsPerRun(1000, func() {
				got = s.IsAllowlisted(tc.probe)
			})
			if got != tc.want {
				t.Fatalf("IsAllowlisted(%q) = %v, want %v", tc.probe, got, tc.want)
			}
			if allocs != 0 {
				t.Errorf("IsAllowlisted(%q) allocated %v times per call, want 0", tc.probe, allocs)
			}
		})
	}
}
