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
