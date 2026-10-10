//go:build !race

// This file is excluded from -race builds on purpose. The race detector's
// instrumentation allocates, so testing.AllocsPerRun reports non-zero under
// -race and the zero-alloc assertion below would flake.

package dnsserver

import "testing"

// TestHandler_ChainBlocked_ZeroAlloc pins the CL 117 req 14 property that the
// CNAME check does not allocate: it runs on every served answer. It covers a
// chain with no blocked target (the full walk), a blocked last hop, and an
// allowlisted queried name (the early exit). The names are lowercase, as an
// upstream usually sends them; a mixed-case target allocates in
// strings.ToLower, a normalize concern that TestStore_IsBlocked_ZeroAlloc
// also leaves out.
func TestHandler_ChainBlocked_ZeroAlloc(t *testing.T) {
	h, resp := chainBench()
	cases := []struct {
		name   string
		domain string
		setup  func()
		want   bool
	}{
		{"no target blocked", cnQueried, func() {}, false},
		{"last hop blocked", cnQueried, func() { h.store.Replace([]string{"zqorigin.example"}) }, true},
		{"queried name allowlisted", cnQueried, func() { h.store.AddToAllowlist("shop.example") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			var got bool
			allocs := testing.AllocsPerRun(1000, func() {
				got = h.chainBlocked(tc.domain, resp)
			})
			if got != tc.want {
				t.Fatalf("chainBlocked = %v, want %v", got, tc.want)
			}
			if allocs != 0 {
				t.Errorf("chainBlocked allocated %v times per call, want 0", allocs)
			}
		})
	}
}
