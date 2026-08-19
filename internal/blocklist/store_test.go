package blocklist

import (
	"strconv"
	"sync"
	"testing"
)

func TestStore_IsBlocked(t *testing.T) {
	s := NewStore()
	s.Replace([]string{"ads.example.com", "tracker.example.net"})

	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"exact match lowercase", "ads.example.com", true},
		{"exact match mixed case", "Ads.Example.Com", true},
		{"trailing dot stripped", "ads.example.com.", true},
		{"parent of a blocked domain is not blocked", "example.com", false},
		{"empty string", "", false},
		// Suffix (wildcard) blocking: a blocked domain blocks its subtree
		// (ROADMAP #3). This case asserted `false` under the old exact-match
		// semantics; the flip is the whole point of the change.
		{"subdomain auto-blocked", "foo.ads.example.com", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.IsBlocked(tc.domain); got != tc.want {
				t.Errorf("IsBlocked(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

func TestStore_WhitelistOverridesBlocklist(t *testing.T) {
	s := NewStore()
	s.Replace([]string{"ads.example.com"})
	s.SetWhitelist([]string{"ads.example.com"})

	if s.IsBlocked("ads.example.com") {
		t.Fatal("whitelist must override blocklist")
	}
}

// TestStore_SubdomainBlocking pins the suffix-match semantics (ROADMAP #3):
// a blocked domain blocks every domain beneath it, but matching is on label
// boundaries, not substrings, and unrelated names stay unblocked.
func TestStore_SubdomainBlocking(t *testing.T) {
	s := NewStore()
	// Two entries: a two-label apex and a deeper label.
	s.Replace([]string{"doubleclick.net", "ads.example.com"})

	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"exact apex", "doubleclick.net", true},
		{"one subdomain", "www.doubleclick.net", true},
		{"deep subdomain", "a.b.c.doubleclick.net", true},
		{"exact deeper entry", "ads.example.com", true},
		{"subdomain of deeper entry", "x.ads.example.com", true},
		// Parent of a blocked deeper entry must NOT be blocked.
		{"parent not blocked", "example.com", false},
		// Sibling under the same parent must NOT be blocked.
		{"sibling not blocked", "cdn.example.com", false},
		// Label-boundary, not substring: "xdoubleclick.net" only shares a
		// suffix with the TLD, which is never on the list.
		{"substring is not a suffix match", "xdoubleclick.net", false},
		// A different apex that merely ends in the same TLD.
		{"unrelated same-TLD domain", "example.net", false},
		{"unrelated domain", "example.org", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.IsBlocked(tc.domain); got != tc.want {
				t.Errorf("IsBlocked(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

// TestStore_WhitelistSuffixSemantics pins the "whitelist wins at every level"
// rule (ROADMAP #3): whitelisting a domain exempts it and its whole subtree,
// even when a more specific parent is on the block set, and the exemption is
// surgical: sibling subtrees stay blocked.
func TestStore_WhitelistSuffixSemantics(t *testing.T) {
	s := NewStore()
	s.Replace([]string{"doubleclick.net", "ads.example.com"})
	// safe.doubleclick.net is a more specific whitelist entry than the
	// doubleclick.net block; example.com is a parent-level whitelist entry
	// sitting above the deeper ads.example.com block.
	s.SetWhitelist([]string{"safe.doubleclick.net", "example.com"})

	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		// Whitelisted name and its subtree are exempt from the parent block.
		{"whitelisted subdomain exempt", "safe.doubleclick.net", false},
		{"child of whitelisted name exempt", "img.safe.doubleclick.net", false},
		// Sibling under the blocked apex is still blocked.
		{"sibling still blocked", "ads.doubleclick.net", true},
		{"blocked apex still blocked", "doubleclick.net", true},
		// Parent-level whitelist exempts the whole subtree, including a
		// deeper block entry underneath it.
		{"parent whitelist exempts blocked child", "ads.example.com", false},
		{"parent whitelist exempts child subtree", "x.ads.example.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.IsBlocked(tc.domain); got != tc.want {
				t.Errorf("IsBlocked(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

func TestStore_AddRemoveWhitelist(t *testing.T) {
	s := NewStore()
	s.Replace([]string{"ads.example.com"})

	if !s.IsBlocked("ads.example.com") {
		t.Fatal("precondition: domain should be blocked before whitelist add")
	}

	s.AddToWhitelist("ads.example.com")
	if s.IsBlocked("ads.example.com") {
		t.Fatal("AddToWhitelist did not take effect")
	}

	s.RemoveFromWhitelist("ads.example.com")
	if !s.IsBlocked("ads.example.com") {
		t.Fatal("RemoveFromWhitelist did not take effect")
	}
}

func TestStore_GetWhitelist(t *testing.T) {
	s := NewStore()
	s.AddToWhitelist("a.com")
	s.AddToWhitelist("b.com")

	got := s.GetWhitelist()
	if len(got) != 2 {
		t.Fatalf("GetWhitelist len = %d, want 2", len(got))
	}
	// Order is unspecified; turn into a set for the comparison.
	set := map[string]bool{got[0]: true, got[1]: true}
	if !set["a.com"] || !set["b.com"] {
		t.Errorf("GetWhitelist = %v, want a.com and b.com", got)
	}
}

func TestStore_ReplaceIsAtomic(t *testing.T) {
	// Hammer Replace from one goroutine while IsBlocked runs from another.
	// Catches lock omissions: under `go test -race`, any unsynchronised map
	// access fires immediately.
	s := NewStore()
	s.Replace([]string{"a.com", "b.com"})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.IsBlocked("a.com")
			}
		}
	}()
	for i := 0; i < 1000; i++ {
		s.Replace([]string{"a.com", "b.com", "c.com"})
	}
	close(stop)
	wg.Wait()
}

func TestStore_Len(t *testing.T) {
	s := NewStore()
	if s.Len() != 0 {
		t.Errorf("empty store Len = %d, want 0", s.Len())
	}
	s.Replace([]string{"a.com", "b.com", "c.com"})
	if s.Len() != 3 {
		t.Errorf("Len = %d, want 3", s.Len())
	}
}

func TestStore_WhitelistLen(t *testing.T) {
	// R34: WhitelistLen must mirror GetWhitelist's count without
	// allocating the full slice. Verify by hand that the two stay in
	// sync across SetWhitelist and AddToWhitelist/RemoveFromWhitelist.
	s := NewStore()
	if s.WhitelistLen() != 0 {
		t.Errorf("empty whitelist WhitelistLen = %d, want 0", s.WhitelistLen())
	}

	s.SetWhitelist([]string{"a.com", "b.com"})
	if s.WhitelistLen() != 2 {
		t.Errorf("after SetWhitelist WhitelistLen = %d, want 2", s.WhitelistLen())
	}
	if len(s.GetWhitelist()) != s.WhitelistLen() {
		t.Errorf("WhitelistLen %d disagrees with len(GetWhitelist()) %d",
			s.WhitelistLen(), len(s.GetWhitelist()))
	}

	s.AddToWhitelist("c.com")
	if s.WhitelistLen() != 3 {
		t.Errorf("after AddToWhitelist WhitelistLen = %d, want 3", s.WhitelistLen())
	}

	s.RemoveFromWhitelist("a.com")
	if s.WhitelistLen() != 2 {
		t.Errorf("after RemoveFromWhitelist WhitelistLen = %d, want 2", s.WhitelistLen())
	}
}

// BenchmarkStore_IsBlocked guards the hot DNS path against accidental
// O(n) regressions: IsBlocked is called once per query and is the single
// largest call-graph hop on every blocked-or-not decision.
func BenchmarkStore_IsBlocked(b *testing.B) {
	s := NewStore()
	const N = 100_000
	dom := make([]string, 0, N)
	for i := 0; i < N; i++ {
		dom = append(dom, "x"+strconv.Itoa(i)+".example.com")
	}
	s.Replace(dom)

	probe := "x50000.example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !s.IsBlocked(probe) {
			b.Fatal("probe not found")
		}
	}
}

// BenchmarkStore_IsBlocked_Miss covers the suffix walk's worst case: a
// deep, not-blocked, not-whitelisted name walks every label to the TLD
// without an early return. This is the hot path for the overwhelming
// majority of real traffic (allowed queries), so it is the number that
// matters most for the ROADMAP #3 suffix-match change.
func BenchmarkStore_IsBlocked_Miss(b *testing.B) {
	s := NewStore()
	const N = 100_000
	dom := make([]string, 0, N)
	for i := 0; i < N; i++ {
		dom = append(dom, "x"+strconv.Itoa(i)+".example.com")
	}
	s.Replace(dom)

	// Five labels, none of whose suffixes are on the set.
	probe := "deep.sub.domain.example.org"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if s.IsBlocked(probe) {
			b.Fatal("probe unexpectedly blocked")
		}
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{"EXAMPLE.COM.", "example.com"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := normalize(tc.in); got != tc.want {
			t.Errorf("normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
