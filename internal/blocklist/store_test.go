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
		{"not in list", "example.com", false},
		{"empty string", "", false},
		{"subdomain not auto-blocked", "foo.ads.example.com", false},
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
