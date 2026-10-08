package blocklist

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// SEC-11: Store.AddToAllowlistLimited caps the runtime allowlist. It refuses
// a new domain once limit runtime entries exist (config entries from
// SetAllowlist do not count), accepts a domain that is already present
// without using a slot, and checks and adds atomically.

func TestStore_AddToAllowlistLimited_BelowLimitAdds(t *testing.T) {
	s := NewStore()
	s.Replace([]string{"ads.example.com"})
	for i := 0; i < 3; i++ {
		if !s.AddToAllowlistLimited(fmt.Sprintf("d%d.example.com", i), 3) {
			t.Fatalf("add %d with limit 3 = false, want true", i+1)
		}
	}
	if n := s.AllowlistLen(); n != 3 {
		t.Errorf("AllowlistLen = %d, want 3", n)
	}
	// The added entry works like any allowlist entry.
	if !s.AddToAllowlistLimited("ads.example.com", 4) || s.IsBlocked("ads.example.com") {
		t.Error("an entry added with AddToAllowlistLimited does not override the block set")
	}
}

func TestStore_AddToAllowlistLimited_RefusesNewAtLimit(t *testing.T) {
	s := NewStore()
	s.Replace([]string{"new.example.com"})
	for _, d := range []string{"a.example.com", "b.example.com"} {
		if !s.AddToAllowlistLimited(d, 2) {
			t.Fatalf("add %q below the limit = false, want true", d)
		}
	}
	if s.AddToAllowlistLimited("new.example.com", 2) {
		t.Error("new domain at the limit = true, want false")
	}
	if n := s.AllowlistLen(); n != 2 {
		t.Errorf("AllowlistLen = %d after a refused add, want 2", n)
	}
	for _, d := range s.GetAllowlist() {
		if d == "new.example.com" {
			t.Error("the refused domain is in the allowlist")
		}
	}
	if !s.IsBlocked("new.example.com") {
		t.Error("the refused domain is not blocked any more")
	}
	// A smaller limit than the runtime entries refuses too.
	if s.AddToAllowlistLimited("new.example.com", 1) {
		t.Error("new domain over the limit = true, want false")
	}
}

func TestStore_AddToAllowlistLimited_ConfigEntriesDoNotCount(t *testing.T) {
	// SEC-11 (maintainer decision): the limit counts only runtime entries.
	// Config entries (SetAllowlist), more than the limit, take no slot.
	s := NewStore()
	s.SetAllowlist([]string{"c1.example.com", "c2.example.com", "c3.example.com", "c4.example.com", "c5.example.com"})
	for _, d := range []string{"r1.example.com", "r2.example.com"} {
		if !s.AddToAllowlistLimited(d, 2) {
			t.Fatalf("runtime add %q with 5 config entries and limit 2 = false, want true", d)
		}
	}
	if s.AddToAllowlistLimited("r3.example.com", 2) {
		t.Error("third runtime add with limit 2 = true, want false")
	}
	if n := s.AllowlistLen(); n != 7 {
		t.Errorf("AllowlistLen = %d, want 7", n)
	}
}

func TestStore_AddToAllowlistLimited_PresentDomainUsesNoSlot(t *testing.T) {
	// SEC-11: a domain already in the allowlist (config or runtime) is
	// accepted at the limit and uses no slot.
	s := NewStore()
	s.SetAllowlist([]string{"cfg.example.com"})
	if !s.AddToAllowlistLimited("cfg.example.com", 1) {
		t.Fatal("config domain with limit 1 = false, want true")
	}
	if !s.AddToAllowlistLimited("r1.example.com", 1) {
		t.Fatal("first runtime add after the config re-add = false, want true (the re-add used a slot)")
	}
	for _, d := range []string{"r1.example.com", "cfg.example.com"} {
		if !s.AddToAllowlistLimited(d, 1) {
			t.Errorf("re-add %q at the limit = false, want true", d)
		}
	}
	if s.AddToAllowlistLimited("r2.example.com", 1) {
		t.Error("new runtime add at the limit = true, want false (a re-add used a slot or the limit is off)")
	}
	if n := s.AllowlistLen(); n != 2 {
		t.Errorf("AllowlistLen = %d, want 2", n)
	}
}

func TestStore_AddToAllowlistLimited_RemoveFreesSlot(t *testing.T) {
	// SEC-11: RemoveFromAllowlist of a runtime entry frees its slot.
	s := NewStore()
	if !s.AddToAllowlistLimited("r1.example.com", 1) {
		t.Fatal("first add = false, want true")
	}
	if s.AddToAllowlistLimited("r2.example.com", 1) {
		t.Fatal("second add with limit 1 = true, want false")
	}
	s.RemoveFromAllowlist("r1.example.com")
	if !s.AddToAllowlistLimited("r2.example.com", 1) {
		t.Error("add after removing the runtime entry = false, want true")
	}
	if s.AddToAllowlistLimited("r3.example.com", 1) {
		t.Error("add after the freed slot is used = true, want false")
	}
}

func TestStore_AddToAllowlistLimited_SetAllowlistClearsRuntime(t *testing.T) {
	// SEC-11: SetAllowlist replaces the whole allowlist, the runtime entries
	// included, so their slots are free again afterwards.
	s := NewStore()
	if !s.AddToAllowlistLimited("r1.example.com", 1) {
		t.Fatal("first add = false, want true")
	}
	s.SetAllowlist([]string{"cfg.example.com"})
	if !s.AddToAllowlistLimited("r2.example.com", 1) {
		t.Error("add after SetAllowlist = false, want true")
	}
	if s.AddToAllowlistLimited("r3.example.com", 1) {
		t.Error("second add after SetAllowlist with limit 1 = true, want false")
	}
}

func TestStore_AddToAllowlistLimited_ConcurrentAddsKeepLimit(t *testing.T) {
	// SEC-11: the check and the add are atomic. Many goroutines add distinct
	// domains at once; exactly limit adds succeed and the allowlist ends at
	// limit entries. Run under -race.
	const (
		limit      = 50
		goroutines = 400
	)
	s := NewStore()
	var accepted atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if s.AddToAllowlistLimited(fmt.Sprintf("g%d.example.com", i), limit) {
				accepted.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if got := accepted.Load(); got != limit {
		t.Errorf("accepted adds = %d, want %d", got, limit)
	}
	if n := s.AllowlistLen(); n != limit {
		t.Errorf("AllowlistLen = %d, want %d", n, limit)
	}
}
