package stats

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestCounter_RecordAndSnapshot(t *testing.T) {
	c := New()
	c.RecordQuery("1.2.3.4", "ads.example.com.", true)
	c.RecordQuery("1.2.3.4", "google.com.", false)
	c.RecordQuery("5.6.7.8", "ads.example.com.", true)

	s := c.Snapshot(10)
	if s.TotalQueries != 3 {
		t.Errorf("TotalQueries = %d, want 3", s.TotalQueries)
	}
	if s.BlockedCount != 2 {
		t.Errorf("BlockedCount = %d, want 2", s.BlockedCount)
	}
	wantPct := float64(2) / float64(3) * 100
	if s.BlockedPct != wantPct {
		t.Errorf("BlockedPct = %v, want %v", s.BlockedPct, wantPct)
	}
}

func TestCounter_RecordCacheHit(t *testing.T) {
	c := New()
	// One forwardable query (not blocked), three cache hits in scenario.
	c.RecordQuery("1.2.3.4", "google.com.", false)
	c.RecordCacheHit()

	s := c.Snapshot(0)
	if s.CacheHits != 1 {
		t.Errorf("CacheHits = %d, want 1", s.CacheHits)
	}
	if s.CacheHitPct <= 0 {
		t.Errorf("CacheHitPct = %v, want > 0", s.CacheHitPct)
	}
}

func TestCounter_CacheHitPctZeroWhenAllBlocked(t *testing.T) {
	c := New()
	c.RecordQuery("1.2.3.4", "ads.example.com.", true)
	s := c.Snapshot(0)
	if s.CacheHitPct != 0 {
		t.Errorf("CacheHitPct = %v, want 0 (no forwardable queries)", s.CacheHitPct)
	}
}

func TestCounter_TopDomainsOrdering(t *testing.T) {
	c := New()
	c.RecordQuery("1.1.1.1", "a.com.", true)
	c.RecordQuery("1.1.1.1", "a.com.", true)
	c.RecordQuery("1.1.1.1", "a.com.", true)
	c.RecordQuery("1.1.1.1", "b.com.", true)

	s := c.Snapshot(10)
	if len(s.TopDomains) != 2 {
		t.Fatalf("TopDomains len = %d, want 2", len(s.TopDomains))
	}
	if s.TopDomains[0].Name != "a.com." || s.TopDomains[0].Count != 3 {
		t.Errorf("TopDomains[0] = %+v, want {a.com., 3}", s.TopDomains[0])
	}
	if s.TopDomains[1].Name != "b.com." || s.TopDomains[1].Count != 1 {
		t.Errorf("TopDomains[1] = %+v, want {b.com., 1}", s.TopDomains[1])
	}
}

func TestCounter_TopNLimit(t *testing.T) {
	c := New()
	c.RecordQuery("1.1.1.1", "a.com.", true)
	c.RecordQuery("1.1.1.1", "b.com.", true)
	c.RecordQuery("1.1.1.1", "c.com.", true)

	s := c.Snapshot(2)
	if len(s.TopDomains) != 2 {
		t.Errorf("TopDomains len = %d, want 2 (truncated)", len(s.TopDomains))
	}
}

func TestCounter_TopNMapsAreBounded(t *testing.T) {
	// R19: a long-running process must not accumulate every unique key
	// forever. Push topNMaxEntries+1 unique domain/client entries and
	// verify the map is pruned back below the cap.
	c := New()
	for i := 0; i < topNMaxEntries+10; i++ {
		c.RecordQuery(itoa(i)+".client.", "ads"+itoa(i)+".example.com.", true)
	}
	c.mu.Lock()
	domSize := len(c.topDomains)
	cliSize := len(c.topClients)
	c.mu.Unlock()
	if domSize > topNMaxEntries {
		t.Errorf("topDomains len = %d, want <= %d", domSize, topNMaxEntries)
	}
	if cliSize > topNMaxEntries {
		t.Errorf("topClients len = %d, want <= %d", cliSize, topNMaxEntries)
	}
}

func TestPruneBottomHalf_KeepsHighFrequency(t *testing.T) {
	m := map[string]int64{"hot": 100, "warm": 50, "cool": 5, "cold": 1}
	out := pruneBottomHalf(m)
	if _, ok := out["hot"]; !ok {
		t.Error("hot entry was dropped")
	}
	if len(out) >= len(m) {
		t.Errorf("prune did not reduce size: %d → %d", len(m), len(out))
	}
}

// itoa is a minimal integer→string helper to avoid pulling strconv into
// the hot test loop.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestCounter_BlockRateNeverExceeds100UnderLoad(t *testing.T) {
	// Regression for b/021. Hammer RecordQuery from many goroutines while
	// repeatedly calling Snapshot from one goroutine; assert
	// BlockedCount <= TotalQueries on every observation.
	c := New()

	stop := atomic.Bool{}
	var wg sync.WaitGroup

	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				// Every other query is blocked, but the order in which the
				// atomic counters are observed is what's under test.
				c.RecordQuery("1.1.1.1", "ads.com.", true)
				c.RecordQuery("1.1.1.1", "google.com.", false)
			}
		}()
	}

	for range 5000 {
		s := c.Snapshot(0)
		if s.BlockedCount > s.TotalQueries {
			t.Fatalf("invariant violated: blocked=%d > total=%d", s.BlockedCount, s.TotalQueries)
		}
		if s.BlockedPct > 100 {
			t.Fatalf("BlockedPct = %v exceeds 100%%", s.BlockedPct)
		}
	}
	stop.Store(true)
	wg.Wait()
}
