package stats

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
)

// CL 117: a query blocked through a CNAME target is recorded as
// RecordQuery(client, domain, true), then RecordCNAMEBlocked. The CNAME
// counter is a subset of the blocked counter.

func TestCounter_RecordCNAMEBlocked(t *testing.T) {
	// CL 117 req 5: a CNAME block counts once in the total, once as blocked, and
	// once as a CNAME block; never as a cache hit or a failure. A name block
	// does not count as a CNAME block.
	c := New()
	for range 3 {
		c.RecordQuery("", "", true)
		c.RecordCNAMEBlocked()
	}
	c.RecordQuery("", "", true) // a name block
	c.RecordQuery("", "", false)
	s := c.Snapshot(0)
	if s.TotalQueries != 5 || s.BlockedCount != 4 || s.CNAMEBlockedCount != 3 {
		t.Errorf("snapshot = total %d, blocked %d, cname %d; want 5, 4, 3", s.TotalQueries, s.BlockedCount, s.CNAMEBlockedCount)
	}
	if s.CacheHits != 0 || s.ForwardFailures != 0 || s.UpstreamErrors != 0 || s.LocalPTRCount != 0 || s.LocalNameCount != 0 {
		t.Errorf("other counters = %+v, want 0 each", s)
	}
}

func TestSummary_CNAMEBlockedCountJSON(t *testing.T) {
	// CL 117 req 5, req 10: /api/stats carries the counter as "cname_blocked_count",
	// also when it is zero.
	c := New()
	b, err := json.Marshal(c.Snapshot(0))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["cname_blocked_count"]; !ok || v != float64(0) {
		t.Errorf("cname_blocked_count = %#v (present %v) in %s, want 0", v, ok, b)
	}

	c.RecordQuery("", "", true)
	c.RecordCNAMEBlocked()
	b, _ = json.Marshal(c.Snapshot(0))
	m = nil
	_ = json.Unmarshal(b, &m)
	if m["cname_blocked_count"] != float64(1) {
		t.Errorf("cname_blocked_count = %#v in %s, want 1", m["cname_blocked_count"], b)
	}
}

func TestCounter_CNAMEBlockedSurvivesResetTallies(t *testing.T) {
	// CL 117: a purge resets the tallies and the graph, never the counters.
	c := New()
	c.RecordQuery("192.168.1.2", "metrics.shop.example.", true)
	c.RecordCNAMEBlocked()
	c.ResetTallies()
	c.ResetTimeline()
	if s := c.Snapshot(10); s.CNAMEBlockedCount != 1 || s.BlockedCount != 1 {
		t.Errorf("after a purge: cname %d, blocked %d; want 1, 1", s.CNAMEBlockedCount, s.BlockedCount)
	}
}

func TestCounter_CNAMEBlockedNeverExceedsBlockedUnderLoad(t *testing.T) {
	// CL 117 req 6: the b/021 pattern applied to the CNAME counter. The handler
	// records a CNAME block as RecordQuery(blocked) then RecordCNAMEBlocked,
	// so cnameBlocked is the strictly-later counter. If Snapshot read it after
	// blocked, a query landing between the two loads could make it exceed
	// blocked. Assert cname <= blocked <= total on every read.
	c := New()

	stop := atomic.Bool{}
	var wg sync.WaitGroup

	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				// Mirror handler.go: RecordQuery first, then RecordCNAMEBlocked.
				c.RecordQuery("1.1.1.1", "metrics.shop.example.", true)
				c.RecordCNAMEBlocked()
			}
		}()
	}

	for range 5000 {
		s := c.Snapshot(0)
		if s.CNAMEBlockedCount > s.BlockedCount {
			t.Fatalf("invariant violated: cname=%d > blocked=%d", s.CNAMEBlockedCount, s.BlockedCount)
		}
		if s.BlockedCount > s.TotalQueries {
			t.Fatalf("invariant violated: blocked=%d > total=%d", s.BlockedCount, s.TotalQueries)
		}
	}
	stop.Store(true)
	wg.Wait()
}
