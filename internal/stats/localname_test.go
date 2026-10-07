package stats

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// CL 94 R9: a local answer (localhost, a never-resolved name, or a LAN-only
// name with no LAN upstream) is recorded as RecordQuery, then
// RecordLocalName.

func TestCounter_RecordLocalName(t *testing.T) {
	// CL 94 R9: a local name counts once in the total and once in
	// LocalNameCount, and never as blocked or as a local PTR.
	c := New()
	for i := 0; i < 3; i++ {
		c.RecordQuery("", "", false)
		c.RecordLocalName()
	}
	s := c.Snapshot(0)
	if s.TotalQueries != 3 || s.LocalNameCount != 3 || s.BlockedCount != 0 || s.LocalPTRCount != 0 || s.CacheHits != 0 {
		t.Errorf("snapshot = total %d, local names %d, blocked %d, local PTR %d, cache %d; want 3, 3, 0, 0, 0",
			s.TotalQueries, s.LocalNameCount, s.BlockedCount, s.LocalPTRCount, s.CacheHits)
	}
	if s.BlockedPct != 0 {
		t.Errorf("BlockedPct = %v, want 0", s.BlockedPct)
	}
}

func TestSummary_LocalNameCountJSON(t *testing.T) {
	// CL 94 R9: /api/stats carries the counter as "local_name_count".
	c := New()
	c.RecordQuery("", "", false)
	c.RecordLocalName()
	b, err := json.Marshal(c.Snapshot(0))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["local_name_count"] != float64(1) {
		t.Errorf("local_name_count = %#v in %s, want 1", m["local_name_count"], b)
	}
}

func TestCounter_CacheHitPctExcludesLocalNames(t *testing.T) {
	// CL 94 R9: local names never reach the cache, so the cache-hit
	// denominator leaves them out. 4 local names and 2 forwardable queries,
	// one of them a cache hit, give 50 %.
	c := New()
	for i := 0; i < 4; i++ {
		c.RecordQuery("", "", false)
		c.RecordLocalName()
	}
	c.RecordQuery("", "", false)
	c.RecordCacheHit()
	c.RecordQuery("", "", false)
	if s := c.Snapshot(0); s.CacheHitPct != 50 {
		t.Errorf("CacheHitPct = %v, want 50", s.CacheHitPct)
	}
}

func TestCounter_LogHasLocalNames(t *testing.T) {
	// CL 94 R9: the stats log line has local_names.
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))

	c := New()
	for i := 0; i < 2; i++ {
		c.RecordQuery("", "", false)
		c.RecordLocalName()
	}
	c.Log()
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatalf("log line is not one JSON record: %q: %v", buf.String(), err)
	}
	if rec["local_names"] != float64(2) {
		t.Errorf("local_names = %#v, want 2", rec["local_names"])
	}
}

func TestCounter_LocalNameNeverExceedsTotalUnderLoad(t *testing.T) {
	// CL 94 R9, the b/021 pattern applied to the local-name counter. The
	// handler records a local answer as RecordQuery, then RecordLocalName,
	// so localName is the later counter. Snapshot must read it before total,
	// or a query between the two loads can make localName > total.
	c := New()
	stop := atomic.Bool{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				c.RecordQuery("", "", false)
				c.RecordLocalName()
			}
		}()
	}
	for range 5000 {
		s := c.Snapshot(0)
		if s.LocalNameCount > s.TotalQueries {
			t.Fatalf("invariant violated: localName=%d > total=%d", s.LocalNameCount, s.TotalQueries)
		}
	}
	stop.Store(true)
	wg.Wait()
}

func TestCounter_CacheHitRateWithLocalNamesNeverExceeds100UnderLoad(t *testing.T) {
	// CL 94 R9: local-name queries and cache hits run at the same time. The
	// cache-hit denominator is total minus blocked, local PTR, and local
	// names, so a wrong load order can push CacheHitPct over 100 %.
	c := New()
	stop := atomic.Bool{}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if i%2 == 0 {
					c.RecordQuery("", "", false)
					c.RecordLocalName()
				} else {
					c.RecordQuery("", "", false)
					c.RecordCacheHit()
				}
			}
		}()
	}
	for range 5000 {
		s := c.Snapshot(0)
		if s.CacheHitPct > 100 {
			t.Fatalf("CacheHitPct = %v exceeds 100%% (hits=%d total=%d localNames=%d)",
				s.CacheHitPct, s.CacheHits, s.TotalQueries, s.LocalNameCount)
		}
		if s.LocalNameCount+s.CacheHits > s.TotalQueries {
			t.Fatalf("local names %d + cache hits %d > total %d", s.LocalNameCount, s.CacheHits, s.TotalQueries)
		}
	}
	stop.Store(true)
	wg.Wait()
}
