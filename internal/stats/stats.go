// Package stats tracks per-process query counters and top-N domain/client
// tallies. Counters are atomic; top-N maps are protected by a mutex.
// The package is safe for concurrent use and produces a JSON-serialisable
// Summary via Snapshot, consumed both by the periodic stdout printer and
// the REST API.
package stats

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Counter aggregates query statistics across the lifetime of the process.
// Total, blocked, and cache-hit counts are atomic; per-domain and per-client
// tallies are mutex-protected maps used for top-N reporting.
type Counter struct {
	total    atomic.Int64
	blocked  atomic.Int64
	cacheHit atomic.Int64
	start    time.Time

	mu         sync.Mutex
	topDomains map[string]int64 // blocked domain → block count
	topClients map[string]int64 // client IP → total query count
}

// Entry is a name/count pair used in top-N lists (domains and clients).
type Entry struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// Summary is the JSON-serialisable snapshot returned by Counter.Snapshot
// and surfaced by the REST API at /api/stats.
type Summary struct {
	Uptime       string  `json:"uptime"`
	TotalQueries int64   `json:"total_queries"`
	BlockedCount int64   `json:"blocked_count"`
	BlockedPct   float64 `json:"blocked_pct"`
	CacheHits    int64   `json:"cache_hits"`
	CacheHitPct  float64 `json:"cache_hit_pct"`
	TopDomains   []Entry `json:"top_domains"`
	TopClients   []Entry `json:"top_clients"`
}

// New returns a Counter with its start time set to now and empty top-N
// maps.
func New() *Counter {
	return &Counter{
		start:      time.Now(),
		topDomains: make(map[string]int64),
		topClients: make(map[string]int64),
	}
}

// RecordQuery records one DNS query. clientIP and domain are added to the
// top-N maps; if blocked, both the blocked counter and the top-blocked-
// domains tally are bumped.
//
// Ordering note: total.Add is performed before taking the mutex, so that
// snapshots that read blocked before total observe blocked ≤ total
// (see Snapshot).
func (c *Counter) RecordQuery(clientIP, domain string, blocked bool) {
	c.total.Add(1)
	c.mu.Lock()
	c.topClients[clientIP]++
	if blocked {
		c.blocked.Add(1)
		c.topDomains[domain]++
	}
	c.mu.Unlock()
}

// RecordCacheHit increments the cache-hit counter. Called from the DNS
// handler when a query is satisfied from the in-memory response cache.
func (c *Counter) RecordCacheHit() {
	c.cacheHit.Add(1)
}

// Snapshot returns a point-in-time summary with the top-n domains and clients.
//
// Load order matters: blocked must be read BEFORE total. RecordQuery increments
// total first, then increments blocked under the mutex. Reading in the opposite
// order can observe (total=N, blocked=N+k) when more queries complete between
// the two loads, producing a block rate >100% in the UI.
func (c *Counter) Snapshot(topN int) Summary {
	blocked := c.blocked.Load()
	total := c.total.Load()
	hits := c.cacheHit.Load()
	blockPct := 0.0
	if total > 0 {
		blockPct = float64(blocked) / float64(total) * 100
	}
	forwardable := total - blocked
	hitPct := 0.0
	if forwardable > 0 {
		hitPct = float64(hits) / float64(forwardable) * 100
	}
	return Summary{
		Uptime:       time.Since(c.start).Round(time.Second).String(),
		TotalQueries: total,
		BlockedCount: blocked,
		BlockedPct:   blockPct,
		CacheHits:    hits,
		CacheHitPct:  hitPct,
		TopDomains:   c.topN(c.topDomains, topN),
		TopClients:   c.topN(c.topClients, topN),
	}
}

func (c *Counter) topN(m map[string]int64, n int) []Entry {
	c.mu.Lock()
	entries := make([]Entry, 0, len(m))
	for k, v := range m {
		entries = append(entries, Entry{Name: k, Count: v})
	}
	c.mu.Unlock()

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})
	if n > 0 && len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// Print writes a human-readable one-line summary plus the top-5 blocked
// domains and top-5 clients to stdout. Called periodically by main.go
// (stats_interval) and once at shutdown.
func (c *Counter) Print() {
	s := c.Snapshot(5)
	fmt.Printf("[stats] uptime=%s total=%d blocked=%d (%.1f%%) cache-hits=%d (%.1f%%)\n",
		s.Uptime, s.TotalQueries, s.BlockedCount, s.BlockedPct, s.CacheHits, s.CacheHitPct)
	if len(s.TopDomains) > 0 {
		fmt.Println("[stats] top blocked domains:")
		for i, e := range s.TopDomains {
			fmt.Printf("[stats]   %d. %s (%d)\n", i+1, e.Name, e.Count)
		}
	}
	if len(s.TopClients) > 0 {
		fmt.Println("[stats] top clients:")
		for i, e := range s.TopClients {
			fmt.Printf("[stats]   %d. %s (%d queries)\n", i+1, e.Name, e.Count)
		}
	}
}
