package stats

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Counter struct {
	total    atomic.Int64
	blocked  atomic.Int64
	cacheHit atomic.Int64
	start    time.Time

	mu         sync.Mutex
	topDomains map[string]int64 // blocked domain → block count
	topClients map[string]int64 // client IP → total query count
}

type Entry struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

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

func New() *Counter {
	return &Counter{
		start:      time.Now(),
		topDomains: make(map[string]int64),
		topClients: make(map[string]int64),
	}
}

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

func (c *Counter) RecordCacheHit() {
	c.cacheHit.Add(1)
}

// Snapshot returns a point-in-time summary with the top-n domains and clients.
func (c *Counter) Snapshot(topN int) Summary {
	total := c.total.Load()
	blocked := c.blocked.Load()
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
