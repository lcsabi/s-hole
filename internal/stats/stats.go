// Package stats tracks per-process query counters, top-N domain/client
// tallies, and the per-minute graph, which follows query_log.mode.
//
// total, cacheHit, localPTR, and localName are atomic and updated lock-free on
// the hot path. blocked is mutex-guarded because RecordQuery's critical section
// already takes the lock to update the top-domain tally; promoting it
// to atomic would be redundant and misleading. Snapshot reads blocked
// inside the same mutex and reads total/cacheHit lock-free.
//
// Top-N maps are protected by the mutex and capped at topNMaxEntries;
// when exceeded, the bottom half is pruned so memory stays bounded
// under long-running operation. The map *pointers* are read inside the
// lock by topN so a concurrent reassignment in RecordQuery does not
// race against Snapshot (R31).
//
// The package is safe for concurrent use and produces a
// JSON-serialisable Summary via Snapshot, which the REST API (/api/stats)
// serves. The periodic stats log line (Counter.Log) holds no counts.
package stats

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lcsabi/s-hole/internal/logging"
)

var logger = logging.For("stats")

// topNMaxEntries caps the per-domain and per-client tally maps so a
// long-running process does not accumulate every unique key forever.
// When a map exceeds this, prune() drops the least-frequent half,
// preserving high-traffic entries that operators care about. The chosen
// size is comfortably above any home-network domain diversity (~80 B
// per key × 4 096 ≈ 320 KiB per map) while bounded against pathological
// scenarios such as a misconfigured DNS scanner.
const topNMaxEntries = 4096

// Counter aggregates query statistics across the lifetime of the process.
// total, cacheHit, localPTR, and localName are atomic and updated lock-free on
// the hot path. blocked is mutex-guarded (incremented inside RecordQuery's critical
// section alongside the top-domain map update). Making it atomic too
// would be misleading dead optimisation. Snapshot reads it back inside
// the same lock. localPTR and localName are atomic alongside cacheHit: each is
// incremented after total, maintaining total ≥ localPTR + localName at all times.
//
// LOAD-ORDER INVARIANT (read this before adding a counter). Every per-query
// counter below (blocked, cnameBlocked, localPTR, localName, cacheHit,
// forwardFailures, upstreamErrors) is incremented AFTER RecordQuery bumps
// total. Snapshot must therefore read each of them BEFORE it reads total;
// otherwise a query completing between the two atomic loads makes the counter
// exceed the total captured alongside it, surfacing as a >100 % ratio on the
// dashboard. This exact mistake has regressed three times: b/021 (blocked),
// b/033 (localPTR), b/036 (cacheHit). If you add a counter that a query
// increments after total, load it before total in Snapshot and add a
// `*NeverExceeds*UnderLoad` regression test next to the existing ones.
// cnameBlocked is also a subset of blocked (RecordCNAMEBlocked runs after
// RecordQuery has counted the query as blocked), so Snapshot reads it before
// blocked as well.
type Counter struct {
	total           atomic.Int64
	cacheHit        atomic.Int64
	localPTR        atomic.Int64
	localName       atomic.Int64 // local-only names answered here (CL 94)
	forwardFailures atomic.Int64 // queries s-hole could not resolve (synthesized SERVFAIL)
	upstreamErrors  atomic.Int64 // relayed SERVFAIL/REFUSED from a live upstream
	cnameBlocked    atomic.Int64 // blocked because a CNAME target is blocked (CL 117)
	start           time.Time

	mu         sync.Mutex
	blocked    int64            // guarded by mu
	topDomains map[string]int64 // blocked domain → block count
	topClients map[string]int64 // client IP → total query count

	// timeline is the per-minute graph (see timeline.go). Its counts are not
	// part of the LOAD-ORDER INVARIANT: the graph shows counts, not ratios.
	// graphMode is query_log.mode, which decides what the graph records (see
	// SetQueryLogMode). The zero value records nothing.
	timeline  timeline
	graphMode string
}

// Entry is a name/count pair used in top-N lists (domains and clients).
type Entry struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// Summary is the JSON-serialisable snapshot returned by Counter.Snapshot
// and surfaced by the REST API at /api/stats.
type Summary struct {
	Uptime        string  `json:"uptime"`
	TotalQueries  int64   `json:"total_queries"`
	BlockedCount  int64   `json:"blocked_count"`
	BlockedPct    float64 `json:"blocked_pct"`
	LocalPTRCount int64   `json:"local_ptr_count"`
	// LocalNameCount counts queries for local-only names that s-hole answered
	// itself: localhost, a never-resolved name (.onion, .invalid, .alt), and
	// a LAN name while no upstream is on the LAN.
	LocalNameCount int64   `json:"local_name_count"`
	CacheHits      int64   `json:"cache_hits"`
	CacheHitPct    float64 `json:"cache_hit_pct"`
	// ForwardFailures counts queries s-hole could not resolve (every upstream
	// failed, so it synthesized a SERVFAIL). UpstreamErrors counts failure
	// rcodes (SERVFAIL/REFUSED) relayed from a live upstream. Both are subsets
	// of TotalQueries.
	ForwardFailures int64 `json:"forward_failures"`
	UpstreamErrors  int64 `json:"upstream_errors"`
	// CNAMEBlockedCount counts the blocked queries whose own name is on no
	// list but whose answer has a CNAME target on one. It is a subset of
	// BlockedCount.
	CNAMEBlockedCount int64 `json:"cname_blocked_count"`
	// BlocklistSize is the current number of domains in the block set.
	// Set by the API handler (not Counter.Snapshot) because the stats
	// package does not depend on the blocklist package.
	BlocklistSize int     `json:"blocklist_size"`
	TopDomains    []Entry `json:"top_domains"`
	TopClients    []Entry `json:"top_clients"`
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
// domains tally are bumped. An empty clientIP or domain is not tallied: the
// DNS handler passes "" when query_log.clients drops the client or when
// query_log.mode does not record the query, so the Top Clients and Top
// Domains lists hold only what the query log would hold. The counters are
// bumped either way.
//
// Ordering note: total.Add is performed before taking the mutex, so that
// snapshots that read blocked before total observe blocked ≤ total
// (see Snapshot).
func (c *Counter) RecordQuery(clientIP, domain string, blocked bool) {
	c.total.Add(1)
	if c.graphs(blocked) {
		b := c.timeline.at(time.Now())
		b.total.Add(1)
		if blocked {
			b.blocked.Add(1)
		}
	}
	c.mu.Lock()
	if clientIP != "" {
		c.topClients[clientIP]++
	}
	if blocked {
		c.blocked++
		if domain != "" {
			c.topDomains[domain]++
		}
	}
	// Cap the maps so a long-running process does not accumulate every
	// unique key forever. We prune lazily, only when a map exceeds the
	// cap, so the steady-state hot path stays at one map[++].
	if len(c.topClients) > topNMaxEntries {
		c.topClients = pruneBottomHalf(c.topClients)
	}
	if len(c.topDomains) > topNMaxEntries {
		c.topDomains = pruneBottomHalf(c.topDomains)
	}
	c.mu.Unlock()
}

// pruneBottomHalf returns a new map containing the upper-half of m by
// count value. Ties are broken arbitrarily (map iteration order); the
// dropped entries are exactly the low-frequency ones top-N is least
// interested in.
//
// We sort key/value pairs and keep the top len/2 rather than thresholding
// by value: when every count is equal (the pathological "every key seen
// once" case) thresholding would keep every entry and leave the map
// unbounded; see the regression test
// TestCounter_TopNMapsAreBounded.
func pruneBottomHalf(m map[string]int64) map[string]int64 {
	type kv struct {
		k string
		v int64
	}
	entries := make([]kv, 0, len(m))
	for k, v := range m {
		entries = append(entries, kv{k, v})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].v > entries[j].v })
	keep := len(entries) / 2
	out := make(map[string]int64, keep)
	for i := 0; i < keep; i++ {
		out[entries[i].k] = entries[i].v
	}
	return out
}

// ResetTallies empties the Top Domains and Top Clients lists, which name the
// domains and clients s-hole has seen. A purge calls it. The counters (total,
// blocked, cache hits, and so on) are not reset: they are counts, not
// history, and resetting them while queries are in flight could make a ratio
// exceed 100 % (see the LOAD-ORDER INVARIANT on Counter).
func (c *Counter) ResetTallies() {
	c.mu.Lock()
	c.topDomains = make(map[string]int64)
	c.topClients = make(map[string]int64)
	c.mu.Unlock()
}

// RecordCacheHit increments the cache-hit counter. Called from the DNS
// handler when a query is satisfied from the in-memory response cache.
func (c *Counter) RecordCacheHit() {
	c.cacheHit.Add(1)
	if c.graphs(false) {
		c.timeline.at(time.Now()).cached.Add(1)
	}
}

// RecordCNAMEBlocked records that a query was blocked because a CNAME target
// in its answer is blocked. The handler calls it after RecordQuery has counted
// the query as blocked, so it is a subset of the blocked counter.
func (c *Counter) RecordCNAMEBlocked() {
	c.cnameBlocked.Add(1)
}

// RecordLocalPTR increments the local-PTR counter. Called from the DNS
// handler after RecordQuery when a PTR query for a private reverse zone or
// the LAN's own IPv6 prefix is answered locally instead of being forwarded
// upstream. The caller must invoke RecordQuery first so that total ≥
// localPTR at all times.
func (c *Counter) RecordLocalPTR() {
	c.localPTR.Add(1)
}

// RecordLocalName increments the local-name counter. Called from the DNS
// handler after RecordQuery when s-hole answers a local-only name itself
// (localhost, .onion, .invalid, .alt, or a LAN name with no LAN upstream)
// instead of forwarding it. The caller must invoke RecordQuery first so that
// total ≥ localName at all times.
func (c *Counter) RecordLocalName() {
	c.localName.Add(1)
}

// RecordForwardFailure increments the unresolved-query counter. Called from
// the DNS handler after RecordQuery when every upstream failed and s-hole
// synthesized a SERVFAIL. The caller must invoke RecordQuery first so that
// total ≥ forwardFailures at all times.
func (c *Counter) RecordForwardFailure() {
	c.forwardFailures.Add(1)
	if c.graphs(false) {
		c.timeline.at(time.Now()).unresolved.Add(1)
	}
}

// RecordUpstreamError increments the relayed-failure counter. Called from the
// DNS handler after RecordQuery when a live upstream answered with a failure
// rcode (SERVFAIL/REFUSED) that s-hole relayed. The caller must invoke
// RecordQuery first so that total ≥ upstreamErrors at all times.
func (c *Counter) RecordUpstreamError() {
	c.upstreamErrors.Add(1)
	if c.graphs(false) {
		c.timeline.at(time.Now()).upstreamError.Add(1)
	}
}

// topNTarget selects which of the two tally maps Snapshot/topN reads.
// We pass an enum rather than the map pointer itself so the map header is
// read under c.mu; see R31. Reading c.topDomains as a function argument
// races against the c.topDomains = pruneBottomHalf(...) write that
// RecordQuery performs while it holds the lock.
type topNTarget int

const (
	topNDomains topNTarget = iota
	topNClients
)

// Snapshot returns a point-in-time summary with the top-n domains and clients.
//
// Load order matters: every counter that a single query increments AFTER
// total must be read BEFORE total, or a concurrent query completing between
// two loads can make the later-incremented counter exceed the total we
// captured. RecordQuery increments total, then blocked (under mu); the PTR
// path additionally calls RecordLocalPTR after RecordQuery, and the
// local-name path calls RecordLocalName after RecordQuery; the cache-hit path
// calls RecordCacheHit after RecordQuery; the forward path calls
// RecordForwardFailure or RecordUpstreamError after RecordQuery; the CNAME
// path calls RecordCNAMEBlocked after RecordQuery counted it as blocked. So
// blocked, localPTR, localName, cacheHit, forwardFailures, and upstreamErrors
// are all read before total, the b/021 fix, extended to localPTR (b/033),
// cacheHit (b/036), the two failure counters (CL 77), and localName (CL 94),
// and cnameBlocked is read before blocked (CL 117). This keeps
// total ≥ blocked + localPTR + localName, cnameBlocked ≤ blocked, and
// hits ≤ forwardable on every snapshot, so forwardable below can never go
// negative and CacheHitPct can never exceed 100 %. The cache-hit denominator
// excludes blocked, localPTR, and localName because none of these queries is
// served as an allowed answer: a query blocked by its CNAME target reads the
// cache or the upstream, but it is counted as blocked, never as a cache hit.
func (c *Counter) Snapshot(topN int) Summary {
	cnameBlocked := c.cnameBlocked.Load()
	c.mu.Lock()
	blocked := c.blocked
	c.mu.Unlock()
	localPTR := c.localPTR.Load()
	localName := c.localName.Load()
	hits := c.cacheHit.Load()
	forwardFailures := c.forwardFailures.Load()
	upstreamErrors := c.upstreamErrors.Load()
	total := c.total.Load()
	blockPct := 0.0
	if total > 0 {
		blockPct = float64(blocked) / float64(total) * 100
	}
	forwardable := total - blocked - localPTR - localName
	hitPct := 0.0
	if forwardable > 0 {
		hitPct = float64(hits) / float64(forwardable) * 100
	}
	return Summary{
		Uptime:            time.Since(c.start).Round(time.Second).String(),
		TotalQueries:      total,
		BlockedCount:      blocked,
		BlockedPct:        blockPct,
		LocalPTRCount:     localPTR,
		LocalNameCount:    localName,
		CacheHits:         hits,
		CacheHitPct:       hitPct,
		ForwardFailures:   forwardFailures,
		UpstreamErrors:    upstreamErrors,
		CNAMEBlockedCount: cnameBlocked,
		TopDomains:        c.topN(topNDomains, topN),
		TopClients:        c.topN(topNClients, topN),
	}
}

func (c *Counter) topN(target topNTarget, n int) []Entry {
	c.mu.Lock()
	// Resolve the map *inside* the lock; otherwise reading c.topDomains
	// at the call site would race against RecordQuery's pruneBottomHalf
	// reassignment (R31 regression).
	var m map[string]int64
	switch target {
	case topNDomains:
		m = c.topDomains
	case topNClients:
		m = c.topClients
	}
	entries := make([]Entry, 0, len(m))
	for k, v := range m {
		entries = append(entries, Entry{Name: k, Count: v})
	}
	c.mu.Unlock()

	// Sort by count descending, then by name ascending. The name tie-break is
	// required, not cosmetic: entries is built from a Go map, whose iteration
	// order is randomized, so a count-only sort orders equal-count entries
	// differently on every call and the dashboard's "Since start" list reshuffles
	// ties on every poll (b/056). sort.Slice is not stable either, so the
	// secondary key, not input order, is what pins the order.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Name < entries[j].Name
	})
	if n > 0 && len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// Log writes the periodic stats line: one INFO line (msg=stats) with the
// uptime only. Called periodically by cmd/s-hole/main.go (stats_interval) and
// once at shutdown. The line holds no counts: the difference between two
// lines would give the number of queries in each interval, a record of when
// the household is active, and the system journal keeps it where retention
// and purge cannot reach (b/098). The dashboard and /metrics show the counts.
func (c *Counter) Log() {
	logger.Info("stats", "uptime", time.Since(c.start).Round(time.Second).String())
}
