// Package cache provides a TTL-based in-memory DNS response cache.
// It is the primary latency and upstream-load optimisation for low-power
// deployments (Raspberry Pi, etc.) where upstream round-trips are expensive.
//
// Keys are (qname, qtype, qclass) so cross-class queries (e.g. ClassCHAOS
// version.bind TXT) cannot collide with the dominant ClassINET traffic.
// Hit, miss, and drop counters are atomic so reads do not contend on the
// entries mutex on the hot path. A background goroutine sweeps expired
// entries once a minute (cleanupExpired); Close stops it cleanly.
package cache

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type entry struct {
	msg    *dns.Msg
	cached time.Time
	minTTL uint32 // smallest TTL seen in Answer section at cache time
}

// Cache is a thread-safe, size-bounded DNS response cache.
// Entries expire after their DNS TTL elapses.
// When the cache is full, Set reclaims an expired entry if a bounded scan
// finds one, and otherwise drops the new entry (counted by Dropped).
//
// hits, misses, and dropped are atomic so Get, Stats, and Dropped do not
// contend on the entries mutex; the entries map itself stays RWMutex-guarded.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*entry
	maxSize int
	stop    chan struct{}

	hits    atomic.Uint64
	misses  atomic.Uint64
	dropped atomic.Uint64
}

// reclaimScanLimit bounds the on-insert expired-entry scan in Set. A full
// cache probes at most this many entries looking for one to reclaim before
// it drops the new entry. Go randomizes map iteration order, so the bounded
// scan samples the map rather than always probing the same entries.
const reclaimScanLimit = 8

// New returns a Cache holding at most maxSize entries and starts the
// background cleanup goroutine. Callers must invoke Close on shutdown to
// stop that goroutine cleanly; otherwise it lives as long as the process.
func New(maxSize int) *Cache {
	c := &Cache{
		entries: make(map[string]*entry, maxSize),
		maxSize: maxSize,
		stop:    make(chan struct{}),
	}
	go c.runCleanup()
	return c
}

// Close stops the background cleanup goroutine.
func (c *Cache) Close() {
	close(c.stop)
}

// Get returns a cloned response for q with TTLs decremented, or (nil, false).
func (c *Cache) Get(q dns.Question) (*dns.Msg, bool) {
	k := key(q)

	c.mu.RLock()
	e, ok := c.entries[k]
	c.mu.RUnlock()

	if !ok || isExpired(e, time.Now()) {
		c.misses.Add(1)
		return nil, false
	}

	msg := e.msg.Copy()
	decrementTTLs(msg, uint32(time.Since(e.cached).Seconds()))

	c.hits.Add(1)
	return msg, true
}

// Set caches msg for question q if it has a non-zero TTL and answers present.
// Truncated messages are never cached: their answer section is incomplete,
// and replaying one for its full TTL would pin every client on the partial
// answer even after a TCP retry could fetch the real one.
func (c *Cache) Set(q dns.Question, msg *dns.Msg) {
	if msg.Rcode != dns.RcodeSuccess || msg.Truncated || len(msg.Answer) == 0 {
		return
	}
	minTTL := minAnswerTTL(msg)
	if minTTL == 0 {
		return
	}

	k := key(q)
	e := &entry{
		msg:    msg.Copy(),
		cached: time.Now(),
		minTTL: minTTL,
	}

	c.mu.Lock()
	if len(c.entries) >= c.maxSize {
		// Full. Get treats expired entries as misses but does not delete
		// them, so a cache full of not-yet-swept corpses would refuse every
		// insert until the once-a-minute cleanupExpired runs. Reclaim one
		// expired slot cheaply before giving up. A cache full of live entries
		// finds nothing to reclaim and drops below, which is the honest
		// capacity signal Dropped reports.
		c.reclaimOneExpired(e.cached)
	}
	if len(c.entries) < c.maxSize {
		c.entries[k] = e
	} else {
		c.dropped.Add(1)
	}
	c.mu.Unlock()
}

// reclaimOneExpired deletes one expired entry to free a slot for an insert,
// scanning at most reclaimScanLimit entries. The caller must hold the write
// lock. It is a best-effort heuristic: if the bounded sample finds no expired
// entry, the cache is near capacity in live entries and the caller drops,
// which is correct. O(reclaimScanLimit), far cheaper than the full O(n)
// cleanupExpired sweep on every full insert.
func (c *Cache) reclaimOneExpired(now time.Time) {
	scanned := 0
	for k, e := range c.entries {
		if isExpired(e, now) {
			delete(c.entries, k)
			return
		}
		scanned++
		if scanned >= reclaimScanLimit {
			return
		}
	}
}

// Stats returns (hits, misses, current size).
func (c *Cache) Stats() (hits, misses uint64, size int) {
	c.mu.RLock()
	size = len(c.entries)
	c.mu.RUnlock()
	return c.hits.Load(), c.misses.Load(), size
}

// Dropped returns the cumulative number of entries Set refused because the
// cache was full of live (not-yet-expired) entries. Surfaced via /metrics as
// shole_cache_dropped_total; a sustained non-zero rate means cache_size is too
// small for the working set. Inserts that reclaimed an expired slot are not
// counted, so this reports real capacity pressure, not sweep-timing noise.
func (c *Cache) Dropped() uint64 {
	return c.dropped.Load()
}

func (c *Cache) runCleanup() {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			c.cleanupExpired(time.Now())
		case <-c.stop:
			return
		}
	}
}

// cleanupExpired removes entries whose minTTL has elapsed since they were
// cached. Returns the count removed. Extracted from runCleanup so tests
// can exercise the sweep deterministically without waiting on the
// 1-minute ticker.
func (c *Cache) cleanupExpired(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for k, e := range c.entries {
		if isExpired(e, now) {
			delete(c.entries, k)
			removed++
		}
	}
	return removed
}

// isExpired reports whether e's DNS TTL has elapsed as of now. One definition
// shared by Get (lazy expiry on read), cleanupExpired (the periodic sweep),
// and reclaimOneExpired (the on-insert reclaim), so the three cannot disagree
// about when an entry is dead.
func isExpired(e *entry, now time.Time) bool {
	return now.Sub(e.cached) >= time.Duration(e.minTTL)*time.Second
}

// key builds the cache key from (qname, qtype, qclass). The Type/Class
// String methods fall back to "TYPE1234"/"CLASS1234" for codes without a
// mnemonic; a bare TypeToString map lookup would render every unknown
// code as "", letting two distinct unknown qtypes collide on one key and
// serve each other's cached answers (T6).
//
// The qname keeps its wire-format case on purpose. A dns-0x20 forwarder
// randomizes case and rejects a reply whose question name does not echo the
// exact case it sent, so the key must not fold "Example.com" and "example.com"
// together (b/037). TestCache_KeyIsCaseSensitive guards this.
func key(q dns.Question) string {
	return q.Name + "\x00" + dns.Type(q.Qtype).String() + "\x00" + dns.Class(q.Qclass).String()
}

func decrementTTLs(msg *dns.Msg, elapsed uint32) {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Ttl > elapsed {
				hdr.Ttl -= elapsed
			} else {
				hdr.Ttl = 0
			}
		}
	}
}

func minAnswerTTL(msg *dns.Msg) uint32 {
	// Named smallest, not min, so it does not shadow the predeclared builtin
	// min (Go 1.21+); a later edit calling builtin min in scope would otherwise
	// bind to this uint32 local by mistake.
	smallest := ^uint32(0)
	for _, rr := range msg.Answer {
		if t := rr.Header().Ttl; t < smallest {
			smallest = t
		}
	}
	if smallest == ^uint32(0) {
		return 0
	}
	return smallest
}
