// Package cache provides a TTL-based in-memory DNS response cache.
// It is the primary latency and upstream-load optimisation for low-power
// deployments (Raspberry Pi, etc.) where upstream round-trips are expensive.
//
// Keys are (qname, qtype, qclass) so cross-class queries (e.g. ClassCHAOS
// version.bind TXT) cannot collide with the dominant ClassINET traffic.
// Hit/miss counters are atomic so reads do not contend on the entries
// mutex on the hot path. A background goroutine sweeps expired entries
// once a minute (cleanupExpired); Close stops it cleanly.
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
// When the cache is full, new entries are silently dropped.
//
// hits and misses are atomic so Get and Stats do not contend on the
// entries mutex; the entries map itself stays RWMutex-guarded.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*entry
	maxSize int
	stop    chan struct{}

	hits   atomic.Uint64
	misses atomic.Uint64
}

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

	if !ok || time.Since(e.cached) >= time.Duration(e.minTTL)*time.Second {
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
	if len(c.entries) < c.maxSize {
		c.entries[k] = e
	}
	c.mu.Unlock()
}

// Stats returns (hits, misses, current size).
func (c *Cache) Stats() (hits, misses uint64, size int) {
	c.mu.RLock()
	size = len(c.entries)
	c.mu.RUnlock()
	return c.hits.Load(), c.misses.Load(), size
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
		if now.Sub(e.cached) >= time.Duration(e.minTTL)*time.Second {
			delete(c.entries, k)
			removed++
		}
	}
	return removed
}

// key builds the cache key from (qname, qtype, qclass). The Type/Class
// String methods fall back to "TYPE1234"/"CLASS1234" for codes without a
// mnemonic; a bare TypeToString map lookup would render every unknown
// code as "", letting two distinct unknown qtypes collide on one key and
// serve each other's cached answers (T6).
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
	min := ^uint32(0)
	for _, rr := range msg.Answer {
		if t := rr.Header().Ttl; t < min {
			min = t
		}
	}
	if min == ^uint32(0) {
		return 0
	}
	return min
}
