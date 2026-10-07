// Package cache provides a TTL-based in-memory DNS response cache.
// It is the primary latency and upstream-load optimisation for low-power
// deployments (Raspberry Pi, etc.) where upstream round-trips are expensive.
//
// A key is (qname, qtype, qclass) plus the query's CD and DO bits. Qclass
// keeps cross-class queries (e.g. ClassCHAOS version.bind TXT) from colliding
// with the dominant ClassINET traffic; the bits change the upstream's answer
// (b/096). An entry lives at most maxTTL, whatever TTL the upstream gave.
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

// maxTTL caps how long an answer stays in the cache: 86,400 s (one day),
// Unbound's default cache-max-ttl. A bad answer, or one with a huge TTL from
// a broken upstream, then leaves the cache within a day. Set also lowers each
// stored record's TTL to the cap, so a client is not told to keep the answer
// longer than s-hole does.
const maxTTL = 86400

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

// Get returns a cloned response for the query req with TTLs decremented, or
// (nil, false). req is the client's query; its question and its CD and DO
// bits pick the entry (see key).
func (c *Cache) Get(req *dns.Msg) (*dns.Msg, bool) {
	k, ok := keyOf(req)
	if !ok {
		c.misses.Add(1)
		return nil, false
	}

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

// Set caches msg, the reply to the query req, if it has a non-zero TTL and
// answers present. The entry is found again only by a query with the same
// question and the same CD and DO bits (see key). Truncated messages are
// never cached: their answer section is incomplete, and replaying one for its
// full TTL would pin every client on the partial answer even after a TCP
// retry could fetch the real one.
func (c *Cache) Set(req, msg *dns.Msg) {
	if msg.Rcode != dns.RcodeSuccess || msg.Truncated || len(msg.Answer) == 0 {
		return
	}
	if minAnswerTTL(msg) == 0 {
		return
	}
	k, ok := keyOf(req)
	if !ok {
		return
	}

	stored := msg.Copy()
	capTTLs(stored, maxTTL)
	e := &entry{
		msg:    stored,
		cached: time.Now(),
		minTTL: minAnswerTTL(stored),
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

// Flush deletes every cached answer. A purge calls it: the cache is a short
// history of the names the network looked up. The hit, miss, and drop
// counters are kept.
func (c *Cache) Flush() {
	c.mu.Lock()
	c.entries = make(map[string]*entry, c.maxSize)
	c.mu.Unlock()
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
// shole_cache_dropped_total; a sustained non-zero rate means dns.cache_entries is too
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

// keyOf returns the cache key for the client query req, or false when req
// does not hold exactly one question. The handler answers such a query
// itself, so it never reaches the cache.
func keyOf(req *dns.Msg) (string, bool) {
	if len(req.Question) != 1 {
		return "", false
	}
	do := false
	if opt := req.IsEdns0(); opt != nil {
		do = opt.Do()
	}
	return key(req.Question[0], req.CheckingDisabled, do), true
}

// keyBits is the last part of a cache key: the query's CD and DO bits, at
// index cd + 2*do.
var keyBits = [4]string{"\x00--", "\x00c-", "\x00-d", "\x00cd"}

// key builds the cache key from (qname, qtype, qclass) and the query's CD
// and DO bits. The handler sends both bits upstream (see upstreamQuery in
// dnsserver), and both change the reply. With CD (checking disabled) set, a
// validating upstream returns data that failed DNSSEC validation, so a CD=1
// reply must never reach a client that asked with CD=0: one CD=1 query would
// otherwise turn off validation for the whole network until the entry
// expires. With DO (DNSSEC OK) set, the reply holds RRSIG records, and a
// validating client that asked with DO=1 fails without them (b/096). The AD
// bit is not in the key: it only asks the upstream to report the AD bit. The
// RD bit is not either: the handler refuses a query with RD=0.
//
// The Type/Class String methods fall back to "TYPE1234"/"CLASS1234" for
// codes without a mnemonic; a bare TypeToString map lookup would render every unknown
// code as "", letting two distinct unknown qtypes collide on one key and
// serve each other's cached answers (T6).
//
// The qname keeps its wire-format case on purpose. A dns-0x20 forwarder
// randomizes case and rejects a reply whose question name does not echo the
// exact case it sent, so the key must not fold "Example.com" and "example.com"
// together (b/037). TestCache_KeyIsCaseSensitive guards this.
func key(q dns.Question, cd, do bool) string {
	bits := 0
	if cd {
		bits |= 1
	}
	if do {
		bits |= 2
	}
	return q.Name + "\x00" + dns.Type(q.Qtype).String() + "\x00" + dns.Class(q.Qclass).String() + keyBits[bits]
}

// decrementTTLs ages the cached records by elapsed seconds. It skips the
// EDNS0 OPT record: OPT has no TTL, and its TTL field holds the extended
// rcode, the EDNS version, and the DO flag. Decrementing it cleared DO after
// a few seconds and wrote junk into the flag bits, so a client that asked
// for DNSSEC records got a reply that said it had not (b/072).
func decrementTTLs(msg *dns.Msg, elapsed uint32) {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			hdr := rr.Header()
			if hdr.Ttl > elapsed {
				hdr.Ttl -= elapsed
			} else {
				hdr.Ttl = 0
			}
		}
	}
}

// capTTLs lowers every record TTL above limit to limit. Like decrementTTLs,
// it skips the OPT record, whose TTL field holds flags.
func capTTLs(msg *dns.Msg, limit uint32) {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if hdr := rr.Header(); hdr.Rrtype != dns.TypeOPT && hdr.Ttl > limit {
				hdr.Ttl = limit
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
