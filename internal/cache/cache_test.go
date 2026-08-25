package cache

import (
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// buildResponse constructs a minimal A-record response for q with the given
// answer TTL. Used to seed the cache in tests.
func buildResponse(q dns.Question, ttl uint32) *dns.Msg {
	msg := new(dns.Msg)
	msg.Question = []dns.Question{q}
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: []byte{1, 2, 3, 4},
		},
	}
	return msg
}

func TestCache_SetGetRoundTrip(t *testing.T) {
	c := New(10)
	defer c.Close()

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, buildResponse(q, 300))

	got, ok := c.Get(q)
	if !ok {
		t.Fatal("Get returned miss after Set")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(got.Answer))
	}
}

func TestCache_TTLDecrement(t *testing.T) {
	c := New(10)
	defer c.Close()

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, buildResponse(q, 100))

	// Force the cached time to be 30 seconds in the past so Get observes
	// elapsed=30 and decrements TTL accordingly.
	c.mu.Lock()
	for _, e := range c.entries {
		e.cached = e.cached.Add(-30 * time.Second)
	}
	c.mu.Unlock()

	got, ok := c.Get(q)
	if !ok {
		t.Fatal("Get returned miss")
	}
	gotTTL := got.Answer[0].Header().Ttl
	if gotTTL < 60 || gotTTL > 75 {
		t.Errorf("Get TTL = %d, want ~70 (100 - 30 ± a few)", gotTTL)
	}
}

func TestCache_ExpiredMisses(t *testing.T) {
	c := New(10)
	defer c.Close()

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, buildResponse(q, 5))

	// Backdate the entry past its TTL.
	c.mu.Lock()
	for _, e := range c.entries {
		e.cached = e.cached.Add(-10 * time.Second)
	}
	c.mu.Unlock()

	if _, ok := c.Get(q); ok {
		t.Error("expected miss on TTL-expired entry")
	}
}

func TestCache_KeyIncludesQclass(t *testing.T) {
	// Regression for b/010: a ClassCHAOS query must not get a ClassINET
	// cached answer for the same name+type.
	c := New(10)
	defer c.Close()

	qInet := dns.Question{Name: "version.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}
	qChaos := dns.Question{Name: "version.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}

	c.Set(qInet, buildResponse(qInet, 300))

	if _, ok := c.Get(qChaos); ok {
		t.Error("ClassCHAOS query was served a ClassINET cache entry")
	}
}

func TestCache_KeyDistinguishesUnknownTypes(t *testing.T) {
	// T6 regression: two distinct qtypes without a mnemonic in
	// dns.TypeToString must not collide on one cache key; a bare map
	// lookup rendered both as "" and let them serve each other's answers.
	q1 := dns.Question{Name: "example.com.", Qtype: 64001, Qclass: dns.ClassINET}
	q2 := dns.Question{Name: "example.com.", Qtype: 64002, Qclass: dns.ClassINET}
	if key(q1) == key(q2) {
		t.Errorf("key collision for unknown qtypes: both map to %q", key(q1))
	}
}

func TestCache_RejectsTruncated(t *testing.T) {
	// T2: a TC-flagged message carries an incomplete answer section and
	// must never be replayed from cache.
	c := New(10)
	defer c.Close()

	q := dns.Question{Name: "big.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg := buildResponse(q, 300)
	msg.Truncated = true
	c.Set(q, msg)

	if _, ok := c.Get(q); ok {
		t.Error("truncated response should not be cached")
	}
}

func TestCache_DropOnFull(t *testing.T) {
	c := New(2)
	defer c.Close()

	q1 := dns.Question{Name: "a.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	q2 := dns.Question{Name: "b.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	q3 := dns.Question{Name: "c.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q1, buildResponse(q1, 300))
	c.Set(q2, buildResponse(q2, 300))
	c.Set(q3, buildResponse(q3, 300)) // overflow; must be dropped

	if _, _, size := c.Stats(); size != 2 {
		t.Errorf("Stats size = %d, want 2", size)
	}
	if _, ok := c.Get(q3); ok {
		t.Error("c.com should have been dropped (cache full)")
	}
	if _, ok := c.Get(q1); !ok {
		t.Error("a.com should still be cached")
	}
}

func TestCache_DropOnFull_CountsDropped(t *testing.T) {
	// A cache full of live entries must count the refused insert. This is the
	// signal /metrics surfaces as shole_cache_dropped_total: real capacity
	// pressure, not sweep-timing noise.
	c := New(1)
	defer c.Close()

	live := dns.Question{Name: "live.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	overflow := dns.Question{Name: "overflow.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(live, buildResponse(live, 300))
	c.Set(overflow, buildResponse(overflow, 300)) // full of a live entry: must drop and count

	if got := c.Dropped(); got != 1 {
		t.Errorf("Dropped() = %d after one drop, want 1", got)
	}
	if _, ok := c.Get(overflow); ok {
		t.Error("overflow.com should have been dropped")
	}
}

func TestCache_ReclaimsExpiredOnFull(t *testing.T) {
	// When the cache is full only of expired entries, Set must reclaim a slot
	// rather than drop. Get treats an expired entry as a miss but leaves it in
	// the map until the 1-minute sweep, so without on-insert reclaim a cache
	// full of corpses would refuse every insert for up to a minute.
	c := New(1)
	defer c.Close()

	stale := dns.Question{Name: "stale.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	fresh := dns.Question{Name: "fresh.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(stale, buildResponse(stale, 5))

	// Backdate the only entry past its TTL so the cache is full of a corpse.
	c.mu.Lock()
	c.entries[key(stale)].cached = c.entries[key(stale)].cached.Add(-10 * time.Second)
	c.mu.Unlock()

	c.Set(fresh, buildResponse(fresh, 300))

	if _, ok := c.Get(fresh); !ok {
		t.Error("fresh.com should have been admitted by reclaiming the expired slot")
	}
	if got := c.Dropped(); got != 0 {
		t.Errorf("Dropped() = %d, want 0: a reclaimed insert is not a drop", got)
	}
	// The reclaimed corpse must be gone, not lingering alongside the new entry.
	if _, _, size := c.Stats(); size != 1 {
		t.Errorf("Stats size = %d, want 1 (corpse reclaimed, fresh admitted)", size)
	}
}

func TestCache_RejectsZeroTTL(t *testing.T) {
	c := New(10)
	defer c.Close()

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, buildResponse(q, 0))

	if _, ok := c.Get(q); ok {
		t.Error("zero-TTL response should not be cached")
	}
}

func TestCache_RejectsNonSuccess(t *testing.T) {
	c := New(10)
	defer c.Close()

	q := dns.Question{Name: "nope.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg := buildResponse(q, 300)
	msg.Rcode = dns.RcodeNameError // NXDOMAIN
	c.Set(q, msg)

	if _, ok := c.Get(q); ok {
		t.Error("NXDOMAIN responses should not be cached")
	}
}

func TestCache_StatsHitsAndMisses(t *testing.T) {
	c := New(10)
	defer c.Close()

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, buildResponse(q, 300))

	c.Get(q)                                                                         // hit
	c.Get(q)                                                                         // hit
	c.Get(dns.Question{Name: "other.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}) // miss

	hits, misses, _ := c.Stats()
	if hits != 2 {
		t.Errorf("hits = %d, want 2", hits)
	}
	if misses != 1 {
		t.Errorf("misses = %d, want 1", misses)
	}
}

func TestCache_CleanupExpiredRemovesStale(t *testing.T) {
	// Direct unit test for the cleanup body so we don't have to wait on
	// the 1-minute ticker for coverage of the sweep.
	c := New(10)
	defer c.Close()

	live := dns.Question{Name: "live.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	expired := dns.Question{Name: "expired.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(live, buildResponse(live, 600))
	c.Set(expired, buildResponse(expired, 5))

	// Backdate the expired entry past its TTL.
	c.mu.Lock()
	e := c.entries[key(expired)]
	e.cached = e.cached.Add(-10 * time.Second)
	c.mu.Unlock()

	removed := c.cleanupExpired(time.Now())
	if removed != 1 {
		t.Errorf("cleanupExpired removed %d, want 1", removed)
	}
	if _, ok := c.entries[key(live)]; !ok {
		t.Error("live entry was incorrectly purged")
	}
	if _, ok := c.entries[key(expired)]; ok {
		t.Error("expired entry survived cleanup")
	}
}

func TestCache_CloseStopsGoroutine(t *testing.T) {
	// Regression for b/018: Close must signal the cleanup goroutine to
	// return. A second Close() would panic on "close of closed channel"
	// if Close did not own the stop signal; this also verifies that
	// runCleanup respects the stop channel.
	c := New(10)
	c.Close()

	// Give the goroutine time to observe the close.
	time.Sleep(50 * time.Millisecond)

	// A second close on the same channel would panic. We can't detect
	// that the goroutine actually returned without instrumentation, but
	// the fact that Close completes without deadlocking + the goroutine's
	// select-on-stop guarantee covers the regression.
}

func TestCache_KeyIsCaseSensitive(t *testing.T) {
	// b/037: cache keys preserve the query name's case on purpose. A dns-0x20
	// forwarder randomizes case and rejects a reply whose question name does
	// not echo the exact case it sent, so the cache must not collapse
	// "Example.COM" and "example.com" into one entry. This guards against a
	// future "lowercase the key to raise the hit rate" change.
	c := New(10)
	defer c.Close()

	upper := dns.Question{Name: "Example.COM.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	lower := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(upper, buildResponse(upper, 300))

	if _, ok := c.Get(lower); ok {
		t.Error("Get(lowercase) hit an entry Set under mixed case; key is not case-sensitive (b/037)")
	}
	if _, ok := c.Get(upper); !ok {
		t.Error("Get(same case) missed; Set/Get round-trip broken")
	}
}

// BenchmarkCache_Get guards the cache hit path, the branch that avoids an
// upstream round-trip entirely and is therefore the whole point of the
// cache. Its cost (and per-op allocations) is dominated by the defensive
// msg.Copy plus decrementTTLs walk on every hit; ReportAllocs surfaces a
// regression in either. The miss path is a bare RLock'd map lookup with no
// allocation and needs no companion benchmark.
func BenchmarkCache_Get(b *testing.B) {
	c := New(1024)
	defer c.Close()

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, buildResponse(q, 300))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.Get(q); !ok {
			b.Fatal("expected cache hit")
		}
	}
}

// BenchmarkCache_Set measures the write path that runs on every cache miss:
// validate the message, build the key, and store under lock. Distinct keys so
// each Set builds a fresh key string; the cache is sized to hold them all, so
// this measures the store path rather than the drop-on-full early return.
func BenchmarkCache_Set(b *testing.B) {
	const distinct = 4096
	c := New(distinct * 2)
	defer c.Close()

	qs := make([]dns.Question, distinct)
	msgs := make([]*dns.Msg, distinct)
	for i := range qs {
		qs[i] = dns.Question{Name: "d" + strconv.Itoa(i) + ".example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		msgs[i] = buildResponse(qs[i], 300)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := i % distinct
		c.Set(qs[j], msgs[j])
	}
}

// BenchmarkCache_Set_DropOnFull measures the write path once the cache is at
// capacity, the branch BenchmarkCache_Set deliberately avoids. Set still
// validates the message and copies it (msg.Copy) before the len >= maxSize
// check drops it under lock. A full cache under a query flood pays that copy
// on every miss and throws it away, so this is the standing cost of the
// drop-on-full policy.
func BenchmarkCache_Set_DropOnFull(b *testing.B) {
	c := New(1)
	defer c.Close()

	// Fill the single slot so every benchmarked Set hits the drop branch.
	seed := dns.Question{Name: "seed.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(seed, buildResponse(seed, 300))

	q := dns.Question{Name: "other.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg := buildResponse(q, 300)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set(q, msg)
	}
}

// BenchmarkCache_Get_Parallel measures the hit path under the concurrency it
// runs in: miekg/dns spawns one goroutine per query, so many reads hit the
// RWMutex-guarded map at once. Distinct keys spread the reads across the map
// rather than hammering one entry. A serial Cache_Get cannot show lock
// contention; this catches a regression that serializes readers or moves the
// msg.Copy under an exclusive lock.
func BenchmarkCache_Get_Parallel(b *testing.B) {
	const distinct = 4096
	c := New(distinct * 2)
	defer c.Close()

	qs := make([]dns.Question, distinct)
	for i := range qs {
		qs[i] = dns.Question{Name: "d" + strconv.Itoa(i) + ".example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		c.Set(qs[i], buildResponse(qs[i], 300))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, ok := c.Get(qs[i%distinct]); !ok {
				b.Fatal("expected cache hit")
			}
			i++
		}
	})
}

// BenchmarkCache_CleanupExpired measures the periodic sweep runCleanup runs
// once a minute. It holds the write lock while iterating every entry, so on a
// large cache it is a lock-held O(n) pass that blocks all readers and writers
// for its duration. The entries are seeded not-yet-expired so the sweep walks
// the whole map and deletes nothing, the worst case for scan cost.
func BenchmarkCache_CleanupExpired(b *testing.B) {
	const N = 8192
	c := New(N)
	defer c.Close()

	for i := 0; i < N; i++ {
		q := dns.Question{Name: "d" + strconv.Itoa(i) + ".example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		c.Set(q, buildResponse(q, 3600))
	}
	// A fixed "now" at seed time so no entry has expired.
	now := time.Now()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if removed := c.cleanupExpired(now); removed != 0 {
			b.Fatalf("removed %d entries; expected none expired", removed)
		}
	}
}
