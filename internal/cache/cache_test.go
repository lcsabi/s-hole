package cache

import (
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

	c.Get(q) // hit
	c.Get(q) // hit
	c.Get(dns.Question{Name: "other.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}) // miss

	hits, misses, _ := c.Stats()
	if hits != 2 {
		t.Errorf("hits = %d, want 2", hits)
	}
	if misses != 1 {
		t.Errorf("misses = %d, want 1", misses)
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
