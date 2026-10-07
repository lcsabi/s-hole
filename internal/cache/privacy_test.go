package cache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ageEntries moves the cache time of every entry d into the past.
func ageEntries(c *Cache, d time.Duration) {
	c.mu.Lock()
	for _, e := range c.entries {
		e.cached = e.cached.Add(-d)
	}
	c.mu.Unlock()
}

func TestCache_AgingKeepsOPTRecord(t *testing.T) {
	// K1 (b/072): aging a cached reply lowers the TTL of every record but the
	// EDNS0 OPT record, whose TTL field holds the extended rcode, the EDNS
	// version, and the DO flag.
	q := dns.Question{Name: "signed.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg := buildResponse(q, 1000)
	msg.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 200},
		Ns:  "ns.example.",
	}}
	msg.Extra = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "ns.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(192, 0, 2, 1),
	}}
	msg.SetEdns0(1232, true)
	opt := msg.IsEdns0()
	opt.SetExtendedRcode(dns.RcodeBadVers) // upper rcode bits live in the TTL field too
	wantOPTTTL := opt.Hdr.Ttl
	if !opt.Do() || wantOPTTTL == 0 {
		t.Fatalf("test setup: OPT TTL field = %#x, DO = %v", wantOPTTTL, opt.Do())
	}

	c := New(10)
	defer c.Close()
	c.Set(asQuery(q), msg)
	for _, elapsed := range []time.Duration{0, 30 * time.Second, 90 * time.Second} {
		ageEntries(c, elapsed)
		got, ok := c.Get(asQuery(q))
		if !ok {
			t.Fatalf("Get after %s missed", elapsed)
		}
		gotOPT := got.IsEdns0()
		if gotOPT == nil {
			t.Fatalf("after %s: the cached reply lost its OPT record", elapsed)
		}
		if gotOPT.Hdr.Ttl != wantOPTTTL || !gotOPT.Do() || gotOPT.UDPSize() != 1232 {
			t.Errorf("after %s: OPT TTL field = %#x DO = %v size = %d, want %#x, true, 1232",
				elapsed, gotOPT.Hdr.Ttl, gotOPT.Do(), gotOPT.UDPSize(), wantOPTTTL)
		}
	}
	// The other records did age: 120 s have passed in total.
	got, _ := c.Get(asQuery(q))
	if ttl := got.Ns[0].Header().Ttl; ttl > 80 || ttl < 70 {
		t.Errorf("NS TTL = %d, want about 80 (200 - 120)", ttl)
	}
	for _, rr := range got.Extra {
		if a, ok := rr.(*dns.A); ok && (a.Hdr.Ttl > 180 || a.Hdr.Ttl < 170) {
			t.Errorf("additional A TTL = %d, want about 180 (300 - 120)", a.Hdr.Ttl)
		}
	}
}

func TestCache_FlushEmptiesAndKeepsCounters(t *testing.T) {
	// K2: Flush deletes every cached answer and keeps the hit, miss, and drop
	// counters.
	c := New(2)
	defer c.Close()
	qs := []dns.Question{
		{Name: "a.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "c.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	for _, q := range qs {
		c.Set(asQuery(q), buildResponse(q, 300)) // the third is dropped: the cache is full
	}
	c.Get(asQuery(qs[0]))                                                                     // hit
	c.Get(asQuery(dns.Question{Name: "x.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})) // miss
	hits, misses, size := c.Stats()
	dropped := c.Dropped()
	if hits != 1 || misses != 1 || size != 2 || dropped != 1 {
		t.Fatalf("before Flush: hits %d, misses %d, size %d, dropped %d; want 1, 1, 2, 1", hits, misses, size, dropped)
	}

	c.Flush()

	h2, m2, s2 := c.Stats()
	if s2 != 0 {
		t.Errorf("size after Flush = %d, want 0", s2)
	}
	if h2 != hits || m2 != misses || c.Dropped() != dropped {
		t.Errorf("counters after Flush = hits %d, misses %d, dropped %d; want %d, %d, %d", h2, m2, c.Dropped(), hits, misses, dropped)
	}
	for _, q := range qs[:2] {
		if _, ok := c.Get(asQuery(q)); ok {
			t.Errorf("Get(%s) hit after Flush", q.Name)
		}
	}
	// The cache still works and has its full capacity again.
	c.Set(asQuery(qs[2]), buildResponse(qs[2], 300))
	if _, ok := c.Get(asQuery(qs[2])); !ok {
		t.Error("Set after Flush did not store the answer")
	}
	if c.Dropped() != dropped {
		t.Errorf("Set after Flush was dropped: dropped = %d, want %d", c.Dropped(), dropped)
	}
}
