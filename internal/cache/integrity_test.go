package cache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// clientQuery returns a client query for q with the given header bits. With
// opt, the query has an OPT record with the DO bit do; without it, do must be
// false.
func clientQuery(q dns.Question, cd, ad, opt, do bool) *dns.Msg {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired:  true,
			CheckingDisabled:  cd,
			AuthenticatedData: ad,
		},
		Question: []dns.Question{q},
	}
	if opt {
		m.SetEdns0(1232, do)
	}
	return m
}

func TestCache_KeyHoldsCDAndDOBits(t *testing.T) {
	// b/096: the CD and DO bits change the upstream's answer, so a reply
	// cached for one combination is not served to a query with another. A
	// query with the same bits still hits.
	q := dns.Question{Name: "signed.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	type bits struct{ cd, do bool }
	all := []bits{{false, false}, {true, false}, {false, true}, {true, true}}
	for _, set := range all {
		for _, get := range all {
			c := New(10)
			c.Set(clientQuery(q, set.cd, false, true, set.do), buildResponse(q, 300))
			_, ok := c.Get(clientQuery(q, get.cd, false, true, get.do))
			if want := set == get; ok != want {
				t.Errorf("Set with CD=%v DO=%v, Get with CD=%v DO=%v: hit = %v, want %v",
					set.cd, set.do, get.cd, get.do, ok, want)
			}
			c.Close()
		}
	}
}

func TestCache_EachBitCombinationHasItsOwnEntry(t *testing.T) {
	// b/096: the four CD/DO combinations are four entries. Each query gets
	// the reply that was stored for its own bits, never another one.
	q := dns.Question{Name: "signed.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c := New(10)
	defer c.Close()
	type bits struct{ cd, do bool }
	all := []bits{{false, false}, {true, false}, {false, true}, {true, true}}
	for i, b := range all {
		resp := buildResponse(q, 300)
		resp.Answer[0].(*dns.A).A = net.IPv4(10, 0, 0, byte(i+1))
		c.Set(clientQuery(q, b.cd, false, true, b.do), resp)
	}
	if _, _, size := c.Stats(); size != len(all) {
		t.Fatalf("cache size = %d, want %d (one entry per CD/DO combination)", size, len(all))
	}
	for i, b := range all {
		got, ok := c.Get(clientQuery(q, b.cd, false, true, b.do))
		if !ok {
			t.Fatalf("CD=%v DO=%v: miss, want a hit", b.cd, b.do)
		}
		if ip := got.Answer[0].(*dns.A).A; !ip.Equal(net.IPv4(10, 0, 0, byte(i+1))) {
			t.Errorf("CD=%v DO=%v: answer %v, want 10.0.0.%d", b.cd, b.do, ip, i+1)
		}
	}
}

func TestCache_ADBitIsNotInTheKey(t *testing.T) {
	// b/096: the AD bit in a query only asks the upstream to report AD, so
	// queries that differ only in AD share one entry.
	q := dns.Question{Name: "signed.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	for _, setAD := range []bool{false, true} {
		c := New(10)
		c.Set(clientQuery(q, false, setAD, true, false), buildResponse(q, 300))
		if _, ok := c.Get(clientQuery(q, false, !setAD, true, false)); !ok {
			t.Errorf("Set with AD=%v, Get with AD=%v: miss, want a hit", setAD, !setAD)
		}
		c.Close()
	}
}

func TestCache_QueryWithoutOPTCountsAsDOClear(t *testing.T) {
	// b/096: a query without an OPT record counts as DO=0. It shares an entry
	// with a query that has an OPT record with DO=0, and not with one that
	// has DO=1.
	q := dns.Question{Name: "signed.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	cases := []struct {
		name          string
		setOPT, setDO bool
		getOPT, getDO bool
		cd            bool
		want          bool
	}{
		{"no OPT, then OPT DO=0", false, false, true, false, false, true},
		{"OPT DO=0, then no OPT", true, false, false, false, false, true},
		{"no OPT, then OPT DO=0, with CD", false, false, true, false, true, true},
		{"OPT DO=1, then no OPT", true, true, false, false, false, false},
		{"no OPT, then OPT DO=1", false, false, true, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(10)
			defer c.Close()
			c.Set(clientQuery(q, tc.cd, false, tc.setOPT, tc.setDO), buildResponse(q, 300))
			if _, ok := c.Get(clientQuery(q, tc.cd, false, tc.getOPT, tc.getDO)); ok != tc.want {
				t.Errorf("hit = %v, want %v", ok, tc.want)
			}
		})
	}
}

func TestCache_KeyKeepsNameCaseWithBits(t *testing.T) {
	// b/096 keeps b/037: with the same CD and DO bits, the letter case of the
	// name is still part of the key.
	upper := dns.Question{Name: "Signed.EXAMPLE.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	lower := dns.Question{Name: "signed.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c := New(10)
	defer c.Close()
	c.Set(clientQuery(upper, true, false, true, true), buildResponse(upper, 300))
	if _, ok := c.Get(clientQuery(lower, true, false, true, true)); ok {
		t.Error("a query in lowercase hit an entry stored in mixed case")
	}
	if _, ok := c.Get(clientQuery(upper, true, false, true, true)); !ok {
		t.Error("a query in the same case missed")
	}
}

func TestCache_LifetimeIsCappedAtOneDay(t *testing.T) {
	// SEC-18: an answer with a TTL of 10^6 s stays in the cache for at most
	// 86,400 s. Just before the cap it is a hit; at the cap it is a miss, and
	// the sweep removes it.
	q := dns.Question{Name: "long.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c := New(10)
	defer c.Close()
	c.Set(asQuery(q), buildResponse(q, 1_000_000))

	ageEntries(c, 86_399*time.Second)
	got, ok := c.Get(asQuery(q))
	if !ok {
		t.Fatal("miss 1 s before the cap, want a hit")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 1 {
		t.Errorf("TTL 1 s before the cap = %d, want at most 1", ttl)
	}

	ageEntries(c, time.Second)
	if _, ok := c.Get(asQuery(q)); ok {
		t.Error("hit at the cap (86,400 s), want a miss")
	}
	if n := c.cleanupExpired(time.Now()); n != 1 {
		t.Errorf("cleanupExpired removed %d entries at the cap, want 1", n)
	}
}

func TestCache_ServedTTLsAreCapped(t *testing.T) {
	// SEC-18: a reply from the cache never has a TTL above 86,400 s in any
	// section. A record with a TTL at or below the cap keeps its TTL.
	q := dns.Question{Name: "long.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg := buildResponse(q, 1_000_000)
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 86_400},
		A:   net.IPv4(5, 6, 7, 8),
	})
	msg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172_800}, Ns: "ns1.example."},
		&dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3_600}, Ns: "ns2.example."},
	}
	msg.Extra = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 86_401}, A: net.IPv4(9, 9, 9, 1)},
		&dns.A{Hdr: dns.RR_Header{Name: "ns2.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600}, A: net.IPv4(9, 9, 9, 2)},
	}
	want := map[string][]uint32{
		"answer":     {86_400, 86_400},
		"authority":  {86_400, 3_600},
		"additional": {86_400, 600},
	}

	c := New(10)
	defer c.Close()
	c.Set(asQuery(q), msg)
	got, ok := c.Get(asQuery(q))
	if !ok {
		t.Fatal("Get missed right after Set")
	}
	sections := map[string][]dns.RR{"answer": got.Answer, "authority": got.Ns, "additional": got.Extra}
	for name, rrs := range sections {
		if len(rrs) != len(want[name]) {
			t.Fatalf("%s section has %d records, want %d", name, len(rrs), len(want[name]))
		}
		for i, rr := range rrs {
			if ttl := rr.Header().Ttl; ttl != want[name][i] {
				t.Errorf("%s record %d TTL = %d, want %d", name, i, ttl, want[name][i])
			}
		}
	}

	// The cap holds on a later hit too: the TTLs age from the capped value.
	ageEntries(c, time.Hour)
	got, ok = c.Get(asQuery(q))
	if !ok {
		t.Fatal("Get missed after one hour")
	}
	for _, rr := range append(append(got.Answer, got.Ns...), got.Extra...) {
		if ttl := rr.Header().Ttl; ttl > 86_400-3_600 {
			t.Errorf("record %s TTL after one hour = %d, want at most %d", rr.Header().Name, ttl, 86_400-3_600)
		}
	}
}

func TestCache_QueryWithoutOneQuestionIsNeverCached(t *testing.T) {
	// b/096: the key comes from the client's query. A query without exactly
	// one question has no key: Set stores nothing, and Get misses and counts
	// the miss.
	q := dns.Question{Name: "signed.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	other := dns.Question{Name: "other.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	for _, qs := range [][]dns.Question{nil, {q, other}} {
		c := New(10)
		req := &dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: true}, Question: qs}
		c.Set(req, buildResponse(q, 300))
		if _, _, size := c.Stats(); size != 0 {
			t.Errorf("%d questions: Set stored %d entries, want 0", len(qs), size)
		}
		c.Set(asQuery(q), buildResponse(q, 300))
		if _, ok := c.Get(req); ok {
			t.Errorf("%d questions: Get hit, want a miss", len(qs))
		}
		if hits, misses, _ := c.Stats(); hits != 0 || misses != 1 {
			t.Errorf("%d questions: hits %d, misses %d; want 0 and 1", len(qs), hits, misses)
		}
		c.Close()
	}
}
