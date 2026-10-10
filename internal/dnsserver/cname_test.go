package dnsserver

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// CL 117: CNAME inspection. These tests are written from the CL 117
// requirements: a CNAME target in the Answer section of a served reply
// (from the cache or an upstream) blocks the query like a block on the
// queried name, and the target is never recorded anywhere.

// The names are under example., a public name (not .test or .lan, which are
// LAN-only names). Each label is unusual, so a leak scan cannot match by
// chance.
const (
	cnQueried = "metrics.shop.example."
	cnHop1    = "edge.zqcdnhop.example."
	cnHop2    = "collect.zqtracker.example."
	cnHop3    = "final.zqorigin.example."
	cnTTL     = 42 // blocking.reply_ttl_seconds in these tests
)

var cnUpstreamIP = net.IPv4(203, 0, 113, 7)

// cnameChain answers with a CNAME chain from the queried name through
// targets, then a final record for the query type: an A for A, an AAAA for
// AAAA, and none for other types. rcode sets the reply's rcode.
func cnameChain(rcode int, targets ...string) replyFunc {
	return func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = rcode
		q := req.Question[0]
		owner := q.Name
		for _, tgt := range targets {
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: tgt,
			})
			owner = tgt
		}
		switch q.Qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   cnUpstreamIP,
			})
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: owner, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("2001:db8::7"),
			})
		}
		return resp
	}
}

// cnFixture is a handler with one recording upstream, a capture logger, and
// an optional cache. The LAN ranges are fixed, so the result does not depend
// on the test host.
type cnFixture struct {
	h       *Handler
	store   *blocklist.Store
	counter *stats.Counter
	log     *captureLogger
	up      *queryRecorder
}

func newCNFixture(t *testing.T, reply replyFunc, blockMode string, withCache bool, blocked ...string) *cnFixture {
	t.Helper()
	addr, rec := startRecordingUpstream(t, reply, false)
	store := blocklist.NewStore()
	store.Replace(blocked)
	var c *cache.Cache
	if withCache {
		c = cache.New(100)
		t.Cleanup(c.Close)
	}
	counter := stats.New()
	log := &captureLogger{}
	h := NewHandler(store, counter, []string{addr}, log, blockMode, cnTTL, c, false, "full")
	h.lan = testACL(newFakeAddrs())
	h.SetQueryLogMode("all")
	return &cnFixture{h: h, store: store, counter: counter, log: log, up: rec}
}

// ask sends one query from the fake LAN client and returns the reply.
func (f *cnFixture) ask(t *testing.T, name string, qtype uint16) *dns.Msg {
	t.Helper()
	w := fakeClient()
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	f.h.ServeDNS(w, req)
	if w.written == nil {
		t.Fatalf("%s %s: no reply", name, dns.TypeToString[qtype])
	}
	return w.written
}

// hasCNAME reports whether any section of m holds a CNAME record.
func hasCNAME(m *dns.Msg) bool {
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			if _, ok := rr.(*dns.CNAME); ok {
				return true
			}
		}
	}
	return false
}

// checkSinkhole fails unless r is the sinkhole reply for qtype in blockMode:
// the same reply as a block on the queried name, with no CNAME record and no
// address from the upstream.
func checkSinkhole(t *testing.T, r *dns.Msg, qtype uint16, blockMode string) {
	t.Helper()
	if hasCNAME(r) {
		t.Errorf("sinkhole reply holds a CNAME record: %v", r)
	}
	if blockMode == "nxdomain" {
		if r.Rcode != dns.RcodeNameError || len(r.Answer) != 0 {
			t.Errorf("reply = rcode %s with %d answers, want NXDOMAIN with none", dns.RcodeToString[r.Rcode], len(r.Answer))
		}
		return
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[r.Rcode])
	}
	switch qtype {
	case dns.TypeA:
		if len(r.Answer) != 1 {
			t.Fatalf("answers = %v, want one A 0.0.0.0", r.Answer)
		}
		a, ok := r.Answer[0].(*dns.A)
		if !ok || !a.A.Equal(net.IPv4zero) || a.Hdr.Ttl != cnTTL {
			t.Errorf("answer = %v, want A 0.0.0.0 with TTL %d", r.Answer[0], cnTTL)
		}
	case dns.TypeAAAA:
		if len(r.Answer) != 1 {
			t.Fatalf("answers = %v, want one AAAA ::", r.Answer)
		}
		a, ok := r.Answer[0].(*dns.AAAA)
		if !ok || !a.AAAA.Equal(net.IPv6zero) || a.Hdr.Ttl != cnTTL {
			t.Errorf("answer = %v, want AAAA :: with TTL %d", r.Answer[0], cnTTL)
		}
	default:
		if len(r.Answer) != 0 {
			t.Errorf("answers = %v, want none for %s", r.Answer, dns.TypeToString[qtype])
		}
	}
}

// checkRelayed fails unless r is the upstream answer: the CNAME chain to
// targets in order, and for an A query the upstream's address at the end.
func checkRelayed(t *testing.T, r *dns.Msg, qtype uint16, targets ...string) {
	t.Helper()
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want the relayed NOERROR", dns.RcodeToString[r.Rcode])
	}
	var got []string
	for _, rr := range r.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			got = append(got, c.Target)
		}
	}
	if strings.Join(got, ",") != strings.Join(targets, ",") {
		t.Errorf("relayed CNAME targets = %v, want %v", got, targets)
	}
	if qtype == dns.TypeA {
		if ip := answerIP(r); ip == nil || !ip.Equal(cnUpstreamIP) {
			t.Errorf("relayed address = %v, want the upstream's %v", ip, cnUpstreamIP)
		}
	}
}

// checkCounts compares the counters that CNAME inspection touches.
func checkCounts(t *testing.T, c *stats.Counter, total, blocked, cname, hits int64) {
	t.Helper()
	s := c.Snapshot(0)
	if s.TotalQueries != total || s.BlockedCount != blocked || s.CNAMEBlockedCount != cname || s.CacheHits != hits {
		t.Errorf("counters = {total %d, blocked %d, cname %d, cache hits %d}, want {%d, %d, %d, %d}",
			s.TotalQueries, s.BlockedCount, s.CNAMEBlockedCount, s.CacheHits, total, blocked, cname, hits)
	}
	if s.ForwardFailures != 0 || s.UpstreamErrors != 0 {
		t.Errorf("failure counters = {forward %d, upstream %d}, want {0, 0}", s.ForwardFailures, s.UpstreamErrors)
	}
}

func TestServeDNS_CNAMEBlockedAtEveryHop(t *testing.T) {
	// CL 117 req 1, req 2: one blocked target anywhere in the chain blocks the
	// query. The reply is the zero_ip sinkhole, with no CNAME and no
	// upstream address.
	for _, tc := range []struct {
		name    string
		blocked string
	}{
		{"first hop", "edge.zqcdnhop.example"},
		{"middle hop", "collect.zqtracker.example"},
		{"last hop", "final.zqorigin.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2, cnHop3), "zero_ip", false, tc.blocked)
			r := f.ask(t, cnQueried, dns.TypeA)
			checkSinkhole(t, r, dns.TypeA, "zero_ip")
			checkCounts(t, f.counter, 1, 1, 1, 0)
		})
	}
}

func TestServeDNS_CNAMEParentOfTargetBlocks(t *testing.T) {
	// CL 117 req 1: the suffix rule of a name block applies to a target. A list
	// entry for a parent domain blocks the target under it, in any letter
	// case.
	f := newCNFixture(t, cnameChain(dns.RcodeSuccess, "Collect.ZQTracker.Example."), "zero_ip", false, "zqtracker.example")
	checkSinkhole(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, "zero_ip")
	checkCounts(t, f.counter, 1, 1, 1, 0)
}

func TestServeDNS_CNAMEUnblockedChainIsRelayed(t *testing.T) {
	// CL 117 req 1 (negative): a chain with no blocked target is relayed as the
	// upstream sent it, and the query is not counted as blocked. A sibling
	// of a listed domain does not match.
	f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2, cnHop3), "zero_ip", false, "other.zqtracker.example", "zqorigin.example.com")
	r := f.ask(t, cnQueried, dns.TypeA)
	checkRelayed(t, r, dns.TypeA, cnHop1, cnHop2, cnHop3)
	checkCounts(t, f.counter, 1, 0, 0, 0)
}

func TestServeDNS_CNAMEBlockEveryQtype(t *testing.T) {
	// CL 117 req 1, req 2: inspection applies to every query type, and the reply
	// matches a name block in both reply modes: 0.0.0.0 for A, :: for AAAA,
	// an empty NOERROR for the other types, and NXDOMAIN in nxdomain mode.
	for _, mode := range []string{"zero_ip", "nxdomain"} {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS, dns.TypeTXT, dns.TypeMX} {
			t.Run(mode+"/"+dns.TypeToString[qtype], func(t *testing.T) {
				f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2), mode, false, "zqtracker.example")
				r := f.ask(t, cnQueried, qtype)
				checkSinkhole(t, r, qtype, mode)
				checkCounts(t, f.counter, 1, 1, 1, 0)

				// The same reply as a block on the queried name.
				nameStore := blocklist.NewStore()
				nameStore.Replace([]string{"metrics.shop.example"})
				nh := NewHandler(nameStore, stats.New(), nil, nullLogger{}, mode, cnTTL, nil, false, "full")
				nw := fakeClient()
				nreq := new(dns.Msg)
				nreq.SetQuestion(cnQueried, qtype)
				nh.ServeDNS(nw, nreq)
				r.Id, nw.written.Id = 0, 0
				if r.String() != nw.written.String() {
					t.Errorf("CNAME block reply:\n%v\nname block reply:\n%v", r, nw.written)
				}
			})
		}
	}
}

func TestServeDNS_CNAMEFromLANUpstream(t *testing.T) {
	// CL 117 req 1: an answer from a LAN upstream, for a LAN-only name, is
	// inspected too.
	pub, pubRec := startRecordingUpstream(t, answerWith(net.IPv4(198, 51, 100, 1)), false)
	lan, lanRec := startRecordingUpstream(t, cnameChain(dns.RcodeSuccess, cnHop2), false)
	store := blocklist.NewStore()
	store.Replace([]string{"zqtracker.example"})
	counter := stats.New()
	h := NewHandler(store, counter, []string{pub, lan}, nullLogger{}, "zero_ip", cnTTL, nil, false, "full")
	h.lan = testACL(newFakeAddrs())
	markPublic(h, 0)

	w := fakeClient()
	h.ServeDNS(w, buildReq("nas.lan"))
	if pubRec.count() != 0 || lanRec.count() != 1 {
		t.Fatalf("public upstream got %d, LAN upstream got %d; want 0 and 1", pubRec.count(), lanRec.count())
	}
	checkSinkhole(t, w.written, dns.TypeA, "zero_ip")
	checkCounts(t, counter, 1, 1, 1, 0)
}

func TestServeDNS_CNAMEAllowlistedQueriedNameSkipsInspection(t *testing.T) {
	// CL 117 req 3: when the queried name or a parent of it is allowlisted, the
	// upstream answer is relayed unchanged, even with a blocked target.
	for _, allow := range []string{"metrics.shop.example", "shop.example", "SHOP.Example."} {
		t.Run(allow, func(t *testing.T) {
			f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2), "zero_ip", false, "zqtracker.example")
			f.store.AddToAllowlist(allow)
			r := f.ask(t, cnQueried, dns.TypeA)
			checkRelayed(t, r, dns.TypeA, cnHop1, cnHop2)
			checkCounts(t, f.counter, 1, 0, 0, 0)
			if f.log.last.Blocked {
				t.Errorf("query-log record = %+v, want not blocked", f.log.last)
			}
		})
	}
}

func TestServeDNS_CNAMEAllowlistedTargetDoesNotBlock(t *testing.T) {
	// CL 117 req 3: a target that is allowlisted, or that has an allowlisted
	// parent, does not count as blocked. A different blocked target in the
	// same chain still blocks.
	t.Run("target allowlisted", func(t *testing.T) {
		f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2), "zero_ip", false, "zqtracker.example")
		f.store.AddToAllowlist("collect.zqtracker.example")
		checkRelayed(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, cnHop1, cnHop2)
		checkCounts(t, f.counter, 1, 0, 0, 0)
	})
	t.Run("parent of target allowlisted", func(t *testing.T) {
		f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2), "zero_ip", false, "collect.zqtracker.example")
		f.store.AddToAllowlist("zqtracker.example")
		checkRelayed(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, cnHop1, cnHop2)
		checkCounts(t, f.counter, 1, 0, 0, 0)
	})
	t.Run("another target still blocks", func(t *testing.T) {
		f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2), "zero_ip", false, "zqtracker.example", "zqcdnhop.example")
		f.store.AddToAllowlist("zqtracker.example")
		checkSinkhole(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, "zero_ip")
		checkCounts(t, f.counter, 1, 1, 1, 0)
	})
}

func TestServeDNS_CNAMEBlockedFromCache(t *testing.T) {
	// CL 117 req 4(a), req 5: the raw answer is cached, so a second identical
	// query does not go upstream again, and the chain is checked on the
	// cache hit, so it is still blocked. A blocked query is never a cache
	// hit.
	f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2, cnHop3), "zero_ip", true, "zqtracker.example")
	checkSinkhole(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, "zero_ip")
	checkSinkhole(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, "zero_ip")
	if n := f.up.count(); n != 1 {
		t.Errorf("upstream got %d queries, want 1 (the second is served from the cache)", n)
	}
	checkCounts(t, f.counter, 2, 2, 2, 0)
	if f.log.last.CacheHit || f.log.last.BlockSource != querylog.BlockedByCNAME {
		t.Errorf("record for the cached query = %+v, want CacheHit=false and BlockSource=cname", f.log.last)
	}
}

func TestServeDNS_CNAMEBlockSetChangeAppliesToCachedAnswer(t *testing.T) {
	// CL 117 req 4(b): after a block-set change, the next query served from
	// the cache follows the new set, with no new upstream query, in both
	// directions.
	f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2), "zero_ip", true)

	checkRelayed(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, cnHop1, cnHop2)
	checkCounts(t, f.counter, 1, 0, 0, 0)

	f.store.Replace([]string{"zqtracker.example"})
	checkSinkhole(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, "zero_ip")
	checkCounts(t, f.counter, 2, 1, 1, 0)

	f.store.Replace(nil)
	checkRelayed(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, cnHop1, cnHop2)
	checkCounts(t, f.counter, 3, 1, 1, 1)

	if n := f.up.count(); n != 1 {
		t.Errorf("upstream got %d queries, want 1 (later queries come from the cache)", n)
	}
}

func TestServeDNS_CNAMEAllowlistChangeAppliesToCachedAnswer(t *testing.T) {
	// CL 117 req 4(b): an allowlist change applies to the next query served
	// from the cache, with no new upstream query.
	f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2), "zero_ip", true, "zqtracker.example")

	checkSinkhole(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, "zero_ip")

	f.store.AddToAllowlist("shop.example")
	checkRelayed(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, cnHop1, cnHop2)

	f.store.RemoveFromAllowlist("shop.example")
	checkSinkhole(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, "zero_ip")

	f.store.AddToAllowlist("collect.zqtracker.example")
	checkRelayed(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, cnHop1, cnHop2)

	if n := f.up.count(); n != 1 {
		t.Errorf("upstream got %d queries, want 1 (later queries come from the cache)", n)
	}
	checkCounts(t, f.counter, 4, 2, 2, 2)
}

func TestServeDNS_CNAMEBlockQueryLogRecord(t *testing.T) {
	// CL 117 req 7: the row holds the queried name in lowercase with the
	// trailing dot, Blocked, the sinkhole rcode, Synthesized, CacheHit=false,
	// and BlockSource=cname. It holds no CNAME target.
	for _, tc := range []struct {
		mode  string
		rcode int
	}{
		{"zero_ip", dns.RcodeSuccess},
		{"nxdomain", dns.RcodeNameError},
	} {
		for _, cached := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cache=%v", tc.mode, cached), func(t *testing.T) {
				f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2, cnHop3), tc.mode, cached, "zqtracker.example")
				for range 2 {
					f.ask(t, "Metrics.SHOP.example.", dns.TypeA)
					want := querylog.Record{
						ClientIP:    "192.168.1.100",
						Domain:      cnQueried,
						Blocked:     true,
						Rcode:       tc.rcode,
						Synthesized: true,
						CacheHit:    false,
						BlockSource: querylog.BlockedByCNAME,
					}
					if f.log.last != want {
						t.Errorf("record = %+v, want %+v", f.log.last, want)
					}
				}
				if f.log.calls != 2 {
					t.Errorf("logger called %d times, want 2 (one row a query)", f.log.calls)
				}
				rec := strings.ToLower(fmt.Sprintf("%+v", f.log.last))
				for _, tgt := range []string{"zqcdnhop", "zqtracker", "zqorigin"} {
					if strings.Contains(rec, tgt) {
						t.Errorf("record names the CNAME target %q: %s", tgt, rec)
					}
				}
			})
		}
	}
}

func TestServeDNS_NameBlockRecordIsBlockedByName(t *testing.T) {
	// CL 117 req 7: a block on the queried name has BlockSource=name (the zero
	// value), and it does not count as a CNAME block.
	f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop2), "zero_ip", false, "shop.example", "zqtracker.example")
	checkSinkhole(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, "zero_ip")
	if f.log.last.BlockSource != querylog.BlockedByName || !f.log.last.Blocked {
		t.Errorf("record = %+v, want Blocked with BlockSource=name", f.log.last)
	}
	if f.up.count() != 0 {
		t.Errorf("upstream got %d queries for a name block, want 0", f.up.count())
	}
	checkCounts(t, f.counter, 1, 1, 0, 0)
}

func TestServeDNS_CNAMEBlockTalliesFollowQueryLogMode(t *testing.T) {
	// CL 117 req 5: the Top Domains and Top Clients tallies and the per-minute
	// graph follow query_log.mode exactly as for a name block. The queried
	// name is tallied, never a target.
	cases := []struct {
		mode        string
		wantClients []stats.Entry
		wantDomains []stats.Entry
		wantGraph   stats.TimelineBucket
	}{
		{"all", []stats.Entry{{Name: "192.168.1.100", Count: 2}}, []stats.Entry{{Name: cnQueried, Count: 2}}, stats.TimelineBucket{Total: 2, Blocked: 2}},
		{"blocked", []stats.Entry{{Name: "192.168.1.100", Count: 2}}, []stats.Entry{{Name: cnQueried, Count: 2}}, stats.TimelineBucket{Total: 2, Blocked: 2}},
		{"none", nil, nil, stats.TimelineBucket{}},
	}
	for _, tc := range cases {
		for _, source := range []string{"cname", "name"} {
			t.Run(tc.mode+"/"+source, func(t *testing.T) {
				blocked := []string{"zqtracker.example"}
				if source == "name" {
					blocked = []string{"metrics.shop.example"}
				}
				f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2), "zero_ip", true, blocked...)
				f.h.SetQueryLogMode(tc.mode)
				f.counter.SetQueryLogMode(tc.mode)
				// The second query is served from the cache on the CNAME path.
				f.ask(t, cnQueried, dns.TypeA)
				f.ask(t, cnQueried, dns.TypeA)

				s := f.counter.Snapshot(10)
				if !sameEntries(s.TopClients, tc.wantClients) {
					t.Errorf("top clients = %v, want %v", s.TopClients, tc.wantClients)
				}
				if !sameEntries(s.TopDomains, tc.wantDomains) {
					t.Errorf("top domains = %v, want %v", s.TopDomains, tc.wantDomains)
				}
				var got stats.TimelineBucket
				for _, b := range f.counter.Timeline(2*time.Hour, time.Hour, time.Now()) {
					got.Total += b.Total
					got.Blocked += b.Blocked
					got.Cached += b.Cached
					got.Unresolved += b.Unresolved
					got.UpstreamError += b.UpstreamError
				}
				if got != tc.wantGraph {
					t.Errorf("graph = %+v, want %+v", got, tc.wantGraph)
				}
			})
		}
	}
}

func TestServeDNS_CNAMEInspectionOff(t *testing.T) {
	// CL 117 req 11: with blocking.cname_inspection off, the answer is relayed
	// with its CNAME chain unchanged, from the upstream and from the cache.
	f := newCNFixture(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2), "zero_ip", true, "zqtracker.example")
	f.h.SetCNAMEInspection(false)
	checkRelayed(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, cnHop1, cnHop2)
	checkRelayed(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, cnHop1, cnHop2)
	checkCounts(t, f.counter, 2, 0, 0, 1)
	if f.log.last.Blocked {
		t.Errorf("record = %+v, want not blocked", f.log.last)
	}

	// Turning it on again blocks the cached answer.
	f.h.SetCNAMEInspection(true)
	checkSinkhole(t, f.ask(t, cnQueried, dns.TypeA), dns.TypeA, "zero_ip")
}

func TestNewHandler_CNAMEInspectionOnByDefault(t *testing.T) {
	// CL 117 req 11: before SetCNAMEInspection is called, inspection is on, the
	// most private choice.
	addr, _ := startRecordingUpstream(t, cnameChain(dns.RcodeSuccess, cnHop2), false)
	store := blocklist.NewStore()
	store.Replace([]string{"zqtracker.example"})
	h := NewHandler(store, stats.New(), []string{addr}, nullLogger{}, "zero_ip", cnTTL, nil, false, "drop")
	w := fakeClient()
	h.ServeDNS(w, buildReq(cnQueried))
	checkSinkhole(t, w.written, dns.TypeA, "zero_ip")
}

func TestServeDNS_CNAMENotCheckedOutsideTheAnswer(t *testing.T) {
	// CL 117 req 13: a CNAME record in the Authority or Additional section is
	// not checked, and an answer with no CNAME is relayed as before.
	outside := func(section string, chain ...string) replyFunc {
		return func(req *dns.Msg) *dns.Msg {
			resp := cnameChain(dns.RcodeSuccess, chain...)(req)
			c := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: "other.zqcdnhop.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: cnHop2,
			}
			if section == "authority" {
				resp.Ns = append(resp.Ns, c)
			} else {
				resp.Extra = append(resp.Extra, c)
			}
			return resp
		}
	}
	for _, tc := range []struct {
		name  string
		reply replyFunc
	}{
		{"authority", outside("authority")},
		{"additional", outside("additional")},
		// An unblocked chain in the Answer section, so the check runs.
		{"authority with a chain in the answer", outside("authority", cnHop1)},
		{"additional with a chain in the answer", outside("additional", cnHop1)},
		{"no CNAME", cnameChain(dns.RcodeSuccess)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCNFixture(t, tc.reply, "zero_ip", false, "zqtracker.example")
			r := f.ask(t, cnQueried, dns.TypeA)
			if ip := answerIP(r); ip == nil || !ip.Equal(cnUpstreamIP) {
				t.Errorf("reply = %v, want the upstream address relayed", r)
			}
			checkCounts(t, f.counter, 1, 0, 0, 0)
		})
	}
}

func TestServeDNS_CNAMENotCheckedOnFailureRcode(t *testing.T) {
	// CL 117 req 13: a reply with a failure rcode is relayed as before, even
	// when its Answer section has a blocked CNAME target.
	for _, rc := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNameError} {
		t.Run(dns.RcodeToString[rc], func(t *testing.T) {
			f := newCNFixture(t, cnameChain(rc, cnHop2), "zero_ip", false, "zqtracker.example")
			r := f.ask(t, cnQueried, dns.TypeTXT)
			if r.Rcode != rc {
				t.Errorf("rcode = %s, want the relayed %s", dns.RcodeToString[r.Rcode], dns.RcodeToString[rc])
			}
			if s := f.counter.Snapshot(0); s.BlockedCount != 0 || s.CNAMEBlockedCount != 0 {
				t.Errorf("counters = {blocked %d, cname %d}, want {0, 0}", s.BlockedCount, s.CNAMEBlockedCount)
			}
			if f.log.last.Blocked || f.log.last.Synthesized || f.log.last.Rcode != rc {
				t.Errorf("record = %+v, want a relayed %s", f.log.last, dns.RcodeToString[rc])
			}
		})
	}
}

// cnTargetLabels are the parts of the CNAME targets that a leak scan looks
// for. None of them is part of the queried name.
var cnTargetLabels = []string{"zqcdnhop", "zqtracker", "zqorigin"}

func TestServeDNS_CNAMETargetIsNeverStored(t *testing.T) {
	// CL 117 privacy: the CNAME target never reaches the query-log database,
	// the log file, the stats, or the application log, on the upstream path
	// and on the cache path. The queried name does reach the stores that
	// query_log.mode "all" allows, which shows the scan can find a name.
	app := captureAppLog(t)
	dir := t.TempDir()
	dbPath, filePath := filepath.Join(dir, "q.db"), filepath.Join(dir, "q.log")
	db, err := querylog.NewDBLogger(dbPath, "all", 20*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	fl, err := querylog.NewFileLogger(filePath, "all")
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}

	addr, _ := startRecordingUpstream(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2, cnHop3), false)
	store := blocklist.NewStore()
	store.Replace([]string{"zqtracker.example"})
	c := cache.New(100)
	defer c.Close()
	counter := stats.New()
	counter.SetQueryLogMode("all")
	h := NewHandler(store, counter, []string{addr}, querylog.NewMulti(db, fl), "zero_ip", cnTTL, c, false, "full")
	h.lan = testACL(newFakeAddrs())
	h.SetQueryLogMode("all")

	for range 2 {
		w := fakeClient()
		h.ServeDNS(w, buildReq(cnQueried))
		checkSinkhole(t, w.written, dns.TypeA, "zero_ip")
	}
	rows, err := db.Recent(t.Context(), 10)
	deadline := time.Now().Add(2 * time.Second)
	for (err != nil || len(rows) < 2) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		rows, err = db.Recent(t.Context(), 10)
	}
	if err != nil || len(rows) != 2 {
		t.Fatalf("database rows = %v (err %v), want 2", rows, err)
	}
	for _, r := range rows {
		if r.Domain != cnQueried || r.BlockedBy != "cname" {
			t.Errorf("row = %+v, want domain %s blocked_by cname", r, cnQueried)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	if err := fl.Close(); err != nil {
		t.Fatalf("close log file: %v", err)
	}

	snap, err := json.Marshal(counter.Snapshot(10))
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	dbBytes, _ := os.ReadFile(dbPath)
	walBytes, _ := os.ReadFile(dbPath + "-wal")
	stores := map[string]string{
		"database": string(dbBytes) + string(walBytes),
		"log file": string(file),
		"stats":    string(snap),
		"app log":  app.text(),
	}
	for where, text := range stores {
		low := strings.ToLower(text)
		for _, tgt := range cnTargetLabels {
			if strings.Contains(low, tgt) {
				t.Errorf("%s holds the CNAME target %q", where, tgt)
			}
		}
	}
	// Positive controls: the stores that mode "all" fills hold the queried
	// name, so the scan above reads the right data.
	for _, where := range []string{"database", "log file", "stats"} {
		if !strings.Contains(stores[where], "metrics.shop.example") {
			t.Errorf("%s does not hold the queried name; the scan is not reading it", where)
		}
	}
	if !strings.Contains(string(file), "BLOCK 192.168.1.100 "+cnQueried+" CNAME") {
		t.Errorf("log file = %q, want a CNAME BLOCK line for the queried name", file)
	}
	assertNoQueryData(t, app, cnQueried)
}

func TestServeDNS_CNAMEBlockModeNoneLeavesNoTrace(t *testing.T) {
	// CL 117 privacy: under query_log.mode "none", a CNAME-blocked query
	// leaves no domain and no client in the tallies, the graph, the query
	// logs, or the application log. Only the counters count it.
	app := captureAppLog(t)
	dir := t.TempDir()
	dbPath, filePath := filepath.Join(dir, "q.db"), filepath.Join(dir, "q.log")
	db, err := querylog.NewDBLogger(dbPath, "none", 20*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	fl, err := querylog.NewFileLogger(filePath, "none")
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}

	addr, _ := startRecordingUpstream(t, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2), false)
	store := blocklist.NewStore()
	store.Replace([]string{"zqtracker.example"})
	c := cache.New(100)
	defer c.Close()
	counter := stats.New()
	counter.SetQueryLogMode("none")
	h := NewHandler(store, counter, []string{addr}, querylog.NewMulti(db, fl), "zero_ip", cnTTL, c, false, "full")
	h.lan = testACL(newFakeAddrs())
	h.SetQueryLogMode("none")

	for range 2 {
		w := fakeClient()
		h.ServeDNS(w, buildReq(cnQueried))
		checkSinkhole(t, w.written, dns.TypeA, "zero_ip")
	}
	time.Sleep(60 * time.Millisecond) // three flush ticks
	rows, err := db.Recent(t.Context(), 10)
	if err != nil || len(rows) != 0 {
		t.Errorf("database rows = %v (err %v), want none", rows, err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	if err := fl.Close(); err != nil {
		t.Fatalf("close log file: %v", err)
	}
	if file, _ := os.ReadFile(filePath); len(file) != 0 {
		t.Errorf("log file = %q, want empty", file)
	}

	s := counter.Snapshot(10)
	if len(s.TopClients) != 0 || len(s.TopDomains) != 0 {
		t.Errorf("tallies = clients %v, domains %v; want none", s.TopClients, s.TopDomains)
	}
	if s.BlockedCount != 2 || s.CNAMEBlockedCount != 2 {
		t.Errorf("counters = {blocked %d, cname %d}, want {2, 2}", s.BlockedCount, s.CNAMEBlockedCount)
	}
	for _, b := range counter.Timeline(2*time.Hour, time.Hour, time.Now()) {
		if b.Total != 0 || b.Blocked != 0 {
			t.Errorf("graph bucket = %+v, want empty", b)
		}
	}
	snap, _ := json.Marshal(s)
	for _, leak := range append([]string{"metrics.shop", "192.168.1.100"}, cnTargetLabels...) {
		if strings.Contains(strings.ToLower(string(snap)), leak) {
			t.Errorf("stats hold %q: %s", leak, snap)
		}
	}
	assertNoQueryData(t, app, cnQueried)
	for _, tgt := range cnTargetLabels {
		if strings.Contains(strings.ToLower(app.text()), tgt) {
			t.Errorf("application log holds the CNAME target %q", tgt)
		}
	}
}

// BenchmarkHandler_ChainBlocked measures the CNAME check of CL 117 req 14 on a
// served answer with a three-hop chain where no target is blocked: the walk
// that every allowed answer with a chain pays.
func BenchmarkHandler_ChainBlocked(b *testing.B) {
	h, resp := chainBench()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if h.chainBlocked(cnQueried, resp) {
			b.Fatal("chain unexpectedly blocked")
		}
	}
}

// chainBench builds a handler with a block set of 100,000 names, none of
// which matches, and an A answer with a three-hop CNAME chain.
func chainBench() (*Handler, *dns.Msg) {
	store := blocklist.NewStore()
	dom := make([]string, 0, 100_000)
	for i := range 100_000 {
		dom = append(dom, fmt.Sprintf("x%d.zqtracker.example", i))
	}
	store.Replace(dom)
	store.SetAllowlist([]string{"unrelated.example"})
	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero_ip", cnTTL, nil, false, "drop")
	req := new(dns.Msg)
	req.SetQuestion(cnQueried, dns.TypeA)
	return h, cnameChain(dns.RcodeSuccess, cnHop1, cnHop2, cnHop3)(req)
}

func TestServeDNS_CNAMEBlockedNeverExceedsBlockedUnderLoad(t *testing.T) {
	// CL 117 req 6 at the handler: the handler counts a CNAME block as blocked
	// before it counts it as a CNAME block, so a snapshot taken while many
	// queries run never shows more CNAME blocks than blocks. The answer comes
	// from the cache, so the test needs no network.
	store := blocklist.NewStore()
	store.Replace([]string{"zqtracker.example"})
	c := cache.New(100)
	defer c.Close()
	q := dns.Question{Name: cnQueried, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(asQuery(q), cnameChain(dns.RcodeSuccess, cnHop1, cnHop2)(asQuery(q)))
	counter := stats.New()
	h := NewHandler(store, counter, nil, nullLogger{}, "zero_ip", cnTTL, c, false, "drop")
	h.lan = testACL(newFakeAddrs())
	req := buildReq(cnQueried)

	stop := make(chan struct{})
	done := make(chan struct{})
	for range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			w := fakeClient()
			for {
				select {
				case <-stop:
					return
				default:
					h.ServeDNS(w, req)
				}
			}
		}()
	}
	for range 20000 {
		s := counter.Snapshot(0)
		if s.CNAMEBlockedCount > s.BlockedCount || s.BlockedCount > s.TotalQueries {
			close(stop)
			for range 8 {
				<-done
			}
			t.Fatalf("invariant violated: cname=%d blocked=%d total=%d", s.CNAMEBlockedCount, s.BlockedCount, s.TotalQueries)
		}
	}
	close(stop)
	for range 8 {
		<-done
	}
	if s := counter.Snapshot(0); s.CNAMEBlockedCount == 0 || s.CNAMEBlockedCount != s.BlockedCount {
		t.Errorf("after the load: cname=%d blocked=%d, want equal and above 0", s.CNAMEBlockedCount, s.BlockedCount)
	}
}
