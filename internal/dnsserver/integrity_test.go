package dnsserver

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// Tests for the integrity of the answers s-hole gives: the cache key holds
// the CD and DO bits (b/096), an upstream reply must match the query
// (SEC-17), the cache caps TTLs (SEC-18), and a query with RD=0 is refused
// (PRIV-05).

// bitsQuery is an A query for name with RD=1, the given CD and AD bits, and,
// with opt, an OPT record with the DO bit do.
func bitsQuery(name string, cd, ad, opt, do bool) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	req.CheckingDisabled = cd
	req.AuthenticatedData = ad
	if opt {
		withOPT(req, 1232, do)
	}
	return req
}

// queryDO reports the DO bit of req's OPT record, false without one.
func queryDO(req *dns.Msg) bool {
	o := req.IsEdns0()
	return o != nil && o.Do()
}

// answerIP returns the address of the first A record in m, or nil.
func answerIP(m *dns.Msg) net.IP {
	if m == nil {
		return nil
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A
		}
	}
	return nil
}

// hasRRSIG reports whether m has an RRSIG record in the answer section.
func hasRRSIG(m *dns.Msg) bool {
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return true
		}
	}
	return false
}

func TestServeDNS_CDReplyIsNotServedToCDClear(t *testing.T) {
	// b/096: a validating upstream returns data that failed validation only
	// to a query with CD=1, and SERVFAIL to a query with CD=0. After a CD=1
	// query fills the cache, a CD=0 query goes upstream again and gets the
	// upstream's SERVFAIL, not the cached data.
	bogus := net.IPv4(6, 6, 6, 6)
	validating := func(req *dns.Msg) *dns.Msg {
		if !req.CheckingDisabled {
			resp := new(dns.Msg)
			resp.SetRcode(req, dns.RcodeServerFailure)
			return resp
		}
		return answerWith(bogus)(req)
	}
	addr, rec := startRecordingUpstream(t, validating, false)
	c := cache.New(10)
	defer c.Close()
	h := testHandler([]string{addr}, c)
	const name = "dnssec-failed.example.com."

	w := fakeClient()
	h.ServeDNS(w, bitsQuery(name, true, false, true, false))
	if !answerIP(w.written).Equal(bogus) {
		t.Fatalf("CD=1 reply = %v, want the upstream's answer %v", w.written, bogus)
	}

	w = fakeClient()
	h.ServeDNS(w, bitsQuery(name, false, false, true, false))
	if rec.count() != 2 {
		t.Errorf("upstream got %d queries, want 2 (the CD=0 query is not a cache hit)", rec.count())
	}
	if w.written == nil || w.written.Rcode != dns.RcodeServerFailure || len(w.written.Answer) != 0 {
		t.Errorf("CD=0 reply = %v, want the upstream's SERVFAIL without answers", w.written)
	}

	// A CD=1 query still hits the cache.
	w = fakeClient()
	h.ServeDNS(w, bitsQuery(name, true, false, true, false))
	if rec.count() != 2 {
		t.Errorf("upstream got %d queries, want 2 (the second CD=1 query is a cache hit)", rec.count())
	}
	if !answerIP(w.written).Equal(bogus) {
		t.Errorf("second CD=1 reply = %v, want %v from the cache", w.written, bogus)
	}
}

func TestServeDNS_CDBitsGetTheirOwnCacheEntries(t *testing.T) {
	// b/096: the reverse order too. A CD=0 reply is not served to a CD=1
	// query, and each bit value then hits its own cache entry.
	checked, unchecked := net.IPv4(1, 1, 1, 1), net.IPv4(2, 2, 2, 2)
	reply := func(req *dns.Msg) *dns.Msg {
		if req.CheckingDisabled {
			return answerWith(unchecked)(req)
		}
		return answerWith(checked)(req)
	}
	addr, rec := startRecordingUpstream(t, reply, false)
	c := cache.New(10)
	defer c.Close()
	h := testHandler([]string{addr}, c)
	const name = "cd.example.com."

	steps := []struct {
		cd       bool
		want     net.IP
		upstream int
	}{
		{false, checked, 1},
		{true, unchecked, 2},
		{false, checked, 2},
		{true, unchecked, 2},
	}
	for i, s := range steps {
		w := fakeClient()
		h.ServeDNS(w, bitsQuery(name, s.cd, false, false, false))
		if got := answerIP(w.written); !got.Equal(s.want) {
			t.Errorf("step %d (CD=%v): answer %v, want %v", i, s.cd, got, s.want)
		}
		if rec.count() != s.upstream {
			t.Errorf("step %d (CD=%v): upstream got %d queries, want %d", i, s.cd, rec.count(), s.upstream)
		}
	}
}

func TestServeDNS_DOBitsGetTheirOwnCacheEntries(t *testing.T) {
	// b/096: a DO=1 query gets the reply with RRSIG records, and a DO=0
	// reply without them is not served to it from the cache (and the
	// reverse). Queries with the same DO bit share one entry.
	ip := net.IPv4(3, 3, 3, 3)
	reply := func(req *dns.Msg) *dns.Msg {
		resp := answerWith(ip)(req)
		if queryDO(req) {
			q := req.Question[0]
			resp.Answer = append(resp.Answer, &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: q.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
				TypeCovered: dns.TypeA, Algorithm: dns.ECDSAP256SHA256, Labels: 3, OrigTtl: 300,
				Expiration: 2000000000, Inception: 1700000000, KeyTag: 12345,
				SignerName: "example.com.", Signature: "AAAA",
			})
		}
		return resp
	}
	for _, firstDO := range []bool{true, false} {
		t.Run(map[bool]string{true: "DO=1 first", false: "DO=0 first"}[firstDO], func(t *testing.T) {
			addr, rec := startRecordingUpstream(t, reply, false)
			c := cache.New(10)
			defer c.Close()
			h := testHandler([]string{addr}, c)
			const name = "signed.example.com."
			order := []bool{firstDO, !firstDO, firstDO, !firstDO}
			wantUpstream := []int{1, 2, 2, 2}
			for i, do := range order {
				w := fakeClient()
				h.ServeDNS(w, bitsQuery(name, false, false, true, do))
				if w.written == nil || !answerIP(w.written).Equal(ip) {
					t.Fatalf("query %d (DO=%v): reply = %v, want the answer %v", i, do, w.written, ip)
				}
				if got := hasRRSIG(w.written); got != do {
					t.Errorf("query %d (DO=%v): reply has RRSIG = %v, want %v", i, do, got, do)
				}
				if rec.count() != wantUpstream[i] {
					t.Errorf("query %d (DO=%v): upstream got %d queries, want %d", i, do, rec.count(), wantUpstream[i])
				}
			}
		})
	}
}

func TestServeDNS_ADBitAndMissingOPTShareTheCache(t *testing.T) {
	// b/096: the AD bit is not in the cache key, and a query without an OPT
	// record counts as DO=0. These four queries share one cache entry.
	addr, rec := startRecordingUpstream(t, answerWith(net.IPv4(4, 4, 4, 4)), false)
	c := cache.New(10)
	defer c.Close()
	h := testHandler([]string{addr}, c)
	const name = "shared.example.com."
	for i, req := range []*dns.Msg{
		bitsQuery(name, false, false, false, false),
		bitsQuery(name, false, true, false, false),
		bitsQuery(name, false, true, true, false),
		bitsQuery(name, false, false, true, false),
	} {
		w := fakeClient()
		h.ServeDNS(w, req)
		if w.written == nil || len(w.written.Answer) != 1 {
			t.Fatalf("query %d: reply = %v, want one answer", i, w.written)
		}
	}
	if rec.count() != 1 {
		t.Errorf("upstream got %d queries, want 1 (the rest from the cache)", rec.count())
	}
}

// mismatches are upstream replies that do not answer the query s-hole sent.
// Each one keeps an A record in the answer section, so a reply that is
// wrongly accepted would also reach the cache.
var mismatches = []struct {
	name   string
	mutate func(resp *dns.Msg)
}{
	{"other name", func(r *dns.Msg) {
		r.Question[0].Name = "evil.example.net."
		r.Answer[0].Header().Name = "evil.example.net."
	}},
	{"other type", func(r *dns.Msg) { r.Question[0].Qtype = dns.TypeAAAA }},
	{"other class", func(r *dns.Msg) { r.Question[0].Qclass = dns.ClassCHAOS }},
	{"QR clear", func(r *dns.Msg) { r.Response = false }},
	{"opcode NOTIFY", func(r *dns.Msg) { r.Opcode = dns.OpcodeNotify }},
	{"opcode UPDATE", func(r *dns.Msg) { r.Opcode = dns.OpcodeUpdate }},
	{"no question", func(r *dns.Msg) { r.Question = nil }},
	{"two questions", func(r *dns.Msg) {
		r.Question = append(r.Question, dns.Question{Name: "evil.example.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	}},
	{"two equal questions", func(r *dns.Msg) { r.Question = append(r.Question, r.Question[0]) }},
}

// mismatchReply answers like answerWith(ip), then applies mutate.
func mismatchReply(ip net.IP, mutate func(*dns.Msg)) replyFunc {
	return func(req *dns.Msg) *dns.Msg {
		resp := answerWith(ip)(req)
		mutate(resp)
		return resp
	}
}

func TestServeDNS_MismatchedReplyIsAFailure(t *testing.T) {
	// SEC-17: an upstream reply for another question, or one that is not a
	// reply to a QUERY, is a failed attempt. The client gets SERVFAIL,
	// nothing is cached, and the next query goes upstream again.
	for _, transport := range []string{"udp", "doh"} {
		for _, m := range mismatches {
			t.Run(transport+" "+m.name, func(t *testing.T) {
				reply := mismatchReply(net.IPv4(6, 6, 6, 6), m.mutate)
				var addr string
				var rec *queryRecorder
				if transport == "doh" {
					addr, rec = startRecordingDoH(t, reply)
				} else {
					addr, rec = startRecordingUpstream(t, reply, false)
				}
				c := cache.New(10)
				defer c.Close()
				counter := stats.New()
				h := testHandler([]string{addr}, c)
				h.counter = counter
				const name = "www.example.com."

				for i := 1; i <= 2; i++ {
					w := fakeClient()
					h.ServeDNS(w, bitsQuery(name, false, false, false, false))
					if w.written == nil || w.written.Rcode != dns.RcodeServerFailure || len(w.written.Answer) != 0 {
						t.Fatalf("query %d: reply = %v, want SERVFAIL without answers", i, w.written)
					}
					if rec.count() != i {
						t.Errorf("query %d: upstream got %d queries, want %d (nothing cached)", i, rec.count(), i)
					}
				}
				if _, _, size := c.Stats(); size != 0 {
					t.Errorf("cache holds %d entries, want 0", size)
				}
				if s := counter.Snapshot(0); s.ForwardFailures != 2 || s.UpstreamErrors != 0 {
					t.Errorf("forward failures %d, upstream errors %d; want 2 and 0 (s-hole failed the attempt)",
						s.ForwardFailures, s.UpstreamErrors)
				}
			})
		}
	}
}

func TestServeDNS_ReplyNameCaseMayDiffer(t *testing.T) {
	// SEC-17: DNS names are case-insensitive, so a reply whose question
	// differs from the query only in letter case is accepted and cached.
	for _, transport := range []string{"udp", "doh"} {
		t.Run(transport, func(t *testing.T) {
			ip := net.IPv4(5, 5, 5, 5)
			reply := mismatchReply(ip, func(r *dns.Msg) {
				r.Question[0].Name = strings.ToUpper(r.Question[0].Name)
			})
			var addr string
			if transport == "doh" {
				addr, _ = startRecordingDoH(t, reply)
			} else {
				addr, _ = startRecordingUpstream(t, reply, false)
			}
			c := cache.New(10)
			defer c.Close()
			h := testHandler([]string{addr}, c)
			req := bitsQuery("MiXeD.example.com.", false, false, false, false)
			w := fakeClient()
			h.ServeDNS(w, req)
			if w.written == nil || w.written.Rcode != dns.RcodeSuccess || !answerIP(w.written).Equal(ip) {
				t.Fatalf("reply = %v, want NOERROR with %v", w.written, ip)
			}
			if _, ok := c.Get(req); !ok {
				t.Error("the accepted reply is not in the cache")
			}
		})
	}
}

func TestForward_MismatchedReplyMovesToNextUpstream(t *testing.T) {
	// SEC-17: a mismatching reply fails that upstream only. s-hole goes on to
	// the next upstream and returns its answer.
	for _, m := range mismatches {
		t.Run(m.name, func(t *testing.T) {
			bad, badRec := startRecordingUpstream(t, mismatchReply(net.IPv4(6, 6, 6, 6), m.mutate), false)
			good, goodRec := startRecordingUpstream(t, answerWith(net.IPv4(7, 7, 7, 7)), false)
			tracker := newUpstreamTracker()
			resp, err := forwardWith(context.Background(), upstreamQuery(buildReq("next.example.com")), []string{bad, good}, tracker)
			if err != nil {
				t.Fatalf("forward error = %v, want the second upstream's answer", err)
			}
			if !answerIP(resp).Equal(net.IPv4(7, 7, 7, 7)) {
				t.Errorf("answer = %v, want 7.7.7.7 from the second upstream", resp.Answer)
			}
			if badRec.count() != 1 || goodRec.count() != 1 {
				t.Errorf("upstream queries: bad %d, good %d; want 1 and 1", badRec.count(), goodRec.count())
			}
			counts := tracker.TransportFailureCounts()
			if counts[bad] != 1 || counts[good] != 0 {
				t.Errorf("failure counts = %v, want 1 for %s and 0 for %s", counts, bad, good)
			}
		})
	}
}

func TestServeDNS_MismatchedTCPRetryKeepsTruncatedReply(t *testing.T) {
	// SEC-17: when the UDP reply is valid but truncated and the TCP retry
	// returns a reply that does not match, s-hole keeps the truncated UDP
	// reply, as it does when the TCP retry fails. Nothing is cached.
	for _, m := range mismatches {
		t.Run(m.name, func(t *testing.T) {
			addr, rec := startRecordingUpstream(t, mismatchReply(net.IPv4(6, 6, 6, 6), m.mutate), true)
			c := cache.New(10)
			defer c.Close()
			h := testHandler([]string{addr}, c)
			w := fakeClient()
			h.ServeDNS(w, bitsQuery("big.example.com.", false, false, false, false))
			if rec.count() != 2 {
				t.Fatalf("upstream got %d queries, want 2 (UDP, then TCP)", rec.count())
			}
			r := w.written
			if r == nil || r.Rcode != dns.RcodeSuccess || !r.Truncated || len(r.Answer) != 0 {
				t.Fatalf("reply = %v, want the truncated UDP reply (NOERROR, TC set, no answers)", r)
			}
			if len(r.Question) != 1 || r.Question[0].Name != "big.example.com." {
				t.Errorf("reply question = %v, want big.example.com.", r.Question)
			}
			if _, _, size := c.Stats(); size != 0 {
				t.Errorf("cache holds %d entries, want 0", size)
			}
		})
	}
}

func TestServeDNS_MismatchErrorNamesNoQuery(t *testing.T) {
	// SEC-17: the error for a mismatching reply reaches the once-a-minute
	// failure summary. Its text does not hold the queried name, and the
	// summary names no domain under any query_log.mode.
	for _, mode := range []string{"none", "blocked", "all"} {
		t.Run(mode, func(t *testing.T) {
			addr, _ := startRecordingUpstream(t, mismatchReply(net.IPv4(6, 6, 6, 6), mismatches[0].mutate), false)
			h := testHandler([]string{addr}, nil)
			h.SetQueryLogMode(mode)
			app := captureAppLog(t)
			w := fakeClient()
			h.ServeDNS(w, buildReq("secretname.example.com"))
			if w.written == nil || w.written.Rcode != dns.RcodeServerFailure {
				t.Fatalf("reply = %v, want SERVFAIL", w.written)
			}
			reportNow(h)
			sums := app.withMsg(t, "queries could not be resolved")
			if len(sums) != 1 {
				t.Fatalf("got %d summary lines, want 1:\n%s", len(sums), app.text())
			}
			causes, _ := sums[0]["causes"].(string)
			if !strings.Contains(causes, addr+": ") {
				t.Errorf("causes %q do not name the upstream %s with its error", causes, addr)
			}
			if strings.Contains(strings.ToLower(causes), "secretname") {
				t.Errorf("causes %q hold the queried name", causes)
			}
			if mode != "all" && strings.Contains(strings.ToLower(app.text()), "secretname") {
				t.Errorf("the application log names the query under mode %q:\n%s", mode, app.text())
			}
		})
	}
}

func TestServeDNS_RDClearIsRefused(t *testing.T) {
	// PRIV-05: a LAN query with RD=0 gets REFUSED with the client's ID and
	// question, whatever the name. It does not touch the cache (no lookup, no
	// store), the stats, the query log, the application log, or the
	// upstream, and it is not counted as a query from outside the LAN.
	queries := map[string]*dns.Msg{}
	for _, name := range []string{"cached.example.com.", "ads.example.com.", "uncached.example.com.", "localhost.", "app.localhost.", "hidden.onion.", "printer."} {
		queries[name] = bitsQuery(name, false, false, false, false)
	}
	ptr := new(dns.Msg)
	ptr.SetQuestion("5.1.168.192.in-addr.arpa.", dns.TypePTR)
	queries["private PTR"] = ptr
	queries["cached with EDNS and CD"] = bitsQuery("cached.example.com.", true, true, true, true)

	sources := map[string]*fakeWriter{
		"udp": fakeClient(),
		"tcp": {remote: &net.TCPAddr{IP: net.ParseIP("fd00::7"), Port: 40000}},
	}
	for srcName, src := range sources {
		t.Run(srcName, func(t *testing.T) {
			f := newRefusalFixture(t)
			app := captureAppLog(t)
			refusedBefore := RefusedQueries()
			hitsBefore, missesBefore, sizeBefore := f.cache.Stats()

			for label, req := range queries {
				req.RecursionDesired = false
				req.Id = 0x5A5A
				want := req.Question[0]
				w := &fakeWriter{remote: src.remote}
				f.h.ServeDNS(w, req)
				r := w.written
				if r == nil || r.Rcode != dns.RcodeRefused {
					t.Errorf("%s: reply = %v, want REFUSED", label, r)
					continue
				}
				if r.Id != 0x5A5A {
					t.Errorf("%s: reply ID = %#x, want the client's 0x5a5a", label, r.Id)
				}
				if len(r.Question) != 1 || r.Question[0] != want {
					t.Errorf("%s: reply question = %v, want [%v]", label, r.Question, want)
				}
				if len(r.Answer) != 0 || len(r.Ns) != 0 {
					t.Errorf("%s: REFUSED reply has records: answer %v, authority %v", label, r.Answer, r.Ns)
				}
			}

			if got := RefusedQueries() - refusedBefore; got != 0 {
				t.Errorf("RefusedQueries grew by %d, want 0 (it counts sources outside the LAN only)", got)
			}
			s := f.counter.Snapshot(10)
			if s.TotalQueries != 0 || s.BlockedCount != 0 || s.CacheHits != 0 || s.LocalPTRCount != 0 ||
				s.LocalNameCount != 0 || s.ForwardFailures != 0 || len(s.TopClients) != 0 || len(s.TopDomains) != 0 {
				t.Errorf("stats = %+v, want nothing counted", s)
			}
			if f.log.calls != 0 {
				t.Errorf("query logger called %d times, want 0", f.log.calls)
			}
			if hits, misses, size := f.cache.Stats(); hits != hitsBefore || misses != missesBefore || size != sizeBefore {
				t.Errorf("cache stats moved: hits %d->%d, misses %d->%d, size %d->%d",
					hitsBefore, hits, missesBefore, misses, sizeBefore, size)
			}
			if f.hits.Load() != 0 {
				t.Errorf("upstream got %d queries, want 0", f.hits.Load())
			}
			if recs := app.records(t); len(recs) != 0 {
				t.Errorf("application log got %d lines for RD=0 queries: %v", len(recs), recs)
			}

			// The same fixture answers an RD=1 query from the cache, so the
			// checks above can see a cache hit, a count, and a log row.
			w := &fakeWriter{remote: src.remote}
			f.h.ServeDNS(w, bitsQuery("cached.example.com.", false, false, false, false))
			if w.written == nil || w.written.Rcode != dns.RcodeSuccess || len(w.written.Answer) != 1 {
				t.Fatalf("RD=1 reply = %v, want the cached answer", w.written)
			}
			if hits, _, _ := f.cache.Stats(); hits != hitsBefore+1 {
				t.Errorf("cache hits = %d after the RD=1 query, want %d", hits, hitsBefore+1)
			}
			if s := f.counter.Snapshot(0); s.TotalQueries != 1 || s.CacheHits != 1 {
				t.Errorf("stats after the RD=1 query = %+v, want one counted cache hit", s)
			}
			if f.log.calls != 1 {
				t.Errorf("query logger called %d times after the RD=1 query, want 1", f.log.calls)
			}
		})
	}
}

func TestServeDNS_RDClearCheckOrder(t *testing.T) {
	// PRIV-05: the earlier checks still come first. A source outside the LAN
	// gets REFUSED from the LAN check (and is counted there), a query without
	// exactly one question gets SERVFAIL, and an opcode other than QUERY gets
	// NOTIMP, even with RD=0.
	outside := &fakeWriter{remote: &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 5353}}
	f := newRefusalFixture(t)
	before := RefusedQueries()
	req := bitsQuery("cached.example.com.", false, false, false, false)
	req.RecursionDesired = false
	f.h.ServeDNS(outside, req)
	if outside.written == nil || outside.written.Rcode != dns.RcodeRefused {
		t.Errorf("outside the LAN: reply = %v, want REFUSED", outside.written)
	}
	if got := RefusedQueries() - before; got != 1 {
		t.Errorf("outside the LAN: RefusedQueries grew by %d, want 1", got)
	}

	noQuestion := &dns.Msg{MsgHdr: dns.MsgHdr{Id: 7}}
	twoQuestions := &dns.Msg{MsgHdr: dns.MsgHdr{Id: 8}, Question: []dns.Question{
		{Name: "a.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}}
	notify := bitsQuery("cached.example.com.", false, false, false, false)
	notify.Opcode = dns.OpcodeNotify
	status := bitsQuery("cached.example.com.", false, false, false, false)
	status.Opcode = dns.OpcodeStatus
	cases := []struct {
		name  string
		req   *dns.Msg
		rcode int
	}{
		{"no question", noQuestion, dns.RcodeServerFailure},
		{"two questions", twoQuestions, dns.RcodeServerFailure},
		{"opcode NOTIFY", notify, dns.RcodeNotImplemented},
		{"opcode STATUS", status, dns.RcodeNotImplemented},
	}
	for _, tc := range cases {
		tc.req.RecursionDesired = false
		w := fakeClient()
		f.h.ServeDNS(w, tc.req)
		if w.written == nil || w.written.Rcode != tc.rcode {
			t.Errorf("%s with RD=0: reply = %v, want %s", tc.name, w.written, dns.RcodeToString[tc.rcode])
		}
	}
}

func TestServeDNS_CachedReplyTTLIsCapped(t *testing.T) {
	// SEC-18: a reply served from the cache never carries a TTL above
	// 86,400 s, even when the upstream gave a longer one.
	reply := func(req *dns.Msg) *dns.Msg {
		resp := answerWith(net.IPv4(8, 8, 4, 4))(req)
		resp.Answer[0].Header().Ttl = 1_000_000
		resp.Ns = []dns.RR{&dns.NS{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 500_000},
			Ns:  "ns.example.com.",
		}}
		return resp
	}
	addr, rec := startRecordingUpstream(t, reply, false)
	c := cache.New(10)
	defer c.Close()
	h := testHandler([]string{addr}, c)
	h.ServeDNS(fakeClient(), buildReq("long.example.com"))
	w := fakeClient()
	h.ServeDNS(w, buildReq("long.example.com"))
	if rec.count() != 1 {
		t.Fatalf("upstream got %d queries, want 1 (the second from the cache)", rec.count())
	}
	if w.written == nil || len(w.written.Answer) != 1 || len(w.written.Ns) != 1 {
		t.Fatalf("cached reply = %v, want one answer and one authority record", w.written)
	}
	for _, rr := range append(w.written.Answer, w.written.Ns...) {
		if ttl := rr.Header().Ttl; ttl > 86_400 || ttl < 86_390 {
			t.Errorf("cached %s TTL = %d, want 86400 (the cap, less a few seconds)", dns.TypeToString[rr.Header().Rrtype], ttl)
		}
	}
}

func TestUpstreamQuery_CopiesEachClientBit(t *testing.T) {
	// CL 94: the fresh upstream query copies the client's RD, CD, and AD
	// bits, one by one. With RD=1, CD=0, and AD=0 the upstream query has CD
	// and AD clear. The client's DO bit sets DO in s-hole's own OPT record
	// (UDP size 1232).
	cases := []struct {
		name      string
		cd, ad    bool
		clientOPT bool
		do        bool
	}{
		{"CD and AD clear, OPT without DO", false, false, true, false},
		{"CD and AD clear, no OPT", false, false, false, false},
		{"CD and AD clear, OPT with DO", false, false, true, true},
		{"CD only", true, false, false, false},
		{"AD only", false, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, rec := startRecordingUpstream(t, answerWith(net.IPv4(4, 4, 4, 4)), false)
			h := testHandler([]string{addr}, nil)
			req := noisyQuery("WwW.ExAmPlE.CoM.")
			req.CheckingDisabled = tc.cd
			req.AuthenticatedData = tc.ad
			if tc.clientOPT {
				withOPT(req, 4096, tc.do, clientOptions()...)
			}
			w := fakeClient()
			h.ServeDNS(w, req)
			if rec.count() != 1 {
				t.Fatalf("upstream got %d queries, want 1", rec.count())
			}
			got, _, _ := rec.get(0)
			want := dns.Question{Name: "WwW.ExAmPlE.CoM.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
			checkUpstreamQuery(t, got, want, true, tc.cd, tc.ad, tc.do)
			if o := got.IsEdns0(); o != nil && len(o.Option) != 0 {
				t.Errorf("upstream OPT options = %v, want none over plain UDP", o.Option)
			}
			if w.written == nil || w.written.Rcode != dns.RcodeSuccess {
				t.Errorf("client reply = %v, want NOERROR", w.written)
			}
		})
	}
}

func TestUpstreamQuery_DoHHasIDZeroAndOnlyPadding(t *testing.T) {
	// CL 94: a DoH query has ID 0 and the same minimal content as a plain
	// query, with one EDNS option: s-hole's own Padding. The POST body is a
	// multiple of 128 bytes long (RFC 8467), for short and long names.
	endpoint, rec := startRecordingDoH(t, answerWith(net.IPv4(9, 9, 9, 9)))
	h := testHandler([]string{endpoint}, nil)

	names := []string{"a.io.", "WwW.ExAmPlE.CoM."}
	for i := 1; i <= 6; i++ {
		names = append(names, strings.Repeat("abcdefghij", i)+".example.net.")
	}
	for i, name := range names {
		req := noisyQuery(name)
		cd, ad := i%2 == 0, i%3 == 0
		req.CheckingDisabled, req.AuthenticatedData = cd, ad
		do := false
		if i%2 == 0 {
			do = i%4 == 0
			withOPT(req, 4096, do, clientOptions()...)
		}
		h.ServeDNS(fakeClient(), req)
		if rec.count() != i+1 {
			t.Fatalf("%s: DoH upstream got %d queries, want %d", name, rec.count(), i+1)
		}
		got, _, size := rec.get(i)
		if got.Id != 0 {
			t.Errorf("%s: DoH query ID = %#x, want 0", name, got.Id)
		}
		want := dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
		checkUpstreamQuery(t, got, want, true, cd, ad, do)
		o := got.IsEdns0()
		if o == nil {
			continue // checkUpstreamQuery has reported it
		}
		if len(o.Option) != 1 || o.Option[0].Option() != dns.EDNS0PADDING {
			t.Errorf("%s: DoH OPT options = %v, want only one Padding option", name, o.Option)
		}
		if size%128 != 0 {
			t.Errorf("%s: DoH body is %d bytes, want a multiple of 128", name, size)
		}
	}
}

func TestServeDNS_CacheKeepsNoOPT(t *testing.T) {
	// CL 94 with b/096: the cache stores replies without an OPT record, so
	// the upstream's EDNS options never reach another client. Each client
	// gets an OPT record mirrored from its own query (its UDP size and DO
	// bit, no options), or none when its query had none. Clients with the
	// same CD and DO bits share one upstream query; a client with the other
	// DO bit causes one more.
	upstreamReply := func(req *dns.Msg) *dns.Msg {
		return withOPT(answerWith(net.IPv4(4, 4, 4, 4))(req), 4096, true, upstreamOptions()...)
	}
	const name = "shared.example.com."
	clients := []struct {
		name string
		opt  bool
		size uint16
		do   bool
	}{
		{"EDNS 4096 with DO and options", true, 4096, true},
		{"no EDNS", false, 0, false},
		{"EDNS 1300 without DO", true, 1300, false},
		{"EDNS 2000 with DO", true, 2000, true},
		{"no EDNS again", false, 0, false},
	}
	for _, first := range []int{0, 1} {
		t.Run(clients[first].name+" first", func(t *testing.T) {
			addr, rec := startRecordingUpstream(t, upstreamReply, false)
			c := cache.New(10)
			defer c.Close()
			h := testHandler([]string{addr}, c)

			for _, i := range append([]int{first}, 0, 1, 2, 3, 4) {
				cl := clients[i]
				req := new(dns.Msg)
				req.SetQuestion(name, dns.TypeA)
				if cl.opt {
					withOPT(req, cl.size, cl.do, clientOptions()...)
				}
				w := fakeClient()
				h.ServeDNS(w, req)
				if w.written == nil || len(w.written.Answer) != 1 {
					t.Fatalf("%s: reply = %v, want one answer", cl.name, w.written)
				}
				opts := optRecords(w.written)
				if !cl.opt {
					if len(opts) != 0 {
						t.Errorf("%s: reply has OPT %v, want none", cl.name, opts)
					}
					continue
				}
				if len(opts) != 1 {
					t.Fatalf("%s: reply has %d OPT records, want 1", cl.name, len(opts))
				}
				if opts[0].UDPSize() != cl.size || opts[0].Do() != cl.do || len(opts[0].Option) != 0 {
					t.Errorf("%s: reply OPT = size %d DO %v options %v; want size %d DO %v and no options",
						cl.name, opts[0].UDPSize(), opts[0].Do(), opts[0].Option, cl.size, cl.do)
				}
			}
			if rec.count() != 2 {
				t.Errorf("upstream got %d queries, want 2 (one per DO bit, the rest from the cache)", rec.count())
			}
			for _, do := range []bool{false, true} {
				m, ok := c.Get(bitsQuery(name, false, false, true, do))
				if !ok {
					t.Fatalf("the DO=%v reply is not in the cache", do)
				}
				if len(optRecords(m)) != 0 || m.IsEdns0() != nil {
					t.Errorf("cached DO=%v reply has an OPT record: %v", do, m.Extra)
				}
			}
		})
	}
}
