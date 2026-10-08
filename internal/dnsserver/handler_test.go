package dnsserver

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// fakeWriter captures the response written by Handler.ServeDNS.
type fakeWriter struct {
	remote     net.Addr
	written    *dns.Msg
	writeError error
}

func (w *fakeWriter) LocalAddr() net.Addr  { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (w *fakeWriter) RemoteAddr() net.Addr { return w.remote }
func (w *fakeWriter) WriteMsg(m *dns.Msg) error {
	w.written = m
	return w.writeError
}
func (w *fakeWriter) Write([]byte) (int, error) { return 0, nil }
func (w *fakeWriter) Close() error              { return nil }
func (w *fakeWriter) TsigStatus() error         { return nil }
func (w *fakeWriter) TsigTimersOnly(bool)       {}
func (w *fakeWriter) Hijack()                   {}

// nullLogger is a Logger that records nothing.
type nullLogger struct{}

func (nullLogger) Log(querylog.Record) {}

// buildReq creates a single-question A query for name.
func buildReq(name string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return req
}

// fakeClient builds a fakeWriter with a sensible client RemoteAddr.
func fakeClient() *fakeWriter {
	return &fakeWriter{
		remote: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 33333},
	}
}

// customAddr is a net.Addr that is neither *net.UDPAddr nor *net.TCPAddr.
type customAddr string

func (c customAddr) Network() string { return "custom" }
func (c customAddr) String() string  { return string(c) }

func TestMaskClientIP(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		mode string
		want string
	}{
		{"full ipv4", "192.168.1.7", "full", "192.168.1.7"},
		{"full ipv6", "2001:db8::1", "full", "2001:db8::1"},
		{"drop ipv4", "192.168.1.7", "drop", ""},
		{"drop unparseable value", "unknown", "drop", ""},
		{"subnet ipv4", "192.168.1.7", "subnet", "192.168.1.0"},
		{"subnet ipv4 other octet", "10.4.5.6", "subnet", "10.4.5.0"},
		{"subnet ipv6 to /64", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", "subnet", "2001:db8:1:2::"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := querylog.MaskClientIP(tc.ip, tc.mode); got != tc.want {
				t.Errorf("MaskClientIP(%q, %q) = %q, want %q", tc.ip, tc.mode, got, tc.want)
			}
		})
	}
}

// captureLogger records the last Record handed to Log so a test can assert the
// query-log sink sees the masked address and the right per-query fields.
type captureLogger struct {
	clientIP string
	last     querylog.Record
	calls    int
}

func (c *captureLogger) Log(rec querylog.Record) {
	c.clientIP = rec.ClientIP
	c.last = rec
	c.calls++
}

// TestServeDNS_MasksClientEverywhere proves query_privacy masks the client at
// the single choke point, so both the query-log sink and the in-memory stats
// counter (Top Clients) see the masked value. A logger-only decorator would
// mask the log but leave the counter holding the raw IP.
func TestServeDNS_MasksClientEverywhere(t *testing.T) {
	cases := []struct {
		mode string
		want string
	}{
		{"full", "192.168.1.100"},
		{"drop", ""},
		{"subnet", "192.168.1.0"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			store := blocklist.NewStore()
			store.Replace([]string{"ads.example.com"})
			counter := stats.New()
			log := &captureLogger{}

			// A blocked query logs then writes a sinkhole reply, so it never
			// forwards upstream: the client value is recorded on both paths.
			h := NewHandler(store, counter, nil, log, "zero", 60, nil, false, tc.mode)
			h.SetQueryLogMode("all")
			h.ServeDNS(fakeClient(), buildReq("ads.example.com"))

			if log.calls != 1 {
				t.Fatalf("logger called %d times, want 1", log.calls)
			}
			if log.clientIP != tc.want {
				t.Errorf("logged client = %q, want %q", log.clientIP, tc.want)
			}
			clients := counter.Snapshot(10).TopClients
			if tc.want == "" {
				// A dropped client is not tallied at all.
				if len(clients) != 0 {
					t.Fatalf("stats top clients = %v, want none", clients)
				}
				return
			}
			if len(clients) != 1 {
				t.Fatalf("stats top clients = %d entries, want 1", len(clients))
			}
			if clients[0].Name != tc.want {
				t.Errorf("stats top client = %q, want %q", clients[0].Name, tc.want)
			}
		})
	}
}

func TestServeDNS_BlockedZeroMode(t *testing.T) {
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "full")
	w := fakeClient()
	h.ServeDNS(w, buildReq("ads.example.com"))

	if w.written == nil {
		t.Fatal("no response written")
	}
	if len(w.written.Answer) != 1 {
		t.Fatalf("Answer count = %d, want 1", len(w.written.Answer))
	}
	a, ok := w.written.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer not an A record: %T", w.written.Answer[0])
	}
	if !a.A.Equal(net.IPv4zero) {
		t.Errorf("sinkhole A = %v, want 0.0.0.0", a.A)
	}
}

func TestServeDNS_BlockedNxdomainMode(t *testing.T) {
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "nxdomain", 60, nil, false, "full")
	w := fakeClient()
	h.ServeDNS(w, buildReq("ads.example.com"))

	if w.written == nil {
		t.Fatal("no response written")
	}
	if w.written.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want NXDOMAIN (%d)", w.written.Rcode, dns.RcodeNameError)
	}
}

func TestServeDNS_AllowlistOverridesBlock(t *testing.T) {
	store := blocklist.NewStore()
	store.Replace([]string{"example.com"})
	store.AddToAllowlist("example.com")

	c := cache.New(10)
	defer c.Close()

	// Pre-populate the cache so we don't hit the network.
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	preCached := buildResp(q, net.IPv4(8, 8, 8, 8), 300)
	c.Set(asQuery(q), preCached)

	counter := stats.New()
	h := NewHandler(store, counter, nil, nullLogger{}, "zero", 60, c, false, "full")
	w := fakeClient()
	h.ServeDNS(w, buildReq("example.com"))

	if w.written == nil {
		t.Fatal("no response written")
	}
	if len(w.written.Answer) != 1 {
		t.Fatal("expected cached answer, got none")
	}
	a := w.written.Answer[0].(*dns.A)
	if !a.A.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Errorf("allowlisted domain not served from cache: A=%v", a.A)
	}
	// Block stats should be zero.
	if s := counter.Snapshot(0); s.BlockedCount != 0 {
		t.Errorf("BlockedCount = %d, want 0 (allowlist)", s.BlockedCount)
	}
}

func TestServeDNS_CacheHitAvoidsUpstream(t *testing.T) {
	store := blocklist.NewStore() // empty
	c := cache.New(10)
	defer c.Close()

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(asQuery(q), buildResp(q, net.IPv4(1, 2, 3, 4), 300))

	counter := stats.New()
	// Upstream is unreachable on purpose: if the cache path works, we
	// never call forward, so this must succeed.
	unreachable := []string{"127.0.0.1:1"}
	h := NewHandler(store, counter, unreachable, nullLogger{}, "zero", 60, c, false, "full")

	w := fakeClient()
	h.ServeDNS(w, buildReq("example.com"))

	if w.written == nil {
		t.Fatal("no response written (cache hit should have succeeded)")
	}
	if len(w.written.Answer) != 1 {
		t.Fatal("no Answer records in cached response")
	}
	a := w.written.Answer[0].(*dns.A)
	if !a.A.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Errorf("cache hit served wrong A: %v", a.A)
	}

	if s := counter.Snapshot(0); s.CacheHits != 1 {
		t.Errorf("CacheHits = %d, want 1", s.CacheHits)
	}
}

// TestServeDNS_LogsCacheHit proves the query-log Record carries CacheHit=true
// only for a reply served from the cache. A blocked query short-circuits before
// the cache, so it logs CacheHit=false (ROADMAP #29).
func TestServeDNS_LogsCacheHit(t *testing.T) {
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	t.Run("cache hit logs CacheHit=true", func(t *testing.T) {
		store := blocklist.NewStore() // empty: query is allowed
		c := cache.New(10)
		defer c.Close()
		c.Set(asQuery(q), buildResp(q, net.IPv4(1, 2, 3, 4), 300))
		log := &captureLogger{}
		h := NewHandler(store, stats.New(), nil, log, "zero", 60, c, false, "full")

		h.ServeDNS(fakeClient(), buildReq("example.com"))

		if log.calls != 1 {
			t.Fatalf("logger called %d times, want 1", log.calls)
		}
		if !log.last.CacheHit || log.last.Blocked {
			t.Errorf("cache-hit record = %+v, want CacheHit=true Blocked=false", log.last)
		}
	})

	t.Run("blocked logs CacheHit=false", func(t *testing.T) {
		store := blocklist.NewStore()
		store.Replace([]string{"ads.example.com"})
		c := cache.New(10)
		defer c.Close()
		log := &captureLogger{}
		h := NewHandler(store, stats.New(), nil, log, "zero", 60, c, false, "full")

		h.ServeDNS(fakeClient(), buildReq("ads.example.com"))

		if !log.last.Blocked || log.last.CacheHit {
			t.Errorf("blocked record = %+v, want Blocked=true CacheHit=false", log.last)
		}
	})
}

func TestServeDNS_EmptyQuestion(t *testing.T) {
	store := blocklist.NewStore()
	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "full")
	w := fakeClient()

	req := new(dns.Msg)
	// Question slice is empty.
	h.ServeDNS(w, req)

	if w.written == nil {
		t.Fatal("expected SERVFAIL response, got nothing")
	}
	if w.written.Rcode != dns.RcodeServerFailure {
		t.Errorf("Rcode = %d, want SERVFAIL", w.written.Rcode)
	}
}

func TestServeDNS_BlockedPreservesEDNS0(t *testing.T) {
	// R12: clients that advertise EDNS0 expect the OPT record to be
	// echoed in the reply. A missing OPT causes some resolvers to fall
	// back to legacy DNS, adding round trips. Verify that a sinkholed
	// reply still carries OPT.
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "full")
	w := fakeClient()
	req := new(dns.Msg)
	req.SetQuestion("ads.example.com.", dns.TypeA)
	req.SetEdns0(4096, true)

	h.ServeDNS(w, req)
	if w.written == nil {
		t.Fatal("no response written")
	}
	if w.written.IsEdns0() == nil {
		t.Error("sinkhole reply dropped OPT pseudo-record; clients will fall back to legacy DNS")
	}
}

func TestServeDNS_CacheMissForwardsToUpstream(t *testing.T) {
	// Exercises the cache-miss → forward → cache-set → write path. With
	// no entry in the cache, the handler must dispatch to the upstream
	// mock and store the result.
	addr, hits := startMockUpstream(t, net.IPv4(4, 4, 4, 4))

	store := blocklist.NewStore()
	c := cache.New(10)
	defer c.Close()

	h := NewHandler(store, stats.New(), []string{addr}, nullLogger{}, "zero", 60, c, false, "full")
	w := fakeClient()
	h.ServeDNS(w, buildReq("example.com"))

	if hits.Load() != 1 {
		t.Errorf("upstream got %d queries, want 1", hits.Load())
	}
	if w.written == nil || len(w.written.Answer) != 1 {
		t.Fatal("no answer written to client")
	}
	// And the result should now be cached.
	if _, ok := c.Get(asQuery(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})); !ok {
		t.Error("response was not stored in the cache after forward")
	}
}

func TestServeDNS_UpstreamFailureProducesServfail(t *testing.T) {
	// All upstreams are unreachable. Handler must answer SERVFAIL
	// (writeRcode) rather than write a malformed reply.
	store := blocklist.NewStore()
	h := NewHandler(store, stats.New(), []string{"127.0.0.1:1"}, nullLogger{}, "zero", 60, nil, false, "full")
	w := fakeClient()
	h.ServeDNS(w, buildReq("example.com"))
	if w.written == nil {
		t.Fatal("no response written")
	}
	if w.written.Rcode != dns.RcodeServerFailure {
		t.Errorf("Rcode = %d, want SERVFAIL", w.written.Rcode)
	}
}

// TestServeDNS_LogsOutcome proves the forward path records the query outcome
// (rcode + synthesized) and bumps the matching failure counter (CL 77). The
// three cases that reach the forward step: a clean NOERROR answer, an
// unresolved query (every upstream failed, s-hole synthesizes SERVFAIL), and a
// relayed upstream failure rcode (the upstream answered SERVFAIL/REFUSED).
func TestServeDNS_LogsOutcome(t *testing.T) {
	t.Run("ok forwarded NOERROR", func(t *testing.T) {
		addr, _ := startMockUpstream(t, net.IPv4(4, 4, 4, 4))
		counter := stats.New()
		log := &captureLogger{}
		h := NewHandler(blocklist.NewStore(), counter, []string{addr}, log, "zero", 60, nil, false, "full")

		h.ServeDNS(fakeClient(), buildReq("example.com"))

		if log.calls != 1 {
			t.Fatalf("logger called %d times, want 1", log.calls)
		}
		if log.last.Synthesized || log.last.Rcode != dns.RcodeSuccess || log.last.Failed() {
			t.Errorf("record = %+v, want Rcode=0 Synthesized=false not-failed", log.last)
		}
		if s := counter.Snapshot(0); s.ForwardFailures != 0 || s.UpstreamErrors != 0 {
			t.Errorf("counters = {forward %d, upstream %d}, want {0, 0}", s.ForwardFailures, s.UpstreamErrors)
		}
	})

	t.Run("unresolved when all upstreams fail", func(t *testing.T) {
		counter := stats.New()
		log := &captureLogger{}
		h := NewHandler(blocklist.NewStore(), counter, []string{"127.0.0.1:1"}, log, "zero", 60, nil, false, "full")

		w := fakeClient()
		h.ServeDNS(w, buildReq("example.com"))

		if w.written == nil || w.written.Rcode != dns.RcodeServerFailure {
			t.Fatalf("client reply = %+v, want SERVFAIL", w.written)
		}
		if !log.last.Unresolved() || !log.last.Synthesized || log.last.Rcode != dns.RcodeServerFailure {
			t.Errorf("record = %+v, want unresolved (SERVFAIL, synthesized)", log.last)
		}
		if s := counter.Snapshot(0); s.ForwardFailures != 1 || s.UpstreamErrors != 0 {
			t.Errorf("counters = {forward %d, upstream %d}, want {1, 0}", s.ForwardFailures, s.UpstreamErrors)
		}
	})

	for _, rc := range []int{dns.RcodeServerFailure, dns.RcodeRefused} {
		t.Run("upstream error relaying rcode "+dns.RcodeToString[rc], func(t *testing.T) {
			addr, _ := startMockUpstreamRcode(t, rc)
			counter := stats.New()
			log := &captureLogger{}
			h := NewHandler(blocklist.NewStore(), counter, []string{addr}, log, "zero", 60, nil, false, "full")

			w := fakeClient()
			h.ServeDNS(w, buildReq("example.com"))

			if w.written == nil || w.written.Rcode != rc {
				t.Fatalf("client reply rcode = %v, want relayed %v", w.written, dns.RcodeToString[rc])
			}
			if !log.last.UpstreamError() || log.last.Synthesized || log.last.Rcode != rc {
				t.Errorf("record = %+v, want upstream error (rcode %d, not synthesized)", log.last, rc)
			}
			if s := counter.Snapshot(0); s.UpstreamErrors != 1 || s.ForwardFailures != 0 {
				t.Errorf("counters = {forward %d, upstream %d}, want {0, 1}", s.ForwardFailures, s.UpstreamErrors)
			}
		})
	}
}

func TestServeDNS_WriteSinkholeErrorIsLogged(t *testing.T) {
	// Confirm the writeSinkhole error branch is exercised when the
	// ResponseWriter fails. We don't capture log output here; the
	// purpose is to drive the branch for coverage and ensure the
	// handler doesn't panic.
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "full")
	w := fakeClient()
	w.writeError = errFakeWriteFailed
	h.ServeDNS(w, buildReq("ads.example.com"))
	if w.written == nil {
		t.Error("WriteMsg should still have been called (just with an error)")
	}
}

// errFakeWriteFailed is a sentinel injected via fakeWriter.writeError.
var errFakeWriteFailed = fakeError{}

type fakeError struct{}

func (fakeError) Error() string { return "fake write failed" }

func TestServeDNS_BlockedMXReturnsNoAnswer(t *testing.T) {
	// Blocked domain in zero mode, queried for MX: handler should reply
	// NOERROR with no Answer rather than fabricating an MX record.
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "full")
	w := fakeClient()
	req := new(dns.Msg)
	req.SetQuestion("ads.example.com.", dns.TypeMX)
	h.ServeDNS(w, req)

	if w.written == nil {
		t.Fatal("no response written")
	}
	if w.written.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want NOERROR", w.written.Rcode)
	}
	if len(w.written.Answer) != 0 {
		t.Errorf("Answer = %v, want empty", w.written.Answer)
	}
}

func TestIsPrivatePTR(t *testing.T) {
	// Verify the zone-list covers all RFC 6303 private ranges and that
	// non-PTR queries and public-range PTR queries are not matched.
	cases := []struct {
		name  string
		qtype uint16
		want  bool
	}{
		// RFC 1918 IPv4, private
		{"1.0.0.10.in-addr.arpa.", dns.TypePTR, true},
		{"255.255.0.10.in-addr.arpa.", dns.TypePTR, true},
		{"1.1.16.172.in-addr.arpa.", dns.TypePTR, true},
		{"1.1.31.172.in-addr.arpa.", dns.TypePTR, true},
		{"1.1.168.192.in-addr.arpa.", dns.TypePTR, true},
		// Zone apex itself
		{"168.192.in-addr.arpa.", dns.TypePTR, true},
		// Mixed-case names must still match: DNS is case-insensitive and
		// dns-0x20 forwarders randomise case (b/032, ultrareview bug_004).
		{"1.1.168.192.IN-ADDR.ARPA.", dns.TypePTR, true},
		{"1.1.168.192.In-Addr.Arpa.", dns.TypePTR, true},
		// IPv6 ULA
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.", dns.TypePTR, true},
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.f.ip6.arpa.", dns.TypePTR, true},
		// IPv6 link-local
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.", dns.TypePTR, true},
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.e.f.ip6.arpa.", dns.TypePTR, true},
		// Public range, must not match
		{"4.3.2.1.in-addr.arpa.", dns.TypePTR, false},
		{"8.8.8.8.in-addr.arpa.", dns.TypePTR, false},
		// 172.15 is NOT in 172.16/12
		{"1.1.15.172.in-addr.arpa.", dns.TypePTR, false},
		// Same name but wrong qtype, must not match
		{"1.0.0.10.in-addr.arpa.", dns.TypeA, false},
		{"1.0.0.10.in-addr.arpa.", dns.TypeAAAA, false},
	}
	for _, tc := range cases {
		if got := isPrivatePTR(tc.qtype, tc.name); got != tc.want {
			t.Errorf("isPrivatePTR(%d, %q) = %v, want %v", tc.qtype, tc.name, got, tc.want)
		}
	}
}

func TestServeDNS_LocalPTRReturnsNXDOMAIN(t *testing.T) {
	// Private PTR query with localPTR enabled must yield authoritative
	// NXDOMAIN without touching the upstream or the blocklist.
	store := blocklist.NewStore()
	counter := stats.New()
	h := NewHandler(store, counter, []string{"127.0.0.1:1"}, nullLogger{}, "zero", 60, nil, true, "full")
	w := fakeClient()
	req := new(dns.Msg)
	req.SetQuestion("1.1.168.192.in-addr.arpa.", dns.TypePTR)
	h.ServeDNS(w, req)

	if w.written == nil {
		t.Fatal("no response written")
	}
	if w.written.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want NXDOMAIN", w.written.Rcode)
	}
	if !w.written.Authoritative {
		t.Error("local PTR reply must be authoritative")
	}
	s := counter.Snapshot(0)
	if s.LocalPTRCount != 1 {
		t.Errorf("LocalPTRCount = %d, want 1", s.LocalPTRCount)
	}
	if s.BlockedCount != 0 {
		t.Errorf("BlockedCount = %d, want 0 (local PTR must not count as blocked)", s.BlockedCount)
	}
}

func TestServeDNS_LocalPTRDisabledForwardsUpstream(t *testing.T) {
	// With localPTR disabled, private PTR queries are forwarded normally.
	addr, hits := startMockUpstream(t, net.IPv4(0, 0, 0, 0))
	store := blocklist.NewStore()
	h := NewHandler(store, stats.New(), []string{addr}, nullLogger{}, "zero", 60, nil, false, "full")
	w := fakeClient()
	req := new(dns.Msg)
	req.SetQuestion("1.1.168.192.in-addr.arpa.", dns.TypePTR)
	h.ServeDNS(w, req)

	if hits.Load() != 1 {
		t.Errorf("upstream hits = %d, want 1 (localPTR disabled)", hits.Load())
	}
}

func TestServeDNS_LocalPTRPreservesEDNS0(t *testing.T) {
	// The EDNS0 OPT record must be echoed on local PTR replies for the same
	// reason as on sinkhole replies (R12): clients that advertised it must
	// see it echoed or they fall back to legacy DNS.
	store := blocklist.NewStore()
	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, true, "full")
	w := fakeClient()
	req := new(dns.Msg)
	req.SetQuestion("1.1.168.192.in-addr.arpa.", dns.TypePTR)
	req.SetEdns0(4096, true)
	h.ServeDNS(w, req)

	if w.written == nil {
		t.Fatal("no response written")
	}
	if w.written.IsEdns0() == nil {
		t.Error("local PTR reply dropped OPT pseudo-record; clients will fall back to legacy DNS")
	}
}

func TestServeDNS_NonPrivatePTRIsForwarded(t *testing.T) {
	// A PTR query for a public IP address (not in any private range) must
	// not be intercepted and must reach the upstream.
	addr, hits := startMockUpstream(t, net.IPv4(1, 2, 3, 4))
	store := blocklist.NewStore()
	h := NewHandler(store, stats.New(), []string{addr}, nullLogger{}, "zero", 60, nil, true, "full")
	w := fakeClient()
	req := new(dns.Msg)
	req.SetQuestion("4.3.2.1.in-addr.arpa.", dns.TypePTR)
	h.ServeDNS(w, req)

	if hits.Load() != 1 {
		t.Errorf("upstream hits = %d, want 1 (public PTR must be forwarded)", hits.Load())
	}
}

// buildResp constructs a NOERROR A response for q with ip and ttl.
// Local helper so we don't pull in the cache_test package.
func buildResp(q dns.Question, ip net.IP, ttl uint32) *dns.Msg {
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
			A: ip,
		},
	}
	return msg
}

// BenchmarkHandler_ServeDNS guards the two hot paths the handler can serve
// without touching the network: a blocked query (sinkhole reply) and a
// cache hit. The forwarding path is deliberately excluded; it is bounded
// by the upstream round-trip, not by handler code, and cannot be measured
// without a network stub. Each sub-benchmark drives ServeDNS through a stub
// ResponseWriter (fakeWriter); ReportAllocs surfaces per-query allocation
// regressions in the request-routing code.
func BenchmarkHandler_ServeDNS(b *testing.B) {
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	b.Run("Blocked", func(b *testing.B) {
		store := blocklist.NewStore()
		store.Replace([]string{"example.com"})
		h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "full")
		w := fakeClient()
		req := buildReq("example.com")

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			h.ServeDNS(w, req)
		}
	})

	b.Run("Cached", func(b *testing.B) {
		c := cache.New(1024)
		defer c.Close()
		c.Set(asQuery(q), buildResp(q, net.IPv4(1, 2, 3, 4), 300))

		store := blocklist.NewStore() // empty: query is allowed, served from cache
		h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, c, false, "full")
		w := fakeClient()
		req := buildReq("example.com")

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			h.ServeDNS(w, req)
		}
	})
}

// BenchmarkHandler_ServeDNS_Parallel drives the same two network-free paths
// under the concurrency the handler actually runs in: miekg/dns spawns one
// goroutine per query, so many ServeDNS calls hit the shared Store, Cache,
// and stats.Counter at once. This is the contention the serial benchmark
// cannot see, and where a lock regression (an exclusive Lock on the read
// path, or real work under the stats mutex) shows up. Each goroutine gets its
// own ResponseWriter because fakeWriter records the reply; the request is
// read-only during ServeDNS, so all goroutines share it.
func BenchmarkHandler_ServeDNS_Parallel(b *testing.B) {
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	b.Run("Blocked", func(b *testing.B) {
		store := blocklist.NewStore()
		store.Replace([]string{"example.com"})
		h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "full")
		req := buildReq("example.com")

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			w := fakeClient()
			for pb.Next() {
				h.ServeDNS(w, req)
			}
		})
	})

	b.Run("Cached", func(b *testing.B) {
		c := cache.New(1024)
		defer c.Close()
		c.Set(asQuery(q), buildResp(q, net.IPv4(1, 2, 3, 4), 300))

		store := blocklist.NewStore() // empty: query is allowed, served from cache
		h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, c, false, "full")
		req := buildReq("example.com")

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			w := fakeClient()
			for pb.Next() {
				h.ServeDNS(w, req)
			}
		})
	})
}

// asQuery returns a client query for q as the cache keys it: CD and DO clear.
func asQuery(q dns.Question) *dns.Msg {
	return &dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: true}, Question: []dns.Question{q}}
}

func TestServeDNS_StoredClientCarriesNoZone(t *testing.T) {
	// b/101 (CL 101): a link-local source with a zone is stored without the
	// zone: the address under clients "full", and its /64 under "subnet". The
	// query log and the Top Clients tally see the same value.
	cases := []struct {
		mode string
		want string
	}{
		{"full", "fe80::1"},
		{"subnet", "fe80::"},
	}
	sources := map[string]net.Addr{
		"udp": &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 5353, Zone: "eth0"},
		"tcp": &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 5353, Zone: "eth0"},
		// An address of another type keeps the zone in its String().
		"other type": customAddr("[fe80::1%eth0]:5353"),
	}
	for _, tc := range cases {
		for label, src := range sources {
			t.Run(tc.mode+" "+label, func(t *testing.T) {
				store := blocklist.NewStore()
				store.Replace([]string{"ads.example.com"})
				counter := stats.New()
				log := &captureLogger{}
				h := NewHandler(store, counter, nil, log, "zero", 60, nil, false, tc.mode)
				h.lan = testACL(newFakeAddrs())
				h.SetQueryLogMode("all")
				w := &fakeWriter{remote: src}
				h.ServeDNS(w, buildReq("ads.example.com"))
				if w.written == nil || w.written.Rcode != dns.RcodeSuccess {
					t.Fatalf("reply = %v, want the sinkhole answer", w.written)
				}
				if log.calls != 1 || log.clientIP != tc.want {
					t.Errorf("logged client = %q (%d calls), want %q", log.clientIP, log.calls, tc.want)
				}
				clients := counter.Snapshot(10).TopClients
				if len(clients) != 1 || clients[0].Name != tc.want {
					t.Errorf("top clients = %v, want %q", clients, tc.want)
				}
			})
		}
	}
}

// ptrQuery builds a PTR query for name.
func ptrQuery(name string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypePTR)
	return req
}

// ip6Name returns the ip6.arpa name of the first n nibbles of addr: n = 32
// names the address, n = 16 its /64.
func ip6Name(t *testing.T, addr string, n int) string {
	t.Helper()
	full, err := dns.ReverseAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	labels := dns.SplitDomainName(full)
	nibbles := labels[:32] // the last two labels are "ip6" and "arpa"
	return strings.Join(nibbles[32-n:], ".") + ".ip6.arpa."
}

// localPTRZoneNames are names under each reverse zone that s-hole answers
// itself (RFC 6303, RFC 6598): a zone apex and a name under it.
func localPTRZoneNames() []string {
	names := []string{
		"0.in-addr.arpa.", "0.0.0.0.in-addr.arpa.", "5.4.3.0.in-addr.arpa.",
		"127.in-addr.arpa.", "1.0.0.127.in-addr.arpa.", "254.255.255.127.in-addr.arpa.",
		"254.169.in-addr.arpa.", "4.3.254.169.in-addr.arpa.",
		"2.0.192.in-addr.arpa.", "1.2.0.192.in-addr.arpa.",
		"100.51.198.in-addr.arpa.", "7.100.51.198.in-addr.arpa.",
		"113.0.203.in-addr.arpa.", "9.113.0.203.in-addr.arpa.",
		"255.255.255.255.in-addr.arpa.",
		strings.Repeat("0.", 32) + "ip6.arpa.",
		"1." + strings.Repeat("0.", 31) + "ip6.arpa.",
		"8.b.d.0.1.0.0.2.ip6.arpa.",
		"1." + strings.Repeat("0.", 23) + "8.b.d.0.1.0.0.2.ip6.arpa.",
		// Letter case does not matter.
		"1.0.64.100.IN-ADDR.ARPA.", "4.3.254.169.In-Addr.Arpa.",
		"8.B.D.0.1.0.0.2.IP6.ARPA.",
	}
	for i := 64; i <= 127; i++ {
		names = append(names, strconv.Itoa(i)+".100.in-addr.arpa.", "9.8."+strconv.Itoa(i)+".100.in-addr.arpa.")
	}
	return names
}

// notLocalPTRNames are reverse names just outside the local zones, and public
// ones.
var notLocalPTRNames = []string{
	"1.0.63.100.in-addr.arpa.", "63.100.in-addr.arpa.",
	"1.0.128.100.in-addr.arpa.", "128.100.in-addr.arpa.",
	"100.in-addr.arpa.", "1.0.0.100.in-addr.arpa.",
	"1.255.255.255.in-addr.arpa.",
	"1.3.0.192.in-addr.arpa.", "1.101.51.198.in-addr.arpa.", "1.114.0.203.in-addr.arpa.",
	"1.0.0.1.in-addr.arpa.", "8.8.8.8.in-addr.arpa.", "1.1.168.128.in-addr.arpa.",
	"1.0.255.169.in-addr.arpa.",
	"2." + strings.Repeat("0.", 31) + "ip6.arpa.",
	"9.b.d.0.1.0.0.2.ip6.arpa.",
	"1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.6.0.6.2.ip6.arpa.",
}

func TestIsPrivatePTR_RFC6303Zones(t *testing.T) {
	// CL 101: the RFC 6303 and RFC 6598 zones are local, in any letter case.
	// The neighbors of each zone, public names, and other query types are
	// not.
	for _, name := range localPTRZoneNames() {
		if !isPrivatePTR(dns.TypePTR, strings.ToLower(name)) {
			t.Errorf("isPrivatePTR(PTR, %q) = false, want true", name)
		}
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeSOA} {
			if isPrivatePTR(qtype, strings.ToLower(name)) {
				t.Errorf("isPrivatePTR(%s, %q) = true, want false", dns.TypeToString[qtype], name)
			}
		}
	}
	for _, name := range notLocalPTRNames {
		if isPrivatePTR(dns.TypePTR, name) {
			t.Errorf("isPrivatePTR(PTR, %q) = true, want false", name)
		}
	}
}

// ptrFixture is a handler with localPTR on, a LAN upstream that records
// every query, and the given interface addresses.
type ptrFixture struct {
	h       *Handler
	counter *stats.Counter
	log     *captureLogger
	rec     *queryRecorder
	addrs   *fakeAddrs
}

func newPTRFixture(t *testing.T, localPTR bool, ifaces ...net.Addr) *ptrFixture {
	t.Helper()
	lan, rec := startRecordingUpstream(t, answerWith(net.IPv4(192, 168, 1, 1)), false)
	store := blocklist.NewStore()
	if localPTR {
		// A local PTR is never blocked, even when the blocklist holds the
		// name.
		store.Replace([]string{"64.100.in-addr.arpa", "8.b.d.0.1.0.0.2.ip6.arpa", "127.in-addr.arpa"})
	}
	counter := stats.New()
	log := &captureLogger{}
	h := NewHandler(store, counter, []string{lan}, log, "zero", 60, nil, localPTR, "full")
	h.SetQueryLogMode("all")
	addrs := newFakeAddrs(ifaces...)
	h.lan = testACL(addrs)
	if !h.HasLANUpstream() {
		t.Fatal("fixture: the loopback upstream is not on the LAN")
	}
	return &ptrFixture{h: h, counter: counter, log: log, rec: rec, addrs: addrs}
}

// local sends a PTR query for name and reports whether s-hole answered it
// itself (authoritative NXDOMAIN, no upstream query). It fails the test on
// any other mix.
func (f *ptrFixture) local(t *testing.T, name string) bool {
	t.Helper()
	before := f.rec.count()
	w := fakeClient()
	f.h.ServeDNS(w, ptrQuery(name))
	sent := f.rec.count() - before
	r := w.written
	switch {
	case r == nil:
		t.Fatalf("%s: no reply", name)
	case sent == 0 && r.Rcode == dns.RcodeNameError && r.Authoritative:
		return true
	case sent == 1 && !r.Authoritative:
		return false
	}
	t.Fatalf("%s: upstream got %d queries, reply %v", name, sent, r)
	return false
}

func TestServeDNS_RFC6303ZonesAnsweredLocally(t *testing.T) {
	// CL 101: a PTR query under an RFC 6303 or RFC 6598 zone gets an
	// authoritative NXDOMAIN from s-hole. Nothing leaves s-hole, not even to
	// a LAN upstream. It counts as a local PTR, never as blocked.
	f := newPTRFixture(t, true)
	names := localPTRZoneNames()
	for _, name := range names {
		if !f.local(t, name) {
			t.Errorf("%s: forwarded, want a local NXDOMAIN", name)
		}
	}
	if f.rec.count() != 0 {
		t.Errorf("LAN upstream got %d queries, want 0", f.rec.count())
	}
	s := f.counter.Snapshot(0)
	if s.LocalPTRCount != int64(len(names)) || s.BlockedCount != 0 || s.TotalQueries != int64(len(names)) {
		t.Errorf("local PTR %d, blocked %d, total %d; want %d, 0, %d", s.LocalPTRCount, s.BlockedCount, s.TotalQueries, len(names), len(names))
	}
	if !f.log.last.Synthesized || f.log.last.Blocked || f.log.last.Rcode != dns.RcodeNameError {
		t.Errorf("last query log record = %+v, want synthesized NXDOMAIN, not blocked", f.log.last)
	}
}

func TestServeDNS_NotLocalPTRIsForwarded(t *testing.T) {
	// CL 101: the neighbors of the local zones and public reverse names go
	// upstream, and so does a non-PTR query under a local zone.
	f := newPTRFixture(t, true)
	for _, name := range notLocalPTRNames {
		if f.local(t, name) {
			t.Errorf("%s: answered locally, want forwarded", name)
		}
	}
	before := f.rec.count()
	w := fakeClient()
	f.h.ServeDNS(w, buildReq("1.0.65.100.in-addr.arpa"))
	if f.rec.count() != before+1 {
		t.Errorf("A query under 65.100.in-addr.arpa: upstream got %d queries, want 1", f.rec.count()-before)
	}
	if s := f.counter.Snapshot(0); s.LocalPTRCount != 0 {
		t.Errorf("local PTR = %d, want 0", s.LocalPTRCount)
	}
}

func TestServeDNS_LocalPTROffForwardsNewZones(t *testing.T) {
	// CL 101: with dns.local_ptr off, the RFC 6303 and RFC 6598 zones and the
	// own-prefix names go upstream as before.
	f := newPTRFixture(t, false, ipnet(t, "3fff:0:aa:bb::5/64"))
	names := append(localPTRZoneNames(),
		ip6Name(t, "3fff:0:aa:bb:1234:5678:9abc:def0", 32),
		ip6Name(t, "3fff:0:aa:bb::", 16))
	for _, name := range names {
		if f.local(t, name) {
			t.Errorf("%s: answered locally with local_ptr off, want forwarded", name)
		}
	}
	if s := f.counter.Snapshot(0); s.LocalPTRCount != 0 {
		t.Errorf("local PTR = %d, want 0", s.LocalPTRCount)
	}
}

func TestHandler_OwnPrefixPTR(t *testing.T) {
	// CL 101: a PTR name under ip6.arpa names a prefix of 4 bits per label.
	// It is local when that prefix lies inside a global IPv6 subnet of a host
	// interface: a full address in the /64 and the /64 itself, but not the
	// /60 above it, another /64, a malformed name, or a ULA or link-local
	// subnet (those have their own zones). A global /128 counts as its /64.
	f := newPTRFixture(t, true,
		ipnet(t, "3fff:0:aa:bb::5/64"),
		ipnet(t, "3fff:0:cc:dd::5/128"),
		ipnet(t, "3fff:0:ee:f0::5/64"), // the /60 and /48 above it start at the same address
		ipnet(t, "fd00:1:2:3::5/64"),
		ipnet(t, "fe80::5/64"),
		ipnet(t, "192.168.1.5/24"),
	)
	full := ip6Name(t, "3fff:0:aa:bb:1234:5678:9abc:def0", 32)
	labels := strings.Split(full, ".")
	twoChar := "12." + strings.Join(labels[1:], ".")
	nonHex := "g." + strings.Join(labels[1:], ".")
	cases := []struct {
		label string
		qtype uint16
		name  string
		want  bool
	}{
		{"full address in /64", dns.TypePTR, full, true},
		{"other address in /64", dns.TypePTR, ip6Name(t, "3fff:0:aa:bb::1", 32), true},
		{"/64 zone", dns.TypePTR, ip6Name(t, "3fff:0:aa:bb::", 16), true},
		{"/68 inside /64", dns.TypePTR, ip6Name(t, "3fff:0:aa:bb::", 17), true},
		{"address in /64 of a /128", dns.TypePTR, ip6Name(t, "3fff:0:cc:dd:ffff::1", 32), true},
		{"/60 above /64", dns.TypePTR, ip6Name(t, "3fff:0:aa:bb::", 15), false},
		{"/48 above /64", dns.TypePTR, ip6Name(t, "3fff:0:aa:bb::", 12), false},
		{"/64 at its /60 start", dns.TypePTR, ip6Name(t, "3fff:0:ee:f0::", 16), true},
		{"/60 with the same start", dns.TypePTR, ip6Name(t, "3fff:0:ee:f0::", 15), false},
		{"/48 with the same start", dns.TypePTR, ip6Name(t, "3fff:0:ee::", 12), false},
		{"other /64", dns.TypePTR, ip6Name(t, "3fff:0:aa:bc::1", 32), false},
		{"other /64 zone", dns.TypePTR, ip6Name(t, "3fff:0:aa:ba::", 16), false},
		{"two-character label", dns.TypePTR, twoChar, false},
		{"non-hex label", dns.TypePTR, nonHex, false},
		{"33 nibbles", dns.TypePTR, "0." + full, false},
		{"ULA subnet", dns.TypePTR, ip6Name(t, "fd00:1:2:3::9", 32), false},
		{"link-local subnet", dns.TypePTR, ip6Name(t, "fe80::9", 32), false},
		{"public address", dns.TypePTR, ip6Name(t, "2606:4700::1111", 32), false},
		{"not PTR", dns.TypeA, full, false},
		{"in-addr.arpa", dns.TypePTR, "9.1.168.192.in-addr.arpa.", false},
	}
	for _, tc := range cases {
		if got := f.h.ownPrefixPTR(tc.qtype, tc.name); got != tc.want {
			t.Errorf("%s: ownPrefixPTR(%s, %q) = %v, want %v", tc.label, dns.TypeToString[tc.qtype], tc.name, got, tc.want)
		}
	}
}

func TestServeDNS_OwnPrefixPTRAnsweredLocally(t *testing.T) {
	// CL 101: a PTR query under the LAN's own global IPv6 prefix gets an
	// authoritative NXDOMAIN from s-hole, in any letter case, and reaches no
	// upstream, not even the LAN one. Names outside the prefix go upstream.
	f := newPTRFixture(t, true, ipnet(t, "3fff:0:aa:bb::5/64"))
	local := []string{
		ip6Name(t, "3fff:0:aa:bb:1234:5678:9abc:def0", 32),
		strings.ToUpper(ip6Name(t, "3fff:0:aa:bb:1234:5678:9abc:def0", 32)),
		ip6Name(t, "3fff:0:aa:bb::", 16),
	}
	for _, name := range local {
		if !f.local(t, name) {
			t.Errorf("%s: forwarded, want a local NXDOMAIN", name)
		}
	}
	for _, name := range []string{
		ip6Name(t, "3fff:0:aa:bb::", 15),
		ip6Name(t, "3fff:0:aa:bc::1", 32),
	} {
		if f.local(t, name) {
			t.Errorf("%s: answered locally, want forwarded", name)
		}
	}
	s := f.counter.Snapshot(0)
	if s.LocalPTRCount != int64(len(local)) || s.BlockedCount != 0 {
		t.Errorf("local PTR %d, blocked %d; want %d, 0", s.LocalPTRCount, s.BlockedCount, len(local))
	}
}

func TestServeDNS_OwnPrefixPTRFollowsRenumbering(t *testing.T) {
	// CL 101: after the ISP renumbers the prefix, the next interface read
	// (at most every 30 s) makes the new prefix local and the old one public.
	f := newPTRFixture(t, true, ipnet(t, "3fff:0:1:1::5/64"))
	oldName := ip6Name(t, "3fff:0:1:1::77", 32)
	newName := ip6Name(t, "3fff:0:2:2::77", 32)
	if !f.local(t, oldName) {
		t.Fatal("old prefix: forwarded before renumbering, want local")
	}
	f.addrs.set(ipnet(t, "3fff:0:2:2::5/64"))
	if f.local(t, newName) {
		t.Error("new prefix: local inside 30 s of the last read, want forwarded")
	}
	ageACL(f.h.lan, lanRefreshInterval+time.Second)
	if !f.local(t, newName) {
		t.Error("new prefix: forwarded after the refresh, want local")
	}
	if f.local(t, oldName) {
		t.Error("old prefix: local after renumbering, want forwarded")
	}
}
