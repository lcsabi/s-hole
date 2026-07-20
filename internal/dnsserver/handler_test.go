package dnsserver

import (
	"net"
	"testing"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
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

func (nullLogger) Log(string, string, bool) {}

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

func TestServeDNS_BlockedZeroMode(t *testing.T) {
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false)
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

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "nxdomain", 60, nil, false)
	w := fakeClient()
	h.ServeDNS(w, buildReq("ads.example.com"))

	if w.written == nil {
		t.Fatal("no response written")
	}
	if w.written.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want NXDOMAIN (%d)", w.written.Rcode, dns.RcodeNameError)
	}
}

func TestServeDNS_WhitelistOverridesBlock(t *testing.T) {
	store := blocklist.NewStore()
	store.Replace([]string{"example.com"})
	store.AddToWhitelist("example.com")

	c := cache.New(10)
	defer c.Close()

	// Pre-populate the cache so we don't hit the network.
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	preCached := buildResp(q, net.IPv4(8, 8, 8, 8), 300)
	c.Set(q, preCached)

	counter := stats.New()
	h := NewHandler(store, counter, nil, nullLogger{}, "zero", 60, c, false)
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
		t.Errorf("whitelisted domain not served from cache: A=%v", a.A)
	}
	// Block stats should be zero.
	if s := counter.Snapshot(0); s.BlockedCount != 0 {
		t.Errorf("BlockedCount = %d, want 0 (whitelist)", s.BlockedCount)
	}
}

func TestServeDNS_CacheHitAvoidsUpstream(t *testing.T) {
	store := blocklist.NewStore() // empty
	c := cache.New(10)
	defer c.Close()

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, buildResp(q, net.IPv4(1, 2, 3, 4), 300))

	counter := stats.New()
	// Upstream is unreachable on purpose: if the cache path works, we
	// never call forward, so this must succeed.
	unreachable := []string{"127.0.0.1:1"}
	h := NewHandler(store, counter, unreachable, nullLogger{}, "zero", 60, c, false)

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

func TestServeDNS_EmptyQuestion(t *testing.T) {
	store := blocklist.NewStore()
	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false)
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

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false)
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

	h := NewHandler(store, stats.New(), []string{addr}, nullLogger{}, "zero", 60, c, false)
	w := fakeClient()
	h.ServeDNS(w, buildReq("example.com"))

	if hits.Load() != 1 {
		t.Errorf("upstream got %d queries, want 1", hits.Load())
	}
	if w.written == nil || len(w.written.Answer) != 1 {
		t.Fatal("no answer written to client")
	}
	// And the result should now be cached.
	if _, ok := c.Get(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}); !ok {
		t.Error("response was not stored in the cache after forward")
	}
}

func TestServeDNS_UpstreamFailureProducesServfail(t *testing.T) {
	// All upstreams are unreachable. Handler must surface SERVFAIL via
	// dns.HandleFailed rather than write a malformed reply.
	store := blocklist.NewStore()
	h := NewHandler(store, stats.New(), []string{"127.0.0.1:1"}, nullLogger{}, "zero", 60, nil, false)
	w := fakeClient()
	h.ServeDNS(w, buildReq("example.com"))
	if w.written == nil {
		t.Fatal("no response written")
	}
	if w.written.Rcode != dns.RcodeServerFailure {
		t.Errorf("Rcode = %d, want SERVFAIL", w.written.Rcode)
	}
}

func TestServeDNS_WriteSinkholeErrorIsLogged(t *testing.T) {
	// Confirm the writeSinkhole error branch is exercised when the
	// ResponseWriter fails. We don't capture log output here — the
	// purpose is to drive the branch for coverage and ensure the
	// handler doesn't panic.
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false)
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

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false)
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
		// RFC 1918 IPv4 — private
		{"1.0.0.10.in-addr.arpa.", dns.TypePTR, true},
		{"255.255.0.10.in-addr.arpa.", dns.TypePTR, true},
		{"1.1.16.172.in-addr.arpa.", dns.TypePTR, true},
		{"1.1.31.172.in-addr.arpa.", dns.TypePTR, true},
		{"1.1.168.192.in-addr.arpa.", dns.TypePTR, true},
		// Zone apex itself
		{"168.192.in-addr.arpa.", dns.TypePTR, true},
		// IPv6 ULA
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.", dns.TypePTR, true},
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.f.ip6.arpa.", dns.TypePTR, true},
		// IPv6 link-local
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.", dns.TypePTR, true},
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.e.f.ip6.arpa.", dns.TypePTR, true},
		// Public range — must not match
		{"4.3.2.1.in-addr.arpa.", dns.TypePTR, false},
		{"8.8.8.8.in-addr.arpa.", dns.TypePTR, false},
		// 172.15 is NOT in 172.16/12
		{"1.1.15.172.in-addr.arpa.", dns.TypePTR, false},
		// Same name but wrong qtype — must not match
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
	h := NewHandler(store, counter, []string{"127.0.0.1:1"}, nullLogger{}, "zero", 60, nil, true)
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
	h := NewHandler(store, stats.New(), []string{addr}, nullLogger{}, "zero", 60, nil, false)
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
	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, true)
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
	h := NewHandler(store, stats.New(), []string{addr}, nullLogger{}, "zero", 60, nil, true)
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
