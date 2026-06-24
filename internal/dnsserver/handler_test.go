package dnsserver

import (
	"net"
	"testing"

	"github.com/laszlo/s-hole/internal/blocklist"
	"github.com/laszlo/s-hole/internal/cache"
	"github.com/laszlo/s-hole/internal/stats"
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

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil)
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

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "nxdomain", 60, nil)
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
	h := NewHandler(store, counter, nil, nullLogger{}, "zero", 60, c)
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
	h := NewHandler(store, counter, unreachable, nullLogger{}, "zero", 60, c)

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
	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil)
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

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil)
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

func TestServeDNS_BlockedMXReturnsNoAnswer(t *testing.T) {
	// Blocked domain in zero mode, queried for MX: handler should reply
	// NOERROR with no Answer rather than fabricating an MX record.
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})

	h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil)
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
