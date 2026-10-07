package dnsserver

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// fakeAddrs is an interface-address source for lanACL. It counts the reads,
// and the test can change the addresses it returns.
type fakeAddrs struct {
	reads atomic.Int64
	addrs atomic.Pointer[[]net.Addr]
}

func newFakeAddrs(addrs ...net.Addr) *fakeAddrs {
	f := &fakeAddrs{}
	f.set(addrs...)
	return f
}

func (f *fakeAddrs) set(addrs ...net.Addr) { f.addrs.Store(&addrs) }

func (f *fakeAddrs) read() ([]net.Addr, error) {
	f.reads.Add(1)
	return *f.addrs.Load(), nil
}

// testACL returns a lanACL whose interface addresses come from f, read once
// at construction like newLANACL does.
func testACL(f *fakeAddrs) *lanACL {
	a := &lanACL{addrs: f.read}
	a.refresh(time.Now())
	return a
}

func ipnet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	n.IP = ip // keep the host address, as net.InterfaceAddrs does
	return n
}

func TestLANACL_LocalRanges(t *testing.T) {
	// D1 (b/080): loopback, 10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7,
	// and fe80::/10 are answered with no interface address at all. IPv4-mapped
	// IPv6 sources are unmapped first. Everything else is refused.
	a := testACL(newFakeAddrs())
	cases := map[string]bool{
		"127.0.0.1": true, "127.255.255.254": true, "::1": true,
		"10.0.0.1": true, "10.255.255.255": true,
		"172.16.0.1": true, "172.31.255.255": true,
		"192.168.0.1": true, "192.168.255.255": true,
		"169.254.0.1": true, "169.254.255.255": true,
		"fc00::1": true, "fdab:cdef::1": true,
		"fe80::1": true, "febf::1": true, "fe80::1%eth0": true,
		"::ffff:192.168.1.5": true, "::ffff:10.1.2.3": true, "::ffff:127.0.0.1": true,

		"8.8.8.8": false, "1.1.1.1": false,
		"172.15.255.255": false, "172.32.0.1": false,
		"192.167.255.255": false, "192.169.0.1": false,
		"169.253.255.255": false, "169.255.0.1": false,
		"100.64.0.1": false, "11.0.0.1": false,
		"2001:db8::1": false, "2606:4700::1111": false,
		"fe00::1": false, "fec0::1": false, "fbff::1": false,
		"::ffff:8.8.8.8": false, "::": false, "0.0.0.0": false,
	}
	for s, want := range cases {
		ip := netip.MustParseAddr(s)
		if got := a.allows(ip); got != want {
			t.Errorf("allows(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestLANACL_InterfaceSubnets(t *testing.T) {
	// D1: a source inside a subnet of one of the host's interface addresses
	// is answered; that covers a LAN with public addresses. A global IPv6
	// address with a prefix longer than /64 counts as its /64.
	f := newFakeAddrs(
		ipnet(t, "203.0.113.5/24"),
		&net.IPNet{IP: net.ParseIP("198.51.100.9"), Mask: net.CIDRMask(120, 128)}, // IPv4 with a 16-byte mask
		ipnet(t, "2001:db8:aa:bb::5/128"),
		ipnet(t, "2001:db8:cc::5/56"),
	)
	a := testACL(f)
	cases := map[string]bool{
		"203.0.113.200":          true,
		"::ffff:203.0.113.7":     true,
		"203.0.114.1":            false,
		"198.51.100.250":         true,
		"198.51.101.1":           false,
		"2001:db8:aa:bb:ffff::1": true, // same /64 as the /128
		"2001:db8:aa:bc::1":      false,
		"2001:db8:cc:ff::1":      true, // inside the /56
		"2001:db8:cd::1":         false,
	}
	for s, want := range cases {
		if got := a.allows(netip.MustParseAddr(s)); got != want {
			t.Errorf("allows(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestLANACL_RefreshAtMostEvery30s(t *testing.T) {
	// D1: a miss reads the interface addresses again, at most once per 30
	// seconds, so a renumbered prefix is accepted without a restart. A hit
	// does not read them.
	f := newFakeAddrs(ipnet(t, "203.0.113.5/24"))
	a := testACL(f)
	start := f.reads.Load()
	newSource := netip.MustParseAddr("198.51.100.20")

	// The ISP renumbers the prefix.
	f.set(ipnet(t, "198.51.100.5/24"))
	for i := 0; i < 5; i++ {
		if a.allows(newSource) {
			t.Fatal("a miss inside 30 seconds of the last read used the new addresses")
		}
	}
	if got := f.reads.Load() - start; got != 0 {
		t.Errorf("addresses read %d times inside 30 seconds of the last read, want 0", got)
	}

	// 31 seconds later, the next miss reads the addresses again.
	a.mu.Lock()
	a.refreshed = time.Now().Add(-31 * time.Second)
	a.mu.Unlock()
	if !a.allows(newSource) {
		t.Error("a miss 31 seconds after the last read did not accept the renumbered prefix")
	}
	if got := f.reads.Load() - start; got != 1 {
		t.Errorf("addresses read %d times, want 1", got)
	}
	// Further misses inside the new 30 seconds do not read again.
	a.allows(netip.MustParseAddr("8.8.8.8"))
	a.allows(netip.MustParseAddr("8.8.4.4"))
	if got := f.reads.Load() - start; got != 1 {
		t.Errorf("addresses read %d times after more misses, want 1", got)
	}

	// A hit never reads them, even when 30 seconds have passed.
	a.mu.Lock()
	a.refreshed = time.Now().Add(-time.Hour)
	a.mu.Unlock()
	a.allows(netip.MustParseAddr("192.168.1.1"))
	a.allows(netip.MustParseAddr("198.51.100.30"))
	if got := f.reads.Load() - start; got != 1 {
		t.Errorf("addresses read %d times after hits, want 1", got)
	}
}

// refusalFixture is a handler whose every path leaves a trace: a cached
// answer, a counting upstream, a query logger, and the stats counter.
type refusalFixture struct {
	h       *Handler
	counter *stats.Counter
	cache   *cache.Cache
	log     *captureLogger
	hits    *atomic.Int64
}

// udpSink counts the packets sent to a UDP address and never answers. It
// stands in for an upstream that must not be contacted. (A mock DNS server
// that gets no query can outlive its Shutdown, which goleak reports.)
func udpSink(t *testing.T) (addr string, hits *atomic.Int64) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	hits = new(atomic.Int64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			hits.Add(1)
		}
	}()
	t.Cleanup(func() {
		pc.Close()
		<-done
	})
	return pc.LocalAddr().String(), hits
}

func newRefusalFixture(t *testing.T) *refusalFixture {
	t.Helper()
	addr, hits := udpSink(t)
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})
	c := cache.New(10)
	t.Cleanup(c.Close)
	q := dns.Question{Name: "cached.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, buildResp(q, net.IPv4(1, 2, 3, 4), 300))
	counter := stats.New()
	log := &captureLogger{}
	h := NewHandler(store, counter, []string{addr}, log, "zero", 60, c, true, "full")
	h.SetQueryLogMode("all")
	h.lan = testACL(newFakeAddrs())
	return &refusalFixture{h: h, counter: counter, cache: c, log: log, hits: hits}
}

func TestServeDNS_RefusesOutsideLAN(t *testing.T) {
	// D1 (b/080): a source outside the LAN gets REFUSED. The query is not
	// counted, not tallied, not logged, does not touch the cache or an
	// upstream, and increments RefusedQueries.
	sources := map[string]net.Addr{
		"udp ipv4":   &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 5353},
		"tcp ipv6":   &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 5353},
		"udp mapped": &net.UDPAddr{IP: net.ParseIP("::ffff:8.8.8.8"), Port: 5353},
		"other type": customAddr("203.0.113.9:5353"),
	}
	names := []string{"cached.example.com", "ads.example.com", "uncached.example.com", "5.1.168.192.in-addr.arpa"}
	for label, src := range sources {
		t.Run(label, func(t *testing.T) {
			f := newRefusalFixture(t)
			app := captureAppLog(t)
			before := RefusedQueries()
			hitsBefore, missesBefore, sizeBefore := f.cache.Stats()
			for _, name := range names {
				w := &fakeWriter{remote: src}
				req := buildReq(name)
				if name[0] == '5' {
					req.SetQuestion(dns.Fqdn(name), dns.TypePTR)
				}
				f.h.ServeDNS(w, req)
				if w.written == nil || w.written.Rcode != dns.RcodeRefused {
					t.Fatalf("%s: reply = %v, want REFUSED", name, w.written)
				}
				if len(w.written.Answer) != 0 {
					t.Errorf("%s: REFUSED reply carries answers: %v", name, w.written.Answer)
				}
			}
			if got := RefusedQueries() - before; got != uint64(len(names)) {
				t.Errorf("RefusedQueries grew by %d, want %d", got, len(names))
			}
			s := f.counter.Snapshot(10)
			if s.TotalQueries != 0 || s.BlockedCount != 0 || s.CacheHits != 0 || s.LocalPTRCount != 0 || len(s.TopClients) != 0 || len(s.TopDomains) != 0 {
				t.Errorf("stats = %+v, want nothing counted", s)
			}
			if f.log.calls != 0 {
				t.Errorf("query logger called %d times, want 0", f.log.calls)
			}
			if hits, misses, size := f.cache.Stats(); hits != hitsBefore || misses != missesBefore || size != sizeBefore {
				t.Errorf("cache stats moved: hits %d->%d, misses %d->%d, size %d->%d", hitsBefore, hits, missesBefore, misses, sizeBefore, size)
			}
			if f.hits.Load() != 0 {
				t.Errorf("upstream got %d queries, want 0", f.hits.Load())
			}
			if recs := app.records(t); len(recs) != 0 {
				t.Errorf("application log got %d lines for refused queries: %v", len(recs), recs)
			}
		})
	}
}

func TestServeDNS_AnswersLANAndUnknownSources(t *testing.T) {
	// D1: a LAN source and a source the transport cannot give (nil address)
	// are answered and counted.
	sources := map[string]net.Addr{
		"nil":           nil,
		"typed nil udp": (*net.UDPAddr)(nil),
		"typed nil tcp": (*net.TCPAddr)(nil),
		"lan udp":       &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 5353},
		"mapped lan":    &net.UDPAddr{IP: net.ParseIP("::ffff:10.0.0.7"), Port: 5353},
		"link-local":    &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 5353, Zone: "eth0"},
	}
	for label, src := range sources {
		t.Run(label, func(t *testing.T) {
			f := newRefusalFixture(t)
			before := RefusedQueries()
			w := &fakeWriter{remote: src}
			f.h.ServeDNS(w, buildReq("cached.example.com"))
			if w.written == nil || w.written.Rcode != dns.RcodeSuccess || len(w.written.Answer) != 1 {
				t.Fatalf("reply = %v, want the cached answer", w.written)
			}
			if got := RefusedQueries() - before; got != 0 {
				t.Errorf("RefusedQueries grew by %d, want 0", got)
			}
			if s := f.counter.Snapshot(0); s.TotalQueries != 1 || s.CacheHits != 1 {
				t.Errorf("stats = %+v, want one counted cache hit", s)
			}
		})
	}
}

func TestNewHandler_RefusesPublicSourceByDefault(t *testing.T) {
	// D1 wiring: NewHandler builds the LAN check itself, from the real
	// interface addresses. A documentation address is on no LAN.
	h := NewHandler(blocklist.NewStore(), stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "drop")
	w := &fakeWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}}
	h.ServeDNS(w, buildReq("example.com"))
	if w.written == nil || w.written.Rcode != dns.RcodeRefused {
		t.Errorf("reply to 192.0.2.1 = %v, want REFUSED", w.written)
	}
}
