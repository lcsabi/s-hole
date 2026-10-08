package dnsserver

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
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
		"203.0.114.1":            false,
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
	c.Set(asQuery(q), buildResp(q, net.IPv4(1, 2, 3, 4), 300))
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

func TestServeDNS_AnswersLANSources(t *testing.T) {
	// D1: a LAN source is answered and counted. A source that s-hole cannot
	// read is refused (b/100, TestServeDNS_RefusesUnreadableSource).
	sources := map[string]net.Addr{
		"lan udp":    &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 5353},
		"mapped lan": &net.UDPAddr{IP: net.ParseIP("::ffff:10.0.0.7"), Port: 5353},
		"link-local": &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 5353, Zone: "eth0"},
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

// flakyAddrs is an interface-address source whose read can fail, like
// net.InterfaceAddrs in a sandbox without AF_NETLINK.
type flakyAddrs struct {
	fakeAddrs
	fail atomic.Bool
}

func (f *flakyAddrs) read() ([]net.Addr, error) {
	f.reads.Add(1)
	if f.fail.Load() {
		return nil, errors.New("route ip+net: netlinkrib: address family not supported by protocol")
	}
	return *f.addrs.Load(), nil
}

// ageACL moves the last interface read of a back by d, so the next miss is
// outside lanRefreshInterval without a real wait.
func ageACL(a *lanACL, d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshed = a.refreshed.Add(-d)
}

// warns returns the WARN records of the application log.
func warns(t *testing.T, app *appLog) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range app.records(t) {
		if r["level"] == "WARN" {
			out = append(out, r)
		}
	}
	return out
}

// recordText returns a log record as one JSON string, to search all of its
// fields at once.
func recordText(t *testing.T, r map[string]any) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// naming returns how many of recs name s in a field other than the hint. The
// hint is fixed text, and it quotes the CGNAT range.
func naming(t *testing.T, recs []map[string]any, s string) int {
	t.Helper()
	n := 0
	for _, r := range recs {
		c := make(map[string]any, len(r))
		for k, v := range r {
			if k != "hint" {
				c[k] = v
			}
		}
		if strings.Contains(recordText(t, c), s) {
			n++
		}
	}
	return n
}

func TestServeDNS_RefusesUnreadableSource(t *testing.T) {
	// b/100 (CL 101): a source that s-hole cannot read is not on the LAN. The
	// query gets REFUSED, counts in RefusedQueries, and leaves no other trace:
	// no stats, no query log entry, no cache entry, no upstream query, and no
	// application log line.
	sources := map[string]net.Addr{
		"nil":                 nil,
		"typed-nil udp":       (*net.UDPAddr)(nil),
		"typed-nil tcp":       (*net.TCPAddr)(nil),
		"udp without ip":      &net.UDPAddr{Port: 5353},
		"tcp without ip":      &net.TCPAddr{Port: 5353},
		"other type, garbage": customAddr("garbage"),
		"other type, empty":   customAddr(""),
		"other type, no port": customAddr("192.168.1.10"),
	}
	names := []string{"cached.example.com", "ads.example.com", "uncached.example.com", "5.1.168.192.in-addr.arpa", "nas.lan"}
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
			if s.TotalQueries != 0 || s.BlockedCount != 0 || s.CacheHits != 0 || s.LocalPTRCount != 0 || s.LocalNameCount != 0 || len(s.TopClients) != 0 || len(s.TopDomains) != 0 {
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

func TestServeDNS_AnswersReadableSourceOfOtherType(t *testing.T) {
	// b/100 (CL 101): an address of another type is readable when its String()
	// is "ip:port". A LAN source of that kind is still answered; a public one
	// is refused.
	cases := []struct {
		src  customAddr
		want int
	}{
		{"192.168.1.10:5353", dns.RcodeSuccess},
		{"[::ffff:10.0.0.7]:5353", dns.RcodeSuccess},
		{"[fe80::1%eth0]:5353", dns.RcodeSuccess},
		{"[fd00::7]:5353", dns.RcodeSuccess},
		{"8.8.8.8:5353", dns.RcodeRefused},
	}
	for _, tc := range cases {
		t.Run(string(tc.src), func(t *testing.T) {
			f := newRefusalFixture(t)
			before := RefusedQueries()
			w := &fakeWriter{remote: tc.src}
			f.h.ServeDNS(w, buildReq("cached.example.com"))
			if w.written == nil || w.written.Rcode != tc.want {
				t.Fatalf("reply = %v, want rcode %s", w.written, dns.RcodeToString[tc.want])
			}
			refused := RefusedQueries() - before
			total := f.counter.Snapshot(0).TotalQueries
			if tc.want == dns.RcodeSuccess && (refused != 0 || total != 1 || len(w.written.Answer) != 1) {
				t.Errorf("refused %d, counted %d, answers %v; want 0, 1, the cached answer", refused, total, w.written.Answer)
			}
			if tc.want == dns.RcodeRefused && (refused != 1 || total != 0) {
				t.Errorf("refused %d, counted %d; want 1, 0", refused, total)
			}
		})
	}
}

func TestLANACL_PublicIPv4SubnetsAreNotAdmitted(t *testing.T) {
	// CL 101: an on-link IPv4 subnet outside the private ranges (public, or
	// CGNAT 100.64.0.0/10) does not make its hosts LAN sources. Each one gets
	// exactly one WARN that names it. The private IPv4 subnets, loopback, and
	// the IPv6 subnets get no WARN and keep their behavior.
	app := captureAppLog(t)
	f := newFakeAddrs(
		ipnet(t, "203.0.113.5/20"),
		ipnet(t, "100.64.12.7/10"),
		&net.IPNet{IP: net.ParseIP("198.51.100.9"), Mask: net.CIDRMask(116, 128)}, // IPv4 with a 16-byte mask: /20
		ipnet(t, "127.0.0.1/8"),
		ipnet(t, "192.168.1.5/24"),
		ipnet(t, "10.20.30.40/8"),
		ipnet(t, "169.254.7.7/16"),
		ipnet(t, "3fff:0:aa:bb::5/64"),
		ipnet(t, "fd00:1:2:3::5/64"),
		ipnet(t, "fe80::5/64"),
	)
	a := testACL(f)

	cases := map[string]bool{
		"203.0.112.1":     false,
		"203.0.113.77":    false,
		"203.0.127.254":   false,
		"100.64.0.1":      false,
		"100.100.100.100": false,
		"100.127.255.254": false,
		"198.51.96.1":     false,
		"198.51.100.200":  false,
		"192.168.1.77":    true,
		"10.1.1.1":        true,
		"3fff:0:aa:bb::9": true,
		"3fff:0:aa:bc::9": false,
	}
	for s, want := range cases {
		if got := a.allows(netip.MustParseAddr(s)); got != want {
			t.Errorf("allows(%s) = %v, want %v", s, got, want)
		}
	}

	ws := warns(t, app)
	for _, subnet := range []string{"203.0.112.0/20", "100.64.0.0/10", "198.51.96.0/20"} {
		if n := naming(t, ws, subnet); n != 1 {
			t.Errorf("WARN lines that name %s: %d, want 1", subnet, n)
		}
	}
	if len(ws) != 3 {
		t.Errorf("WARN lines = %d, want 3 (one per public or CGNAT subnet): %v", len(ws), ws)
	}
	for _, r := range ws {
		if h, _ := r["hint"].(string); h == "" {
			t.Errorf("WARN without a hint: %v", r)
		}
	}
}

func TestLANACL_WiderSubnetDoesNotAdmitPublicPart(t *testing.T) {
	// CL 101: an on-link IPv4 subnet admits nothing outside the private
	// ranges, also when it is wider than a private range and covers one.
	a := testACL(newFakeAddrs(ipnet(t, "172.16.0.1/8")))
	if a.allows(netip.MustParseAddr("172.200.0.1")) {
		t.Error("allows(172.200.0.1) = true, want false: a public address inside a wide on-link subnet")
	}
	if !a.allows(netip.MustParseAddr("172.16.9.9")) {
		t.Error("allows(172.16.9.9) = false, want true: a private address")
	}
}

func TestLANACL_PublicSubnetWarnsOncePerAppearance(t *testing.T) {
	// CL 101: the WARN for a public on-link IPv4 subnet comes when s-hole
	// first sees the subnet. A later read that finds the same subnet logs
	// nothing; a read that finds a new public subnet logs one WARN for the new
	// one. The refresh starts from a client query, and the WARN names no
	// client address.
	app := captureAppLog(t)
	f := newFakeAddrs(ipnet(t, "203.0.113.5/24"), ipnet(t, "192.168.1.5/24"))
	a := testACL(f)
	if ws := warns(t, app); len(ws) != 1 || naming(t, ws, "203.0.113.0/24") != 1 {
		t.Fatalf("startup WARN lines = %v, want one that names 203.0.113.0/24", ws)
	}

	// Same subnets, later reads (started by misses).
	for i := 0; i < 3; i++ {
		ageACL(a, lanRefreshInterval+time.Second)
		before := f.reads.Load()
		if a.allows(netip.MustParseAddr("203.0.113.66")) {
			t.Fatal("allows(203.0.113.66) = true, want false")
		}
		if f.reads.Load() != before+1 {
			t.Fatalf("read %d: the miss did not read the interfaces again", i)
		}
	}
	if ws := warns(t, app); len(ws) != 1 {
		t.Errorf("WARN lines after three reads of the same subnets = %d, want 1: %v", len(ws), ws)
	}

	// A new public subnet appears.
	f.set(ipnet(t, "203.0.113.5/24"), ipnet(t, "192.168.1.5/24"), ipnet(t, "198.51.100.5/24"))
	ageACL(a, lanRefreshInterval+time.Second)
	if a.allows(netip.MustParseAddr("198.51.100.44")) {
		t.Error("allows(198.51.100.44) = true, want false")
	}
	ws := warns(t, app)
	if len(ws) != 2 {
		t.Fatalf("WARN lines after a new public subnet = %d, want 2: %v", len(ws), ws)
	}
	if naming(t, ws, "198.51.100.0/24") != 1 || naming(t, ws, "203.0.113.0/24") != 1 {
		t.Errorf("WARN lines = %v, want one for each subnet", ws)
	}
	for _, client := range []string{"203.0.113.66", "198.51.100.44"} {
		if n := naming(t, app.records(t), client); n != 0 {
			t.Errorf("%d log lines name the client %s, want 0", n, client)
		}
	}
}

func TestLANACL_RefreshAtMostEvery30s(t *testing.T) {
	// CL 101 (rewritten with IPv6 prefixes): a miss reads the interface
	// addresses again at most once every 30 seconds, so a renumbered prefix
	// is accepted without a restart. A hit never reads them, and a miss
	// inside 30 s of the last read does not read them.
	f := newFakeAddrs(ipnet(t, "3fff:0:1:1::5/64"))
	a := testACL(f)
	if got := f.reads.Load(); got != 1 {
		t.Fatalf("reads after construction = %d, want 1", got)
	}
	oldHost := netip.MustParseAddr("3fff:0:1:1::9")
	newHost := netip.MustParseAddr("3fff:0:2:2::9")

	// Hits never read, also long after the last read.
	ageACL(a, time.Hour)
	for i := 0; i < 5; i++ {
		if !a.allows(oldHost) {
			t.Fatal("allows(old prefix host) = false, want true")
		}
	}
	if got := f.reads.Load(); got != 1 {
		t.Errorf("reads after hits = %d, want 1", got)
	}
	ageACL(a, -time.Hour) // back to "just read"

	// The ISP renumbers the prefix. Misses inside 30 s do not read.
	f.set(ipnet(t, "3fff:0:2:2::5/64"))
	for i := 0; i < 5; i++ {
		if a.allows(newHost) {
			t.Fatal("allows(new prefix host) = true inside 30 s of the last read, want false")
		}
	}
	if got := f.reads.Load(); got != 1 {
		t.Errorf("reads after misses inside 30 s = %d, want 1", got)
	}

	// 30 s later, one miss reads again and the new prefix is accepted.
	ageACL(a, lanRefreshInterval+time.Second)
	if !a.allows(newHost) {
		t.Error("allows(new prefix host) after 30 s = false, want true")
	}
	if got := f.reads.Load(); got != 2 {
		t.Errorf("reads after the refresh = %d, want 2", got)
	}
	// The old prefix is gone, and the misses right after the read do not
	// read again.
	for i := 0; i < 3; i++ {
		if a.allows(oldHost) {
			t.Error("allows(old prefix host) after renumbering = true, want false")
		}
	}
	if got := f.reads.Load(); got != 2 {
		t.Errorf("reads after misses right after the refresh = %d, want 2", got)
	}
}

func TestLANACL_ReadFailureWarnsHourly(t *testing.T) {
	// CL 101: a failed interface read logs a WARN with a hint about the
	// sandbox (AF_NETLINK, RestrictAddressFamilies), at most once an hour.
	// The last good list stays, so the admitted subnets stay admitted.
	app := captureAppLog(t)
	f := &flakyAddrs{}
	f.set(ipnet(t, "3fff:0:aa:bb::5/64"))
	a := &lanACL{addrs: f.read}
	t0 := time.Now()
	a.refresh(t0)
	if ws := warns(t, app); len(ws) != 0 {
		t.Fatalf("WARN lines after a good read = %v, want none", ws)
	}
	host := netip.MustParseAddr("3fff:0:aa:bb::77")

	f.fail.Store(true)
	first := t0.Add(lanRefreshInterval + time.Second)
	a.refresh(first)
	ws := warns(t, app)
	if len(ws) != 1 {
		t.Fatalf("WARN lines after a failed read = %d, want 1: %v", len(ws), ws)
	}
	text := recordText(t, ws[0])
	for _, want := range []string{"AF_NETLINK", "RestrictAddressFamilies"} {
		if !strings.Contains(text, want) {
			t.Errorf("WARN %s does not mention %s", text, want)
		}
	}
	if !a.allows(host) {
		t.Error("allows(admitted host) after a failed read = false, want true (keep the last good list)")
	}

	// More failures inside the hour, each one after the 30 s interval.
	reads := f.reads.Load()
	for i := 1; i <= 10; i++ {
		a.refresh(first.Add(time.Duration(i) * 5 * time.Minute))
	}
	if f.reads.Load() != reads+10 {
		t.Fatalf("reads = %d, want %d: the fixture did not make each refresh read", f.reads.Load(), reads+10)
	}
	if ws := warns(t, app); len(ws) != 1 {
		t.Errorf("WARN lines after failures inside the hour = %d, want 1", len(ws))
	}
	if !a.allows(host) {
		t.Error("allows(admitted host) after repeated failed reads = false, want true")
	}

	// A failure more than an hour after the last WARN logs again.
	a.refresh(first.Add(time.Hour + time.Second))
	if ws := warns(t, app); len(ws) != 2 {
		t.Errorf("WARN lines after a failure an hour later = %d, want 2", len(ws))
	}
}

func TestLANACL_ReadFailureAtStartup(t *testing.T) {
	// CL 101: when the first read fails, s-hole logs the WARN and answers the
	// private ranges only.
	app := captureAppLog(t)
	f := &flakyAddrs{}
	f.set(ipnet(t, "3fff:0:aa:bb::5/64"))
	f.fail.Store(true)
	a := &lanACL{addrs: f.read}
	a.refresh(time.Now())
	if ws := warns(t, app); len(ws) != 1 || !strings.Contains(recordText(t, ws[0]), "AF_NETLINK") {
		t.Errorf("WARN lines = %v, want one with the AF_NETLINK hint", ws)
	}
	if !a.allows(netip.MustParseAddr("192.168.1.9")) {
		t.Error("allows(192.168.1.9) = false, want true")
	}
	if a.allows(netip.MustParseAddr("3fff:0:aa:bb::9")) {
		t.Error("allows(3fff:0:aa:bb::9) = true with no good read, want false")
	}
}
