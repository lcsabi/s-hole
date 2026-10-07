package dnsserver

import (
	"net"
	"testing"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// CL 94 tests for local-only names (R7 to R10), written from the
// requirements.

// routeResult is what the handler did with one query.
type routeResult int

const (
	routeLocalhost routeResult = iota // answered 127.0.0.1, authoritative
	routeNever                        // authoritative NXDOMAIN, nothing sent
	routeLAN                          // sent to the LAN upstream only
	routePublic                       // sent to the public upstream
)

var routeNames = map[routeResult]string{
	routeLocalhost: "localhost answer",
	routeNever:     "local NXDOMAIN",
	routeLAN:       "LAN upstream only",
	routePublic:    "public upstream",
}

// routeFixture has a public upstream first and a LAN upstream second, so a
// public name reaches the public one and a LAN-only name reaches only the
// LAN one.
type routeFixture struct {
	h           *Handler
	public, lan *queryRecorder
}

func newRouteFixture(t *testing.T) *routeFixture {
	t.Helper()
	pub, pubRec := startRecordingUpstream(t, answerWith(net.IPv4(203, 0, 113, 1)), false)
	lan, lanRec := startRecordingUpstream(t, answerWith(net.IPv4(192, 168, 1, 1)), false)
	h := testHandler([]string{pub, lan}, nil)
	markPublic(h, 0)
	return &routeFixture{h: h, public: pubRec, lan: lanRec}
}

// route sends one query and reports what happened to it.
func (f *routeFixture) route(t *testing.T, name string, qtype uint16) (routeResult, *dns.Msg) {
	t.Helper()
	pubBefore, lanBefore := f.public.count(), f.lan.count()
	w := fakeClient()
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	f.h.ServeDNS(w, req)
	pub, lan := f.public.count()-pubBefore, f.lan.count()-lanBefore
	r := w.written
	switch {
	case r == nil:
		t.Fatalf("%s %s: no reply", name, dns.TypeToString[qtype])
	case pub == 1 && lan == 0:
		return routePublic, r
	case pub == 0 && lan == 1:
		return routeLAN, r
	case pub != 0 || lan != 0:
		t.Fatalf("%s %s: public upstream got %d, LAN upstream got %d", name, dns.TypeToString[qtype], pub, lan)
	case r.Rcode == dns.RcodeSuccess && r.Authoritative:
		return routeLocalhost, r
	case r.Rcode == dns.RcodeNameError && r.Authoritative:
		return routeNever, r
	}
	t.Fatalf("%s %s: unexpected reply %v", name, dns.TypeToString[qtype], r)
	return 0, nil
}

func TestServeDNS_NameClasses(t *testing.T) {
	// CL 94 R7: names match in any letter case, a suffix matches the name
	// itself and every name under it, and only at a label boundary.
	// Single-label names are LAN-only, except for the zone types.
	f := newRouteFixture(t)
	cases := []struct {
		name  string
		qtype uint16
		want  routeResult
	}{
		// localhost (RFC 6761).
		{"localhost.", dns.TypeA, routeLocalhost},
		{"LOCALHOST.", dns.TypeA, routeLocalhost},
		{"LocalHost.", dns.TypeA, routeLocalhost},
		{"foo.localhost.", dns.TypeA, routeLocalhost},
		{"a.b.LOCALHOST.", dns.TypeA, routeLocalhost},
		{"localhost.example.com.", dns.TypeA, routePublic},
		{"x.notlocalhost.com.", dns.TypeA, routePublic},

		// Never resolved: .invalid, .onion, .alt.
		{"x.invalid.", dns.TypeA, routeNever},
		{"deep.name.Invalid.", dns.TypeA, routeNever},
		{"invalid.", dns.TypeA, routeNever},
		{"abc.onion.", dns.TypeA, routeNever},
		{"ABC.ONION.", dns.TypeAAAA, routeNever},
		{"onion.", dns.TypeA, routeNever},
		{"foo.alt.", dns.TypeA, routeNever},
		{"x.ALT.", dns.TypeTXT, routeNever},
		{"invalid.example.com.", dns.TypeA, routePublic},
		{"onion.example.com.", dns.TypeA, routePublic},
		{"x.notonion.com.", dns.TypeA, routePublic},
		{"a.alt.example.", dns.TypeA, routePublic},

		// LAN-only suffixes.
		{"printer.local.", dns.TypeA, routeLAN},
		{"local.", dns.TypeA, routeLAN},
		{"x.home.arpa.", dns.TypeA, routeLAN},
		{"home.arpa.", dns.TypeA, routeLAN},
		{"NAS.Home.Arpa.", dns.TypeAAAA, routeLAN},
		{"db.internal.", dns.TypeA, routeLAN},
		{"a.test.", dns.TypeA, routeLAN},
		{"b.intranet.", dns.TypeA, routeLAN},
		{"c.private.", dns.TypeA, routeLAN},
		{"d.corp.", dns.TypeA, routeLAN},
		{"e.home.", dns.TypeA, routeLAN},
		{"nas.lan.", dns.TypeA, routeLAN},
		{"NAS.LAN.", dns.TypeA, routeLAN},
		{"lan.", dns.TypeA, routeLAN},
		{"box.localdomain.", dns.TypeA, routeLAN},
		{"foo.notlan.", dns.TypeA, routePublic},
		{"xhome.arpa.", dns.TypeA, routePublic},
		{"lan.example.com.", dns.TypeA, routePublic},
		{"local.example.com.", dns.TypeA, routePublic},
		{"test.example.com.", dns.TypeA, routePublic},

		// Single-label names.
		{"printer.", dns.TypeA, routeLAN},
		{"WPAD.", dns.TypeA, routeLAN},
		{"printer.", dns.TypeAAAA, routeLAN},
		{"printer.", dns.TypeTXT, routeLAN},
		{"printer.", dns.TypeHTTPS, routeLAN},
		{"com.", dns.TypeA, routeLAN},
		{"arpa.", dns.TypeA, routeLAN},

		// Zone types for a single-label name are public queries.
		{"com.", dns.TypeSOA, routePublic},
		{"com.", dns.TypeNS, routePublic},
		{"com.", dns.TypeDS, routePublic},
		{"com.", dns.TypeDNSKEY, routePublic},
		{"com.", dns.TypeRRSIG, routePublic},
		{"com.", dns.TypeNSEC, routePublic},
		{"com.", dns.TypeNSEC3, routePublic},
		{"com.", dns.TypeNSEC3PARAM, routePublic},
		{"com.", dns.TypeCDS, routePublic},
		{"com.", dns.TypeCDNSKEY, routePublic},
		{"printer.", dns.TypeDS, routePublic},

		// The root is public.
		{".", dns.TypeNS, routePublic},
		{".", dns.TypeDNSKEY, routePublic},
		{".", dns.TypeA, routePublic},

		// An ordinary public name.
		{"www.example.com.", dns.TypeA, routePublic},
		{"fritz.box.", dns.TypeA, routePublic}, // no dns.local_domains yet
	}
	for _, tc := range cases {
		got, _ := f.route(t, tc.name, tc.qtype)
		if got != tc.want {
			t.Errorf("%s %s: %s, want %s", tc.name, dns.TypeToString[tc.qtype], routeNames[got], routeNames[tc.want])
		}
	}
}

func TestServeDNS_LocalDomainsAreLANOnly(t *testing.T) {
	// CL 94 R7, R8: SetLocalDomains adds suffixes. A name under one goes only
	// to the LAN upstream. The match ignores case and a trailing dot.
	for _, set := range [][]string{
		{"fritz.box", "corp.example"},
		{"Fritz.Box.", "CORP.Example."},
	} {
		t.Run(set[0], func(t *testing.T) {
			f := newRouteFixture(t)
			f.h.SetLocalDomains(set)
			cases := []struct {
				name string
				want routeResult
			}{
				{"fritz.box.", routeLAN},
				{"router.fritz.box.", routeLAN},
				{"ROUTER.FRITZ.BOX.", routeLAN},
				{"a.b.fritz.box.", routeLAN},
				{"corp.example.", routeLAN},
				{"intranet.corp.example.", routeLAN},
				{"xfritz.box.", routePublic},
				{"fritz.box.example.", routePublic},
				{"other.example.", routePublic},
				{"www.example.com.", routePublic},
			}
			for _, tc := range cases {
				if got, _ := f.route(t, tc.name, dns.TypeA); got != tc.want {
					t.Errorf("%s: %s, want %s", tc.name, routeNames[got], routeNames[tc.want])
				}
			}
		})
	}
}

func TestServeDNS_LocalhostAnswer(t *testing.T) {
	// CL 94 R8: s-hole answers a localhost name itself: authoritative
	// NOERROR, 127.0.0.1 for A, ::1 for AAAA, an empty answer for other
	// types. It is never forwarded, never blocked, and never served from the
	// cache, even when the blocklist or the cache holds the name.
	sink, hits := udpSink(t)
	store := blocklist.NewStore()
	store.Replace([]string{"localhost", "foo.localhost", "app.localhost"})
	c := cache.New(10)
	defer c.Close()
	for _, name := range []string{"localhost.", "foo.localhost."} {
		q := dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
		c.Set(asQuery(q), buildResp(q, net.IPv4(6, 6, 6, 6), 300))
	}
	counter := stats.New()
	h := NewHandler(store, counter, []string{sink}, nullLogger{}, "zero", 60, c, false, "drop")
	h.lan = testACL(newFakeAddrs())

	cases := []struct {
		name  string
		qtype uint16
		want  net.IP // nil: an empty answer
	}{
		{"localhost.", dns.TypeA, net.IPv4(127, 0, 0, 1)},
		{"foo.localhost.", dns.TypeA, net.IPv4(127, 0, 0, 1)},
		{"Foo.LocalHost.", dns.TypeA, net.IPv4(127, 0, 0, 1)},
		{"localhost.", dns.TypeAAAA, net.IPv6loopback},
		{"app.localhost.", dns.TypeAAAA, net.IPv6loopback},
		{"localhost.", dns.TypeMX, nil},
		{"localhost.", dns.TypeTXT, nil},
		{"app.localhost.", dns.TypeHTTPS, nil},
		{"localhost.", dns.TypeNS, nil},
	}
	for _, tc := range cases {
		w := fakeClient()
		req := new(dns.Msg)
		req.SetQuestion(tc.name, tc.qtype)
		h.ServeDNS(w, req)
		r := w.written
		label := tc.name + " " + dns.TypeToString[tc.qtype]
		if r == nil {
			t.Fatalf("%s: no reply", label)
		}
		if r.Rcode != dns.RcodeSuccess || !r.Authoritative {
			t.Errorf("%s: rcode %d AA %v, want authoritative NOERROR", label, r.Rcode, r.Authoritative)
		}
		if tc.want == nil {
			if len(r.Answer) != 0 {
				t.Errorf("%s: answer %v, want empty", label, r.Answer)
			}
			continue
		}
		if len(r.Answer) != 1 {
			t.Fatalf("%s: answer %v, want one record", label, r.Answer)
		}
		var ip net.IP
		switch rr := r.Answer[0].(type) {
		case *dns.A:
			ip = rr.A
		case *dns.AAAA:
			ip = rr.AAAA
		}
		if !ip.Equal(tc.want) || r.Answer[0].Header().Rrtype != tc.qtype {
			t.Errorf("%s: answer %v, want %v", label, r.Answer[0], tc.want)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("upstream got %d packets, want 0", hits.Load())
	}
	s := counter.Snapshot(0)
	if s.BlockedCount != 0 || s.CacheHits != 0 {
		t.Errorf("blocked %d, cache hits %d; want 0 and 0", s.BlockedCount, s.CacheHits)
	}
	if _, ok := c.Get(asQuery(dns.Question{Name: "app.localhost.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})); ok {
		t.Error("a localhost answer was stored in the cache")
	}
}

func TestServeDNS_NeverResolvedNames(t *testing.T) {
	// CL 94 R8: .invalid, .onion, and .alt names get an authoritative
	// NXDOMAIN from s-hole. They are not sent upstream, not even to a LAN
	// upstream, and never count as blocked, even when the blocklist or the
	// cache holds the name.
	sink, hits := udpSink(t) // a LAN upstream (loopback)
	store := blocklist.NewStore()
	store.Replace([]string{"tracker.onion", "ads.invalid"})
	c := cache.New(10)
	defer c.Close()
	q := dns.Question{Name: "cached.onion.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(asQuery(q), buildResp(q, net.IPv4(6, 6, 6, 6), 300))
	counter := stats.New()
	h := NewHandler(store, counter, []string{sink}, nullLogger{}, "zero", 60, c, false, "drop")
	h.lan = testACL(newFakeAddrs())
	if !h.HasLANUpstream() {
		t.Fatal("fixture: the loopback upstream is not on the LAN")
	}

	names := []string{"tracker.onion.", "ads.invalid.", "cached.onion.", "x.alt.", "Hidden.Onion."}
	for _, name := range names {
		w := fakeClient()
		h.ServeDNS(w, buildReq(name))
		r := w.written
		if r == nil || r.Rcode != dns.RcodeNameError || !r.Authoritative || len(r.Answer) != 0 {
			t.Errorf("%s: reply %v, want authoritative NXDOMAIN with no answer", name, r)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("LAN upstream got %d packets, want 0", hits.Load())
	}
	s := counter.Snapshot(0)
	if s.BlockedCount != 0 || s.CacheHits != 0 {
		t.Errorf("blocked %d, cache hits %d; want 0 and 0", s.BlockedCount, s.CacheHits)
	}
}

func TestServeDNS_LANOnlyNameRouting(t *testing.T) {
	// CL 94 R8: a LAN-only name goes only to LAN upstreams, in order. Public
	// upstreams get nothing, also when every LAN upstream fails. With no LAN
	// upstream, s-hole answers authoritative NXDOMAIN and sends nothing.
	t.Run("first LAN upstream fails, second answers", func(t *testing.T) {
		pub, pubHits := udpSink(t)
		lanFail, failHits := startFailingUpstream(t)
		lanOK, okRec := startRecordingUpstream(t, answerWith(net.IPv4(192, 168, 1, 50)), false)
		h := testHandler([]string{pub, lanFail, lanOK}, nil)
		markPublic(h, 0)
		w := fakeClient()
		h.ServeDNS(w, buildReq("nas.lan"))
		if w.written == nil || len(w.written.Answer) != 1 {
			t.Fatalf("reply = %v, want the second LAN upstream's answer", w.written)
		}
		if failHits.Load() != 1 || okRec.count() != 1 || pubHits.Load() != 0 {
			t.Errorf("hits: failing LAN %d, good LAN %d, public %d; want 1, 1, 0", failHits.Load(), okRec.count(), pubHits.Load())
		}
	})

	t.Run("LAN upstreams in order", func(t *testing.T) {
		a, aRec := startRecordingUpstream(t, answerWith(net.IPv4(192, 168, 1, 1)), false)
		b, bRec := startRecordingUpstream(t, answerWith(net.IPv4(192, 168, 1, 2)), false)
		h := testHandler([]string{a, b}, nil)
		h.ServeDNS(fakeClient(), buildReq("printer"))
		if aRec.count() != 1 || bRec.count() != 0 {
			t.Errorf("hits: first %d, second %d; want 1, 0", aRec.count(), bRec.count())
		}
	})

	t.Run("every LAN upstream fails", func(t *testing.T) {
		pub, pubHits := udpSink(t)
		lan1, hits1 := startFailingUpstream(t)
		lan2, hits2 := startFailingUpstream(t)
		pub2, pub2Hits := udpSink(t)
		h := testHandler([]string{pub, lan1, lan2, pub2}, nil)
		markPublic(h, 0)
		markPublic(h, 3)
		w := fakeClient()
		h.ServeDNS(w, buildReq("nas.home.arpa"))
		if w.written == nil || w.written.Rcode != dns.RcodeServerFailure {
			t.Errorf("reply = %v, want SERVFAIL", w.written)
		}
		if hits1.Load() == 0 || hits2.Load() == 0 {
			t.Errorf("LAN upstreams got %d and %d queries, want both tried", hits1.Load(), hits2.Load())
		}
		if pubHits.Load() != 0 || pub2Hits.Load() != 0 {
			t.Errorf("public upstreams got %d and %d packets, want 0", pubHits.Load(), pub2Hits.Load())
		}
	})

	t.Run("no LAN upstream", func(t *testing.T) {
		pub, pubHits := udpSink(t)
		pub2, pub2Hits := udpSink(t)
		counter := stats.New()
		h := NewHandler(blocklist.NewStore(), counter, []string{pub, pub2}, nullLogger{}, "zero", 60, nil, false, "drop")
		h.lan = testACL(newFakeAddrs())
		markPublic(h, 0)
		markPublic(h, 1)
		if h.HasLANUpstream() {
			t.Fatal("HasLANUpstream = true, want false")
		}
		for _, name := range []string{"nas.lan", "printer", "wpad", "x.home.arpa", "db.internal"} {
			w := fakeClient()
			h.ServeDNS(w, buildReq(name))
			r := w.written
			if r == nil || r.Rcode != dns.RcodeNameError || !r.Authoritative {
				t.Errorf("%s: reply %v, want authoritative NXDOMAIN", name, r)
			}
		}
		if pubHits.Load() != 0 || pub2Hits.Load() != 0 {
			t.Errorf("public upstreams got %d and %d packets, want 0", pubHits.Load(), pub2Hits.Load())
		}
		if s := counter.Snapshot(0); s.ForwardFailures != 0 {
			t.Errorf("forward failures = %d, want 0 (nothing was forwarded)", s.ForwardFailures)
		}
	})

	t.Run("no upstream at all", func(t *testing.T) {
		h := testHandler(nil, nil)
		w := fakeClient()
		h.ServeDNS(w, buildReq("nas.lan"))
		if w.written == nil || w.written.Rcode != dns.RcodeNameError || !w.written.Authoritative {
			t.Errorf("reply = %v, want authoritative NXDOMAIN", w.written)
		}
	})
}

func TestServeDNS_LANOnlyNameUsesBlocklistAndCache(t *testing.T) {
	// CL 94 R8: a LAN-only name sent to a LAN upstream goes through the
	// blocklist and the cache like a public name.
	lan, rec := startRecordingUpstream(t, answerWith(net.IPv4(192, 168, 1, 9)), false)
	store := blocklist.NewStore()
	store.Replace([]string{"ads.lan"})
	c := cache.New(10)
	defer c.Close()
	counter := stats.New()
	h := NewHandler(store, counter, []string{lan}, nullLogger{}, "zero", 60, c, false, "drop")
	h.lan = testACL(newFakeAddrs())

	w := fakeClient()
	h.ServeDNS(w, buildReq("x.ads.lan"))
	if w.written == nil || len(w.written.Answer) != 1 {
		t.Fatalf("blocked LAN name: reply %v, want the sinkhole answer", w.written)
	}
	if a, ok := w.written.Answer[0].(*dns.A); !ok || !a.A.Equal(net.IPv4zero) {
		t.Errorf("blocked LAN name: answer %v, want 0.0.0.0", w.written.Answer[0])
	}
	if rec.count() != 0 {
		t.Errorf("LAN upstream got %d queries for a blocked name, want 0", rec.count())
	}

	for i := 0; i < 2; i++ {
		w = fakeClient()
		h.ServeDNS(w, buildReq("nas.lan"))
		if w.written == nil || len(w.written.Answer) != 1 {
			t.Fatalf("nas.lan query %d: reply %v", i, w.written)
		}
	}
	if rec.count() != 1 {
		t.Errorf("LAN upstream got %d queries, want 1 (the second from the cache)", rec.count())
	}
	s := counter.Snapshot(0)
	if s.BlockedCount != 1 || s.CacheHits != 1 || s.LocalNameCount != 0 {
		t.Errorf("blocked %d, cache hits %d, local names %d; want 1, 1, 0", s.BlockedCount, s.CacheHits, s.LocalNameCount)
	}
}

func TestHandler_HasLANUpstream(t *testing.T) {
	// CL 94 R8: an upstream is on the LAN by the same rule as a client:
	// loopback, private, link-local, unique-local, or inside a subnet of one
	// of the host's interfaces. Plain "IP:port" entries and DoH URLs with an
	// IP host both count.
	cases := []struct {
		upstream string
		want     bool
	}{
		{"127.0.0.1:53", true},
		{"127.8.9.10:5353", true},
		{"10.1.2.3:53", true},
		{"172.16.0.1:53", true},
		{"172.31.255.254:53", true},
		{"192.168.1.1:53", true},
		{"169.254.1.1:53", true},
		{"[::1]:53", true},
		{"[fd00::1]:53", true},
		{"[fc00::53]:53", true},
		{"[fe80::1]:53", true},
		{"https://192.168.1.1/dns-query", true},
		{"https://10.0.0.1:8443/dns-query", true},
		{"https://[fd12::1]/dns-query", true},
		{"203.0.113.53:53", true}, // inside the interface subnet below
		{"https://203.0.113.53/dns-query", true},

		{"8.8.8.8:53", false},
		{"1.1.1.1:53", false},
		{"172.32.0.1:53", false},
		{"100.64.0.1:53", false},
		{"198.51.100.1:53", false},
		{"[2606:4700::1111]:53", false},
		{"https://1.1.1.1/dns-query", false},
		{"https://9.9.9.9/dns-query", false},
		{"https://[2620:fe::fe]/dns-query", false},
		{"https://dns.example.com/dns-query", false},
	}
	for _, tc := range cases {
		h := NewHandler(blocklist.NewStore(), stats.New(), []string{tc.upstream}, nullLogger{}, "zero", 60, nil, false, "drop")
		h.lan = testACL(newFakeAddrs(ipnet(t, "203.0.113.5/24")))
		if got := h.HasLANUpstream(); got != tc.want {
			t.Errorf("HasLANUpstream([%s]) = %v, want %v", tc.upstream, got, tc.want)
		}
	}

	mixed := NewHandler(blocklist.NewStore(), stats.New(), []string{"https://1.1.1.1/dns-query", "8.8.8.8:53", "192.168.1.1:53"}, nullLogger{}, "zero", 60, nil, false, "drop")
	mixed.lan = testACL(newFakeAddrs())
	if !mixed.HasLANUpstream() {
		t.Error("HasLANUpstream with one LAN entry among public ones = false, want true")
	}
	empty := NewHandler(blocklist.NewStore(), stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "drop")
	empty.lan = testACL(newFakeAddrs())
	if empty.HasLANUpstream() {
		t.Error("HasLANUpstream with no upstreams = true, want false")
	}
}

func TestServeDNS_LocalAnswerStats(t *testing.T) {
	// CL 94 R9: each local answer counts once in total_queries and once in
	// local_name_count, never as blocked or as a local PTR. A LAN-only name
	// that a LAN upstream answers is not a local answer.
	pub, _ := udpSink(t)
	cases := []struct {
		name  string
		qtype uint16
	}{
		{"localhost.", dns.TypeA},
		{"x.localhost.", dns.TypeAAAA},
		{"secret.onion.", dns.TypeA},
		{"x.invalid.", dns.TypeA},
		{"y.alt.", dns.TypeA},
		{"nas.lan.", dns.TypeA}, // no LAN upstream
		{"printer.", dns.TypeA}, // no LAN upstream
	}
	for _, tc := range cases {
		counter := stats.New()
		store := blocklist.NewStore()
		store.Replace([]string{"localhost", "x.localhost", "secret.onion", "nas.lan"})
		h := NewHandler(store, counter, []string{pub}, nullLogger{}, "zero", 60, nil, true, "drop")
		h.lan = testACL(newFakeAddrs())
		markPublic(h, 0)
		req := new(dns.Msg)
		req.SetQuestion(tc.name, tc.qtype)
		h.ServeDNS(fakeClient(), req)
		s := counter.Snapshot(0)
		if s.TotalQueries != 1 || s.LocalNameCount != 1 || s.BlockedCount != 0 || s.LocalPTRCount != 0 || s.CacheHits != 0 {
			t.Errorf("%s: total %d, local names %d, blocked %d, local PTR %d, cache %d; want 1, 1, 0, 0, 0",
				tc.name, s.TotalQueries, s.LocalNameCount, s.BlockedCount, s.LocalPTRCount, s.CacheHits)
		}
	}

	lan, _ := startRecordingUpstream(t, answerWith(net.IPv4(192, 168, 1, 9)), false)
	counter := stats.New()
	h := NewHandler(blocklist.NewStore(), counter, []string{lan}, nullLogger{}, "zero", 60, nil, false, "drop")
	h.lan = testACL(newFakeAddrs())
	h.ServeDNS(fakeClient(), buildReq("nas.lan"))
	if s := counter.Snapshot(0); s.TotalQueries != 1 || s.LocalNameCount != 0 {
		t.Errorf("forwarded LAN name: total %d, local names %d; want 1, 0", s.TotalQueries, s.LocalNameCount)
	}
}

func TestServeDNS_LocalAnswerQueryLog(t *testing.T) {
	// CL 94 R10: a local answer is logged once as a synthesized record, not
	// blocked, not a cache hit, with NOERROR for localhost and NXDOMAIN
	// otherwise.
	pub, _ := udpSink(t)
	cases := []struct {
		name  string
		rcode int
	}{
		{"localhost.", dns.RcodeSuccess},
		{"a.localhost.", dns.RcodeSuccess},
		{"x.onion.", dns.RcodeNameError},
		{"x.invalid.", dns.RcodeNameError},
		{"x.alt.", dns.RcodeNameError},
		{"nas.lan.", dns.RcodeNameError},
		{"printer.", dns.RcodeNameError},
	}
	for _, tc := range cases {
		log := &captureLogger{}
		h := NewHandler(blocklist.NewStore(), stats.New(), []string{pub}, log, "zero", 60, nil, false, "drop")
		h.lan = testACL(newFakeAddrs())
		markPublic(h, 0)
		h.SetQueryLogMode("all")
		h.ServeDNS(fakeClient(), buildReq(tc.name))
		if log.calls != 1 {
			t.Errorf("%s: logger called %d times, want 1", tc.name, log.calls)
			continue
		}
		r := log.last
		if !r.Synthesized || r.Blocked || r.CacheHit || r.Rcode != tc.rcode {
			t.Errorf("%s: record %+v, want Synthesized, not Blocked, not CacheHit, rcode %d", tc.name, r, tc.rcode)
		}
	}
}

func TestServeDNS_LocalAnswerTalliesFollowMode(t *testing.T) {
	// CL 94 R10: the Top Domains and Top Clients tallies get a local answer
	// only when query_log.mode records it. A local answer is not blocked, so
	// mode "blocked" does not record it.
	pub, _ := udpSink(t)
	for _, mode := range []string{"", "none", "blocked", "all"} {
		t.Run("mode "+mode, func(t *testing.T) {
			counter := stats.New()
			h := NewHandler(blocklist.NewStore(), counter, []string{pub}, nullLogger{}, "zero", 60, nil, false, "full")
			h.lan = testACL(newFakeAddrs())
			markPublic(h, 0)
			if mode != "" {
				h.SetQueryLogMode(mode)
			}
			for _, name := range []string{"localhost", "x.onion", "nas.lan"} {
				h.ServeDNS(fakeClient(), buildReq(name))
			}
			s := counter.Snapshot(10)
			if s.TotalQueries != 3 {
				t.Errorf("total = %d, want 3", s.TotalQueries)
			}
			if mode != "all" {
				if len(s.TopDomains) != 0 || len(s.TopClients) != 0 {
					t.Errorf("tallies = domains %v, clients %v; want none", s.TopDomains, s.TopClients)
				}
				return
			}
			// Top Domains lists blocked domains only, and a local answer is
			// never blocked.
			if len(s.TopDomains) != 0 {
				t.Errorf("top domains = %v, want none", s.TopDomains)
			}
			if len(s.TopClients) != 1 || s.TopClients[0].Name != "192.168.1.100" || s.TopClients[0].Count != 3 {
				t.Errorf("top clients = %v, want 192.168.1.100 with 3", s.TopClients)
			}
		})
	}
}

func TestServeDNS_LocalAnswerWritesNoAppLog(t *testing.T) {
	// CL 94 R10: a successful local answer writes no application log line,
	// not even at debug level, in any query_log.mode.
	pub, _ := udpSink(t)
	for _, mode := range []string{"none", "all"} {
		app := captureAppLog(t)
		h := NewHandler(blocklist.NewStore(), stats.New(), []string{pub}, &captureLogger{}, "zero", 60, nil, true, "full")
		h.lan = testACL(newFakeAddrs())
		markPublic(h, 0)
		h.SetQueryLogMode(mode)
		for _, name := range []string{"localhost", "a.localhost", "x.onion", "x.invalid", "x.alt", "nas.lan", "printer"} {
			h.ServeDNS(fakeClient(), buildReq(name))
		}
		if recs := app.records(t); len(recs) != 0 {
			t.Errorf("mode %s: application log got %d lines: %v", mode, len(recs), recs)
		}
	}
}
