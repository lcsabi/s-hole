package dnsserver

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// CL 94 tests: s-hole sends a fresh, minimal query upstream and gives each
// client its own OPT record back. The tests are written from the CL 94
// requirements (R1 to R5, R11, R12).

// queryRecorder keeps every query that a mock upstream got, in order.
type queryRecorder struct {
	mu    sync.Mutex
	msgs  []*dns.Msg
	nets  []string // "udp", "tcp", or "doh"
	sizes []int    // the packed length on the wire (the HTTP body for DoH)
}

func (r *queryRecorder) add(m *dns.Msg, network string, size int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, m.Copy())
	r.nets = append(r.nets, network)
	r.sizes = append(r.sizes, size)
}

func (r *queryRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.msgs)
}

func (r *queryRecorder) get(i int) (*dns.Msg, string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.msgs[i], r.nets[i], r.sizes[i]
}

// replyFunc builds the upstream reply to a query.
type replyFunc func(req *dns.Msg) *dns.Msg

// answerWith answers an A query with ip, and any other type with an empty
// NOERROR reply.
func answerWith(ip net.IP) replyFunc {
	return func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   ip,
			}}
		}
		return resp
	}
}

// acceptAll lets a mock upstream read every message. The default accept
// function of miekg/dns drops a query with records in the answer section, so
// a leak of such records would show up as a missing query, not as a clear
// failure.
func acceptAll(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept }

// startRecordingUpstream runs a UDP and a TCP DNS server on one loopback
// port. Each server records the query it gets and answers with reply. With
// truncUDP, the UDP reply is empty with the TC bit set, so s-hole asks again
// over TCP. The function waits until both servers run, so Shutdown at cleanup
// always stops them (goleak checks this).
func startRecordingUpstream(t *testing.T, reply replyFunc, truncUDP bool) (addr string, rec *queryRecorder) {
	t.Helper()
	rec = &queryRecorder{}
	addr, pc, ln := pickFreePort(t)

	serve := func(network string) dns.HandlerFunc {
		return func(w dns.ResponseWriter, req *dns.Msg) {
			packed, _ := req.Pack()
			rec.add(req, network, len(packed))
			resp := reply(req)
			if network == "udp" && truncUDP {
				resp = new(dns.Msg)
				resp.SetReply(req)
				resp.Truncated = true
			}
			_ = w.WriteMsg(resp)
		}
	}
	for _, s := range []*dns.Server{
		{PacketConn: pc, Handler: serve("udp"), MsgAcceptFunc: acceptAll},
		{Listener: ln, Handler: serve("tcp"), MsgAcceptFunc: acceptAll},
	} {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go s.ActivateAndServe()
		<-started
		t.Cleanup(func() { _ = s.Shutdown() })
	}
	return addr, rec
}

// startRecordingDoH runs a DoH upstream that records each query and the
// length of the HTTP POST body, and answers with reply.
func startRecordingDoH(t *testing.T, reply replyFunc) (endpoint string, rec *queryRecorder) {
	t.Helper()
	rec = &queryRecorder{}
	endpoint, _ = startDoHUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req dns.Msg
		if err := req.Unpack(body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rec.add(&req, "doh", len(body))
		packed, err := reply(&req).Pack()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", dohMediaType)
		_, _ = w.Write(packed)
	})
	return endpoint, rec
}

// testHandler builds a handler for upstreams with the fixed LAN ranges and no
// interface subnets, so the result does not depend on the test host.
func testHandler(upstreams []string, c *cache.Cache) *Handler {
	h := NewHandler(blocklist.NewStore(), stats.New(), upstreams, nullLogger{}, "zero", 60, c, false, "drop")
	h.lan = testACL(newFakeAddrs())
	return h
}

// markPublic makes the handler treat upstream i as a public resolver. Every
// mock upstream listens on loopback, which is on the LAN, so the test changes
// the address that the handler keeps for that upstream.
func markPublic(h *Handler, i int) {
	h.upstreamIPs[i] = netip.MustParseAddr("9.9.9.9")
}

// clientOptions are EDNS options that a client can send. None of them may
// reach an upstream (R1).
func clientOptions() []dns.EDNS0 {
	return []dns.EDNS0{
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"},
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(192, 168, 1, 0).To4()},
		&dns.EDNS0_PADDING{Padding: make([]byte, 37)},
		&dns.EDNS0_LOCAL{Code: 65001, Data: []byte("device-42")},
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID},
	}
}

// upstreamOptions are EDNS options that an upstream can put in its reply.
// None of them may reach the client (R3).
func upstreamOptions() []dns.EDNS0 {
	return []dns.EDNS0{
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8"},
		&dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeFiltered, ExtraText: "upstream note"},
		&dns.EDNS0_PADDING{Padding: make([]byte, 20)},
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 24, Address: net.IPv4(203, 0, 113, 0).To4()},
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "6e73"},
		&dns.EDNS0_LOCAL{Code: 65002, Data: []byte("upstream-data")},
	}
}

// withOPT adds an OPT record with size, do, and opts to m.
func withOPT(m *dns.Msg, size uint16, do bool, opts ...dns.EDNS0) *dns.Msg {
	m.SetEdns0(size, do)
	m.IsEdns0().Option = append(m.IsEdns0().Option, opts...)
	return m
}

// optRecords returns every OPT record in the additional section.
func optRecords(m *dns.Msg) []*dns.OPT {
	var out []*dns.OPT
	for _, rr := range m.Extra {
		if o, ok := rr.(*dns.OPT); ok {
			out = append(out, o)
		}
	}
	return out
}

// checkUpstreamQuery checks the parts of R1 that hold for every forwarded
// query: one question equal to want, opcode QUERY, only the RD, CD, and AD
// bits from the client, and exactly one OPT record with size 1232, version 0,
// and the client's DO bit, and nothing else in the record sections.
func checkUpstreamQuery(t *testing.T, got *dns.Msg, want dns.Question, rd, cd, ad, do bool) {
	t.Helper()
	if len(got.Question) != 1 || got.Question[0] != want {
		t.Errorf("upstream question = %v, want exactly [%v]", got.Question, want)
	}
	if got.Opcode != dns.OpcodeQuery {
		t.Errorf("upstream opcode = %d, want QUERY", got.Opcode)
	}
	if got.RecursionDesired != rd || got.CheckingDisabled != cd || got.AuthenticatedData != ad {
		t.Errorf("upstream RD/CD/AD = %v/%v/%v, want %v/%v/%v",
			got.RecursionDesired, got.CheckingDisabled, got.AuthenticatedData, rd, cd, ad)
	}
	if got.Response || got.Authoritative || got.Truncated || got.RecursionAvailable || got.Zero || got.Rcode != 0 {
		t.Errorf("upstream header has bits from the client: QR=%v AA=%v TC=%v RA=%v Z=%v rcode=%d",
			got.Response, got.Authoritative, got.Truncated, got.RecursionAvailable, got.Zero, got.Rcode)
	}
	if len(got.Answer) != 0 || len(got.Ns) != 0 {
		t.Errorf("upstream query has answer %v and authority %v, want none", got.Answer, got.Ns)
	}
	opts := optRecords(got)
	if len(opts) != 1 || len(got.Extra) != 1 {
		t.Fatalf("upstream additional section = %v, want exactly one OPT record", got.Extra)
	}
	o := opts[0]
	if o.UDPSize() != 1232 || o.Version() != 0 || o.Do() != do {
		t.Errorf("upstream OPT = size %d, version %d, DO %v; want 1232, 0, %v", o.UDPSize(), o.Version(), o.Do(), do)
	}
}

// noisyQuery is a client query that sets every header bit and fills every
// record section, so a test can see what reaches the upstream.
func noisyQuery(name string) *dns.Msg {
	req := new(dns.Msg)
	req.Id = 0x1234
	req.Question = []dns.Question{{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	req.RecursionDesired = true
	req.CheckingDisabled = true
	req.AuthenticatedData = true
	req.Authoritative = true
	req.Truncated = true
	req.RecursionAvailable = true
	req.Zero = true
	req.Rcode = dns.RcodeRefused
	req.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IPv4(10, 9, 8, 7)}}
	req.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 1}, Ns: "ns.client.example."}}
	req.Extra = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "client.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{"secret"}}}
	return req
}

func TestUpstreamQuery_IsBuiltBySHole(t *testing.T) {
	// CL 94 R1: the upstream gets one question in the client's letter case,
	// opcode QUERY, only the RD, CD, and AD bits from the client, and one OPT
	// record of s-hole's own. The client's other header bits, its records,
	// and its EDNS options do not reach the upstream.
	cases := []struct {
		name      string
		clientOPT bool
		do        bool
	}{
		{"OPT with DO and options", true, true},
		{"no OPT", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, rec := startRecordingUpstream(t, answerWith(net.IPv4(4, 4, 4, 4)), false)
			h := testHandler([]string{addr}, nil)
			req := noisyQuery("WwW.ExAmPlE.CoM.")
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
			checkUpstreamQuery(t, got, want, true, true, true, tc.do)
			if o := got.IsEdns0(); o != nil && len(o.Option) != 0 {
				t.Errorf("upstream OPT options = %v, want none over plain UDP", o.Option)
			}
			if w.written == nil || w.written.Rcode != dns.RcodeSuccess {
				t.Errorf("client reply = %v, want NOERROR", w.written)
			}
		})
	}
}

func TestUpstreamQuery_KeepsTypeAndClass(t *testing.T) {
	// CL 94 R1: the question keeps the client's type and class.
	for _, q := range []dns.Question{
		{Name: "Mail.Example.Org.", Qtype: dns.TypeMX, Qclass: dns.ClassINET},
		{Name: "example.org.", Qtype: dns.TypeHTTPS, Qclass: dns.ClassINET},
		{Name: "Version.Bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS},
	} {
		t.Run(dns.TypeToString[q.Qtype], func(t *testing.T) {
			addr, rec := startRecordingUpstream(t, answerWith(net.IPv4(4, 4, 4, 4)), false)
			h := testHandler([]string{addr}, nil)
			req := new(dns.Msg)
			req.Question = []dns.Question{q}
			req.RecursionDesired = true
			h.ServeDNS(fakeClient(), req)
			if rec.count() != 1 {
				t.Fatalf("upstream got %d queries, want 1", rec.count())
			}
			got, _, _ := rec.get(0)
			checkUpstreamQuery(t, got, q, true, false, false, false)
		})
	}
}

func TestUpstreamQuery_NewRandomIDOverUDP(t *testing.T) {
	// CL 94 R1: over plain UDP the upstream gets a new random query ID, not
	// the client's ID. One equal ID in 64 queries can be chance; more cannot.
	addr, rec := startRecordingUpstream(t, answerWith(net.IPv4(4, 4, 4, 4)), false)
	h := testHandler([]string{addr}, nil)
	const n = 64
	const clientID = 0x1234
	for i := 0; i < n; i++ {
		req := buildReq("id" + strings.Repeat("x", i%7) + ".example.com")
		req.Id = clientID
		w := fakeClient()
		h.ServeDNS(w, req)
		if w.written == nil || w.written.Id != clientID {
			t.Fatalf("query %d: client reply = %v, want ID %#x", i, w.written, clientID)
		}
	}
	if rec.count() != n {
		t.Fatalf("upstream got %d queries, want %d", rec.count(), n)
	}
	same := 0
	ids := map[uint16]bool{}
	for i := 0; i < n; i++ {
		m, _, _ := rec.get(i)
		ids[m.Id] = true
		if m.Id == clientID {
			same++
		}
	}
	if same > 1 {
		t.Errorf("%d of %d upstream queries used the client's ID %#x", same, n, clientID)
	}
	if len(ids) < n/2 {
		t.Errorf("only %d different upstream IDs in %d queries, want random IDs", len(ids), n)
	}
}

func TestUpstreamQuery_TCPRetryIsAlsoMinimal(t *testing.T) {
	// CL 94 R1, R2: when the UDP reply is truncated, the TCP query is the
	// same minimal query: no client data, a new ID, and no Padding option.
	addr, rec := startRecordingUpstream(t, answerWith(net.IPv4(4, 4, 4, 4)), true)
	h := testHandler([]string{addr}, nil)
	req := noisyQuery("Big.Example.Com.")
	withOPT(req, 4096, true, clientOptions()...)
	w := fakeClient()
	h.ServeDNS(w, req)

	if rec.count() != 2 {
		t.Fatalf("upstream got %d queries, want 2 (UDP, then TCP)", rec.count())
	}
	want := dns.Question{Name: "Big.Example.Com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	for i, network := range []string{"udp", "tcp"} {
		got, gotNet, _ := rec.get(i)
		if gotNet != network {
			t.Errorf("query %d went over %s, want %s", i, gotNet, network)
		}
		checkUpstreamQuery(t, got, want, true, true, true, true)
		if o := got.IsEdns0(); o != nil && len(o.Option) != 0 {
			t.Errorf("%s query has OPT options %v, want none", network, o.Option)
		}
		if got.Id == req.Id {
			t.Errorf("%s query used the client's ID %#x", network, req.Id)
		}
	}
	if w.written == nil || len(w.written.Answer) != 1 {
		t.Errorf("client reply = %v, want the TCP answer", w.written)
	}
}

func TestServeDNS_ReplyGetsTheClientsOPT(t *testing.T) {
	// CL 94 R3: the reply has the client's ID and question, and an OPT record
	// only when the query had one. That OPT record has the client's UDP size
	// and DO bit and no options: none of the upstream's options reach the
	// client.
	upstreamReply := func(req *dns.Msg) *dns.Msg {
		resp := answerWith(net.IPv4(4, 4, 4, 4))(req)
		return withOPT(resp, 4096, true, upstreamOptions()...)
	}
	cases := []struct {
		name string
		opt  bool
		size uint16
		do   bool
	}{
		{"client OPT 1400 with DO", true, 1400, true},
		{"client OPT 1300 without DO", true, 1300, false},
		{"client OPT 512", true, 512, false},
		{"client without OPT", false, 0, false},
	}
	for _, tc := range cases {
		for _, doh := range []bool{false, true} {
			label := tc.name + " over UDP upstream"
			if doh {
				label = tc.name + " over DoH upstream"
			}
			t.Run(label, func(t *testing.T) {
				var addr string
				if doh {
					addr, _ = startRecordingDoH(t, upstreamReply)
				} else {
					addr, _ = startRecordingUpstream(t, upstreamReply, false)
				}
				h := testHandler([]string{addr}, nil)
				req := new(dns.Msg)
				req.SetQuestion("MiXeD.Example.COM.", dns.TypeA)
				req.Id = 0xBEEF
				if tc.opt {
					withOPT(req, tc.size, tc.do, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"})
				}
				w := fakeClient()
				h.ServeDNS(w, req)

				r := w.written
				if r == nil {
					t.Fatal("no reply")
				}
				if r.Id != 0xBEEF {
					t.Errorf("reply ID = %#x, want the client's 0xbeef", r.Id)
				}
				if len(r.Question) != 1 || r.Question[0].Name != "MiXeD.Example.COM." {
					t.Errorf("reply question = %v, want the name as the client sent it", r.Question)
				}
				if len(r.Answer) != 1 {
					t.Errorf("reply answers = %v, want the upstream's one answer", r.Answer)
				}
				opts := optRecords(r)
				if !tc.opt {
					if len(opts) != 0 {
						t.Errorf("reply to a client without EDNS has OPT %v, want none", opts)
					}
					return
				}
				if len(opts) != 1 {
					t.Fatalf("reply has %d OPT records, want 1", len(opts))
				}
				o := opts[0]
				if o.UDPSize() != tc.size || o.Do() != tc.do {
					t.Errorf("reply OPT = size %d DO %v, want the client's size %d DO %v", o.UDPSize(), o.Do(), tc.size, tc.do)
				}
				if len(o.Option) != 0 {
					t.Errorf("reply OPT options = %v, want none", o.Option)
				}
				if _, err := r.Pack(); err != nil {
					t.Errorf("reply does not pack: %v", err)
				}
			})
		}
	}
}

func TestServeDNS_ExtendedRcodeWithoutClientOPT(t *testing.T) {
	// CL 94 R3: an extended RCODE (above 15) needs an OPT record. A client
	// without EDNS cannot get one, so it gets SERVFAIL, and the reply packs.
	upstreamReply := func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = dns.RcodeBadCookie
		resp.SetEdns0(1232, false)
		return resp
	}
	addr, rec := startRecordingUpstream(t, upstreamReply, false)
	h := testHandler([]string{addr}, nil)

	w := fakeClient()
	h.ServeDNS(w, buildReq("cookie.example.com"))
	if rec.count() != 1 {
		t.Fatalf("upstream got %d queries, want 1", rec.count())
	}
	if w.written == nil {
		t.Fatal("no reply")
	}
	if w.written.Rcode != dns.RcodeServerFailure {
		t.Errorf("reply rcode = %d, want SERVFAIL", w.written.Rcode)
	}
	if len(optRecords(w.written)) != 0 {
		t.Errorf("reply to a client without EDNS has an OPT record")
	}
	if _, err := w.written.Pack(); err != nil {
		t.Errorf("reply does not pack: %v", err)
	}

	// A client with EDNS can carry the extended RCODE; its reply must pack too.
	w = fakeClient()
	req := buildReq("cookie2.example.com")
	req.SetEdns0(1232, false)
	h.ServeDNS(w, req)
	if w.written == nil {
		t.Fatal("no reply to the EDNS client")
	}
	if _, err := w.written.Pack(); err != nil {
		t.Errorf("reply to the EDNS client does not pack: %v", err)
	}
	if len(optRecords(w.written)) != 1 {
		t.Errorf("reply to the EDNS client has %d OPT records, want 1", len(optRecords(w.written)))
	}
}

// tlsWriter is a fakeWriter for a DNS-over-TLS connection: ConnectionState
// returns a TLS state, as miekg/dns does for a TLS connection.
type tlsWriter struct {
	*fakeWriter
	state *tls.ConnectionState
}

func (w *tlsWriter) ConnectionState() *tls.ConnectionState { return w.state }

func dotWriter() *tlsWriter {
	return &tlsWriter{
		fakeWriter: &fakeWriter{remote: &net.TCPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 40000}},
		state:      &tls.ConnectionState{HandshakeComplete: true},
	}
}

func TestServeDNS_TruncationWithClientOPT(t *testing.T) {
	// CL 94 R5: a UDP reply is cut to the client's advertised size, with TC
	// set and the client's OPT record kept (no options). A DoT reply is not
	// cut.
	endpoint, _ := bigAnswerDoH(t, 40)
	h := testHandler([]string{endpoint}, nil)

	w := fakeClient()
	req := buildReq("big.example.com")
	req.SetEdns0(600, true)
	h.ServeDNS(w, req)
	if w.written == nil {
		t.Fatal("no UDP reply")
	}
	if n := packedLen(t, w.written); n > 600 || !w.written.Truncated {
		t.Errorf("UDP reply with EDNS 600: %d bytes, TC=%v; want at most 600 bytes with TC set", n, w.written.Truncated)
	}
	if o := w.written.IsEdns0(); o == nil || o.UDPSize() != 600 || !o.Do() || len(o.Option) != 0 {
		t.Errorf("truncated reply OPT = %v, want size 600, DO, no options", o)
	}

	dw := dotWriter()
	req = buildReq("big.example.com")
	req.SetEdns0(512, false)
	h.ServeDNS(dw, req)
	if dw.written == nil || dw.written.Truncated || len(dw.written.Answer) != 40 {
		t.Errorf("DoT reply: %v, want all 40 answers without TC", dw.written)
	}
}

func TestServeDNS_OtherOpcodeIsNotImplemented(t *testing.T) {
	// CL 94 R11: a query with an opcode other than QUERY gets NOTIMP, and
	// nothing goes upstream.
	for _, op := range []int{dns.OpcodeNotify, dns.OpcodeUpdate, dns.OpcodeStatus, dns.OpcodeIQuery} {
		t.Run(dns.OpcodeToString[op], func(t *testing.T) {
			sink, hits := udpSink(t)
			h := testHandler([]string{sink}, nil)
			req := buildReq("example.com")
			req.Opcode = op
			w := fakeClient()
			h.ServeDNS(w, req)
			if w.written == nil || w.written.Rcode != dns.RcodeNotImplemented {
				t.Errorf("reply = %v, want NOTIMP", w.written)
			}
			if hits.Load() != 0 {
				t.Errorf("upstream got %d packets, want 0", hits.Load())
			}
		})
	}
}

func TestServeDNS_QuestionCountMustBeOne(t *testing.T) {
	// CL 94 R11: a query with zero questions or more than one question gets
	// SERVFAIL, and nothing goes upstream.
	two := buildReq("one.example.com")
	two.Question = append(two.Question, dns.Question{Name: "two.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	three := buildReq("one.example.com")
	three.Question = append(three.Question, three.Question[0], three.Question[0])
	for name, req := range map[string]*dns.Msg{"zero": new(dns.Msg), "two": two, "three equal": three} {
		t.Run(name, func(t *testing.T) {
			sink, hits := udpSink(t)
			h := testHandler([]string{sink}, nil)
			w := fakeClient()
			h.ServeDNS(w, req)
			if w.written == nil || w.written.Rcode != dns.RcodeServerFailure {
				t.Errorf("reply = %v, want SERVFAIL", w.written)
			}
			if hits.Load() != 0 {
				t.Errorf("upstream got %d packets, want 0", hits.Load())
			}
		})
	}
}

func TestServeDNS_LANOnlyNameIsNoPlaintextFallback(t *testing.T) {
	// CL 94 R12: a LAN-only name answered by a plain LAN upstream does not
	// count as a plaintext fallback, although the full list has a DoH entry.
	// The public name at the end shows that the same setup does count a real
	// fallback.
	dohDown, _ := startDoHUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	plain, rec := startRecordingUpstream(t, answerWith(net.IPv4(192, 168, 1, 20)), false)
	h := testHandler([]string{dohDown, plain}, nil)
	markPublic(h, 0)

	before := PlaintextFallbacks()
	for _, name := range []string{"nas.lan", "printer", "router.home.arpa"} {
		w := fakeClient()
		h.ServeDNS(w, buildReq(name))
		if w.written == nil || len(w.written.Answer) != 1 {
			t.Fatalf("%s: reply = %v, want the LAN upstream's answer", name, w.written)
		}
	}
	if rec.count() != 3 {
		t.Fatalf("LAN upstream got %d queries, want 3", rec.count())
	}
	if got := PlaintextFallbacks() - before; got != 0 {
		t.Errorf("plaintext fallbacks after LAN-only names = %d, want 0", got)
	}

	before = PlaintextFallbacks()
	h.ServeDNS(fakeClient(), buildReq("public.example.com"))
	if got := PlaintextFallbacks() - before; got != 1 {
		t.Errorf("plaintext fallbacks after a public name = %d, want 1 (control)", got)
	}
}
