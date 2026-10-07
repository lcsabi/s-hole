package dnsserver

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// CL 94 R6: a reply over DNS-over-TLS to a query with a Padding option is
// padded to a multiple of 468 bytes (RFC 8467). Without a Padding option in
// the query, or over plain UDP or TCP, the reply has no padding.

// nilStateWriter is a TCP writer that implements ConnectionStater but has no
// TLS state, as miekg/dns does for a plain TCP connection.
type nilStateWriter struct{ *fakeWriter }

func (nilStateWriter) ConnectionState() *tls.ConnectionState { return nil }

// paddingCount returns the number of Padding options in m's OPT record.
func paddingCount(m *dns.Msg) int {
	o := m.IsEdns0()
	if o == nil {
		return 0
	}
	n := 0
	for _, opt := range o.Option {
		if opt.Option() == dns.EDNS0PADDING {
			n++
		}
	}
	return n
}

// paddedQuery is an A (or qtype) query for name with an OPT record that
// holds a Padding option, as a privacy-aware DoT client sends it.
func paddedQuery(name string, qtype uint16, padding bool) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	req.SetEdns0(1232, false)
	if padding {
		req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_PADDING{Padding: make([]byte, 40)})
	}
	return req
}

// paddingFixture is a handler that can give every kind of reply: forwarded,
// cached, sinkhole, and local answers. Its only upstream counts as public, so
// a LAN-only name gets a local NXDOMAIN.
func paddingFixture(t *testing.T, blockMode string) (*Handler, *cache.Cache) {
	t.Helper()
	addr, _ := startRecordingUpstream(t, answerWith(net.IPv4(4, 4, 4, 4)), false)
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})
	c := cache.New(100)
	t.Cleanup(c.Close)
	h := NewHandler(store, stats.New(), []string{addr}, nullLogger{}, blockMode, 60, c, true, "drop")
	h.lan = testACL(newFakeAddrs())
	markPublic(h, 0)
	return h, c
}

// replyKinds are the queries that give each kind of reply. "forwarded" and
// "cached" use the same name: the first query fills the cache.
var replyKinds = []struct {
	kind  string
	name  string
	qtype uint16
}{
	{"forwarded", "fwd.example.com.", dns.TypeA},
	{"cached", "fwd.example.com.", dns.TypeA},
	{"sinkhole A", "ads.example.com.", dns.TypeA},
	{"sinkhole MX", "ads.example.com.", dns.TypeMX},
	{"localhost A", "localhost.", dns.TypeA},
	{"localhost AAAA", "app.localhost.", dns.TypeAAAA},
	{"never resolved", "secret.onion.", dns.TypeA},
	{"LAN-only without LAN upstream", "nas.lan.", dns.TypeA},
	{"private PTR", "5.1.168.192.in-addr.arpa.", dns.TypePTR},
}

func TestServeDNS_DoTReplyIsPadded(t *testing.T) {
	// CL 94 R6: every kind of reply over DoT to a padded query is padded to a
	// multiple of 468 bytes.
	for _, mode := range []string{"zero", "nxdomain"} {
		t.Run(mode, func(t *testing.T) {
			h, c := paddingFixture(t, mode)
			for _, k := range replyKinds {
				w := dotWriter()
				h.ServeDNS(w, paddedQuery(k.name, k.qtype, true))
				if w.written == nil {
					t.Fatalf("%s: no reply", k.kind)
				}
				if n := paddingCount(w.written); n != 1 {
					t.Errorf("%s: reply has %d Padding options, want 1", k.kind, n)
				}
				if n := packedLen(t, w.written); n%468 != 0 {
					t.Errorf("%s: reply is %d bytes, want a multiple of 468", k.kind, n)
				}
			}
			// The padding is for one reply only; the cache does not keep it.
			q := dns.Question{Name: "fwd.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
			if m, ok := c.Get(q); !ok || m.IsEdns0() != nil {
				t.Errorf("cached reply: ok=%v, extra=%v; want it cached without an OPT record", ok, m)
			}
		})
	}
}

func TestServeDNS_NoPaddingWithoutRequestOrTLS(t *testing.T) {
	// CL 94 R6: no padding when the DoT query has no Padding option, and
	// never over plain UDP or TCP, even when the query has one.
	cases := []struct {
		name    string
		writer  func() dns.ResponseWriter
		padding bool
	}{
		{"DoT without Padding option", func() dns.ResponseWriter { return dotWriter() }, false},
		{"UDP with Padding option", func() dns.ResponseWriter { return fakeClient() }, true},
		{"TCP with Padding option", func() dns.ResponseWriter {
			return &fakeWriter{remote: &net.TCPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 40000}}
		}, true},
		{"TCP with no TLS state and Padding option", func() dns.ResponseWriter {
			return nilStateWriter{&fakeWriter{remote: &net.TCPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 40000}}}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := paddingFixture(t, "zero")
			for _, k := range replyKinds {
				w := tc.writer()
				h.ServeDNS(w, paddedQuery(k.name, k.qtype, tc.padding))
				var got *dns.Msg
				switch fw := w.(type) {
				case *tlsWriter:
					got = fw.written
				case *fakeWriter:
					got = fw.written
				case nilStateWriter:
					got = fw.written
				}
				if got == nil {
					t.Fatalf("%s: no reply", k.kind)
				}
				if n := paddingCount(got); n != 0 {
					t.Errorf("%s: reply has %d Padding options, want none", k.kind, n)
				}
			}
		})
	}
}

func TestDoT_PaddedQueryGetsPaddedReplyOnTheWire(t *testing.T) {
	// CL 94 R6, end to end: over a real DoT connection the reply to a padded
	// query is a multiple of 468 bytes on the wire. This checks that the
	// handler sees the TLS state of miekg/dns's own ResponseWriter. A query
	// without a Padding option gets no padding.
	certFile, keyFile, pool := writeTestCert(t, t.TempDir(), 1, time.Now().Add(90*24*time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	dotAddr, _ := startDoTServer(t, certs)

	conn, err := tls.Dial("tcp", dotAddr, &tls.Config{RootCAs: pool, ServerName: testCertName, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("dial DoT: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	exchange := func(req *dns.Msg) (int, *dns.Msg) {
		t.Helper()
		packed, err := req.Pack()
		if err != nil {
			t.Fatalf("pack: %v", err)
		}
		frame := make([]byte, 2+len(packed))
		binary.BigEndian.PutUint16(frame, uint16(len(packed)))
		copy(frame[2:], packed)
		if _, err := conn.Write(frame); err != nil {
			t.Fatalf("write: %v", err)
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			t.Fatalf("read length: %v", err)
		}
		body := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, body); err != nil {
			t.Fatalf("read body: %v", err)
		}
		var resp dns.Msg
		if err := resp.Unpack(body); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		return len(body), &resp
	}

	n, resp := exchange(paddedQuery("ads.example.com.", dns.TypeA, true))
	if n%468 != 0 || paddingCount(resp) != 1 {
		t.Errorf("padded query: reply is %d bytes with %d Padding options, want a multiple of 468 with one", n, paddingCount(resp))
	}
	_, resp = exchange(paddedQuery("ads.example.com.", dns.TypeA, false))
	if paddingCount(resp) != 0 {
		t.Errorf("query without Padding: reply has %d Padding options, want none", paddingCount(resp))
	}
}
