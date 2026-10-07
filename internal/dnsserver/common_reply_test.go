package dnsserver

import (
	"testing"

	"github.com/miekg/dns"
)

// CL 94 R15: every reply after the LAN check goes through the common reply
// path. That includes the SERVFAIL for an unresolved query, the SERVFAIL for
// a query with zero or several questions, and the NOTIMP for another opcode.
// Each has the client's ID, an OPT record (client's size and DO, no options)
// only when the query had one, and DoT padding when the query asked for it.

// errorReplyQueries builds the three kinds of query. opt adds an OPT record
// with size 1400, DO set, a COOKIE, and (with padding) a Padding option.
func errorReplyQueries(opt, padding bool) map[string]*dns.Msg {
	mk := func() *dns.Msg {
		req := new(dns.Msg)
		req.SetQuestion("fail.example.com.", dns.TypeA)
		req.Id = 0x5A5A
		if opt {
			opts := []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"}}
			if padding {
				opts = append(opts, &dns.EDNS0_PADDING{Padding: make([]byte, 30)})
			}
			withOPT(req, 1400, true, opts...)
		}
		return req
	}
	unresolved := mk()
	zero := mk()
	zero.Question = nil
	two := mk()
	two.Question = append(two.Question, dns.Question{Name: "other.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	notify := mk()
	notify.Opcode = dns.OpcodeNotify
	return map[string]*dns.Msg{
		"unresolved SERVFAIL":     unresolved,
		"zero questions SERVFAIL": zero,
		"two questions SERVFAIL":  two,
		"NOTIFY NOTIMP":           notify,
	}
}

var wantRcode = map[string]int{
	"unresolved SERVFAIL":     dns.RcodeServerFailure,
	"zero questions SERVFAIL": dns.RcodeServerFailure,
	"two questions SERVFAIL":  dns.RcodeServerFailure,
	"NOTIFY NOTIMP":           dns.RcodeNotImplemented,
}

// errorReplyHandler builds a handler for kind. An unresolved query needs an
// upstream that fails. The other kinds must not reach an upstream, so they
// get a sink that counts packets; the test checks it stays at 0.
func errorReplyHandler(t *testing.T, kind string) (*Handler, func() int64) {
	t.Helper()
	if kind == "unresolved SERVFAIL" {
		fail, _ := startFailingUpstream(t)
		return testHandler([]string{fail}, nil), func() int64 { return 0 }
	}
	sink, hits := udpSink(t)
	return testHandler([]string{sink}, nil), hits.Load
}

func TestServeDNS_ErrorRepliesUseTheCommonPath(t *testing.T) {
	// CL 94 R15: ID and OPT record of the error replies, over UDP.
	for _, opt := range []bool{false, true} {
		for kind, req := range errorReplyQueries(opt, false) {
			name := kind + " without OPT"
			if opt {
				name = kind + " with OPT"
			}
			t.Run(name, func(t *testing.T) {
				h, sent := errorReplyHandler(t, kind)
				w := fakeClient()
				h.ServeDNS(w, req)
				if n := sent(); n != 0 {
					t.Errorf("upstream got %d packets, want 0", n)
				}
				r := w.written
				if r == nil {
					t.Fatal("no reply")
				}
				if r.Rcode != wantRcode[kind] {
					t.Errorf("rcode = %d, want %d", r.Rcode, wantRcode[kind])
				}
				if r.Id != 0x5A5A {
					t.Errorf("reply ID = %#x, want the client's 0x5a5a", r.Id)
				}
				opts := optRecords(r)
				if !opt {
					if len(opts) != 0 {
						t.Errorf("reply has OPT %v, want none", opts)
					}
				} else if len(opts) != 1 || opts[0].UDPSize() != 1400 || !opts[0].Do() || len(opts[0].Option) != 0 {
					t.Errorf("reply OPT = %v, want one OPT with size 1400, DO, and no options", opts)
				}
				if _, err := r.Pack(); err != nil {
					t.Errorf("reply does not pack: %v", err)
				}
			})
		}
	}
}

func TestServeDNS_ErrorRepliesArePaddedOverDoT(t *testing.T) {
	// CL 94 R15: over DoT, an error reply to a query with a Padding option is
	// padded to a multiple of 468 bytes. Without the option, or over UDP, it
	// is not padded.
	for kind, req := range errorReplyQueries(true, true) {
		t.Run(kind, func(t *testing.T) {
			h, _ := errorReplyHandler(t, kind)

			dw := dotWriter()
			h.ServeDNS(dw, req.Copy())
			if dw.written == nil {
				t.Fatal("no DoT reply")
			}
			if n := paddingCount(dw.written); n != 1 {
				t.Errorf("DoT reply has %d Padding options, want 1", n)
			}
			if n := packedLen(t, dw.written); n%468 != 0 {
				t.Errorf("DoT reply is %d bytes, want a multiple of 468", n)
			}

			w := fakeClient()
			h.ServeDNS(w, req.Copy())
			if w.written == nil || paddingCount(w.written) != 0 {
				t.Errorf("UDP reply = %v, want no padding", w.written)
			}
		})
	}
	for kind, req := range errorReplyQueries(true, false) {
		t.Run(kind+" without Padding option", func(t *testing.T) {
			h, _ := errorReplyHandler(t, kind)
			dw := dotWriter()
			h.ServeDNS(dw, req)
			if dw.written == nil || paddingCount(dw.written) != 0 {
				t.Errorf("DoT reply = %v, want no padding", dw.written)
			}
		})
	}
}
