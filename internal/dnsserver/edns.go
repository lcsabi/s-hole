package dnsserver

import (
	"net"

	"github.com/miekg/dns"
)

// s-hole does not forward the client's message. It builds a fresh query that
// holds only what an upstream needs to answer: the question, the RD, CD, and
// AD bits, the DO bit, a new random ID, and s-hole's own OPT record. Nothing
// the client put in its message reaches the upstream: not its query ID, not
// its EDNS options, such as a COOKIE (a per-device token that lets the
// upstream tell the household's devices apart behind one address) or a Client
// Subnet (part of the client's address). On the way back, s-hole removes the
// upstream's OPT record before the cache stores the reply, and builds a new
// OPT record for each client. So one client's options never reach another
// client through the cache.
//
// s-hole sends no DNS cookie of its own either. A cookie is an identifier
// that can link queries across a change of the household's public address.
// The plain-DNS fallback still has the random query ID and the random source
// port of each exchange against off-path spoofing, and checkReply
// (upstream.go) drops a reply for another question.

// upstreamUDPSize is the UDP payload size s-hole advertises upstream. 1232
// bytes fits in one IPv6 packet on any path (the DNS Flag Day 2020 value), so
// a reply is not fragmented; a larger reply comes back truncated and s-hole
// asks again over TCP (see exchange).
const upstreamUDPSize = 1232

// RFC 8467 block lengths for EDNS(0) padding: a query is padded to a multiple
// of 128 bytes and a reply to a multiple of 468 bytes, so the size of an
// encrypted message tells an observer little about the name in it.
const (
	queryPadBlock = 128
	replyPadBlock = 468
)

// upstreamQuery builds the query s-hole sends upstream for req (see the
// comment at the top of this file). req has exactly one question. The case of
// the name is kept, so a reply still echoes it to a dns-0x20 client.
func upstreamQuery(req *dns.Msg) *dns.Msg {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                dns.Id(),
			Opcode:            dns.OpcodeQuery,
			RecursionDesired:  req.RecursionDesired,
			CheckingDisabled:  req.CheckingDisabled,
			AuthenticatedData: req.AuthenticatedData,
		},
		Question: []dns.Question{req.Question[0]},
	}
	do := false
	if opt := req.IsEdns0(); opt != nil {
		do = opt.Do()
	}
	m.SetEdns0(upstreamUDPSize, do)
	return m
}

// stripOPT removes the OPT record from an upstream reply, with every EDNS
// option in it. The handler calls it before the cache stores the reply, so a
// cached reply holds no options, and send builds the client's own OPT record.
// miekg/dns has already folded the OPT record's extended RCODE bits into
// resp.Rcode, so the RCODE is kept.
func stripOPT(resp *dns.Msg) {
	extra := resp.Extra[:0]
	for _, rr := range resp.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	resp.Extra = extra
}

// send finishes a reply for the client and writes it. Every reply except the
// REFUSED to a source outside the LAN (refuse, lan.go) goes through it: a
// sinkhole or local answer, a cached or forwarded reply, and the SERVFAIL,
// NOTIMP, and RD=0 REFUSED replies (writeRcode).
// It sets the client's query ID, gives the reply an OPT record when the query
// had one (the client's UDP size and DO bit mirrored, with no options; RFC
// 6891 forbids an OPT record in a reply to a query without one), truncates a
// UDP reply to the size the client can take, and pads the reply when the
// query came over DNS-over-TLS with a Padding option (RFC 8467). A write
// error goes into the once-a-minute failed-reply summary (replyLog), not a
// line of its own.
func (h *Handler) send(w dns.ResponseWriter, req, resp *dns.Msg) {
	resp.Id = req.Id
	opt := req.IsEdns0()
	if opt != nil {
		if resp.IsEdns0() == nil {
			resp.SetEdns0(opt.UDPSize(), opt.Do())
		}
	} else if resp.Rcode > 0xF {
		// An extended RCODE needs an OPT record. With no OPT record in the
		// query, the reply cannot carry one, so it says SERVFAIL instead.
		resp.Rcode = dns.RcodeServerFailure
	}
	fitUDP(w, req, resp)
	if opt != nil && overTLS(w) && wantsPadding(opt) {
		pad(resp, replyPadBlock)
	}
	if err := w.WriteMsg(resp); err != nil {
		h.replies.record(err)
	}
}

// fitUDP truncates a relayed reply to the size the client can take over
// UDP: 512 bytes without EDNS0, or the buffer size the client advertised.
// An upstream reply can be larger: after a TC retry over TCP, or from a DoH
// upstream, which has no UDP size limit. A larger UDP reply is dropped or
// cut by the network or the client's stub (b/081). Truncate sets the TC bit,
// so the client asks again over TCP and gets the full reply. TCP and DoT
// replies are not changed.
func fitUDP(w dns.ResponseWriter, req, resp *dns.Msg) {
	if _, udp := w.RemoteAddr().(*net.UDPAddr); !udp {
		return
	}
	size := dns.MinMsgSize
	if opt := req.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
		size = int(opt.UDPSize())
	}
	resp.Truncate(size)
}

// overTLS reports whether the query came over DNS-over-TLS.
func overTLS(w dns.ResponseWriter) bool {
	cs, ok := w.(dns.ConnectionStater)
	return ok && cs.ConnectionState() != nil
}

// wantsPadding reports whether the client's OPT record holds a Padding
// option. RFC 7830 lets a server pad a reply only when the query was padded.
func wantsPadding(opt *dns.OPT) bool {
	for _, o := range opt.Option {
		if o.Option() == dns.EDNS0PADDING {
			return true
		}
	}
	return false
}

// pad adds a Padding option to m's OPT record so that the packed message is a
// multiple of block bytes long. m must have an OPT record; without one, pad
// does nothing. A message that the padding would push over the DNS size limit
// is not padded.
func pad(m *dns.Msg, block int) {
	opt := m.IsEdns0()
	if opt == nil {
		return
	}
	p := &dns.EDNS0_PADDING{}
	opt.Option = append(opt.Option, p)
	n := m.Len() // includes the 4-byte header of the empty Padding option
	if r := n % block; r != 0 && n+block-r <= dns.MaxMsgSize {
		p.Padding = make([]byte, block-r)
	}
}

// packDoH packs the query for a DoH upstream: with ID 0, as RFC 8484 asks so
// that equal queries are equal on the wire, and padded to a multiple of
// queryPadBlock bytes. TLS hides the bytes but not the length, so without the
// padding the length of the request would hint at the name. q is not changed;
// the same query may go to a plain upstream next.
func packDoH(q *dns.Msg) ([]byte, error) {
	m := q.Copy()
	m.Id = 0
	pad(m, queryPadBlock)
	return m.Pack()
}
