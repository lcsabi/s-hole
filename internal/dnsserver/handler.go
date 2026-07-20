// Package dnsserver implements the DNS sinkhole's listening servers and
// per-query handler. For each query the handler:
//  1. Intercepts PTR queries for RFC 6303 private-range zones and returns
//     authoritative NXDOMAIN locally, without consulting the blocklist,
//     cache, or upstream (see privateReverseZones, isPrivatePTR).
//  2. Consults the blocklist and writes a sinkhole reply for blocked domains.
//  3. Checks the in-memory response cache and returns cached replies.
//  4. Forwards cache misses to upstream resolvers.
//
// UDP and TCP listeners run in parallel; clients fall back to TCP
// automatically when a UDP reply is truncated. On the upstream side the
// forwarder mirrors that fallback: a truncated UDP reply is retried over TCP
// against the same upstream before being returned — see exchange in upstream.go.
//
// The handler mirrors the client's EDNS0 OPT pseudo-record on sinkhole
// replies so clients that advertise EDNS0 do not fall back to legacy DNS.
//
// Upstream forwarding is context-aware (per-query 10 s deadline,
// per-upstream 3 s timeout) and health-tracked: an upstream that failed
// in the last 30 s is skipped on the first sweep, then retried on a
// second sweep if every non-cooldown upstream also failed. See upstream.go
// for the tracker.
//
// The package is named dnsserver to avoid colliding with github.com/miekg/dns,
// which we import as `dns` for its message-codec types.
package dnsserver

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

var logger = slog.With("pkg", "dns")

// queryDeadline is the maximum time the handler is allowed to spend
// resolving a single query end-to-end (upstreams × per-upstream timeout
// is the worst case). Bounds the goroutine lifetime under pathological
// upstream behaviour.
const queryDeadline = 10 * time.Second

// Logger is the minimal log sink used by the DNS handler. Both the file
// and SQLite query loggers satisfy it; cmd/s-hole/main.go fans out to multiple via
// querylog.Multi.
type Logger interface {
	Log(clientIP, domain string, blocked bool)
}

// privateReverseZones lists the RFC 6303 locally-served DNS reverse zones.
// PTR queries whose names fall under any of these zones are answered locally
// with authoritative NXDOMAIN when localPTR is enabled: no public resolver
// holds records for RFC 1918 or ULA addresses, so forwarding only wastes a
// round-trip and leaks internal LAN addresses to the upstream resolver.
//
// IPv4 zones: RFC 1918 (10/8, 172.16/12, 192.168/16).
// IPv6 zones: RFC 4193 ULA fc00::/7 (c.f, d.f) and RFC 4291 link-local
// fe80::/10 (8.e.f, 9.e.f, a.e.f, b.e.f).
var privateReverseZones = []string{
	// 10.0.0.0/8
	"10.in-addr.arpa.",
	// 172.16.0.0/12 (second octet 16–31)
	"16.172.in-addr.arpa.", "17.172.in-addr.arpa.", "18.172.in-addr.arpa.",
	"19.172.in-addr.arpa.", "20.172.in-addr.arpa.", "21.172.in-addr.arpa.",
	"22.172.in-addr.arpa.", "23.172.in-addr.arpa.", "24.172.in-addr.arpa.",
	"25.172.in-addr.arpa.", "26.172.in-addr.arpa.", "27.172.in-addr.arpa.",
	"28.172.in-addr.arpa.", "29.172.in-addr.arpa.", "30.172.in-addr.arpa.",
	"31.172.in-addr.arpa.",
	// 192.168.0.0/16
	"168.192.in-addr.arpa.",
	// fc00::/7 ULA — covers fc::/8 and fd::/8
	"c.f.ip6.arpa.", "d.f.ip6.arpa.",
	// fe80::/10 link-local — third nibble is 8, 9, a, or b
	"8.e.f.ip6.arpa.", "9.e.f.ip6.arpa.", "a.e.f.ip6.arpa.", "b.e.f.ip6.arpa.",
}

// isPrivatePTR reports whether q is a PTR query whose name falls under one
// of the RFC 6303 private-range reverse zones. Non-PTR queries return false
// immediately without scanning the zone list.
func isPrivatePTR(qtype uint16, name string) bool {
	if qtype != dns.TypePTR {
		return false
	}
	for _, zone := range privateReverseZones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}
	return false
}

// Handler is the per-query routing logic: RFC 6303 local PTR check →
// blocklist check → cache check → upstream forward. It is safe for
// concurrent use; miekg/dns invokes ServeDNS from a separate goroutine
// per request.
type Handler struct {
	store     *blocklist.Store
	counter   *stats.Counter
	upstreams []string
	logger    Logger
	blockMode string // "zero" or "nxdomain"
	blockTTL  uint32
	cache     *cache.Cache // nil when caching is disabled
	localPTR  bool         // when true, answer RFC 6303 private PTR queries locally
}

// NewHandler wires together all dependencies needed to answer a query.
// c may be nil to disable response caching entirely (the handler then
// always forwards on a cache miss). localPTR enables authoritative NXDOMAIN
// replies for RFC 6303 private-range PTR queries; see privateReverseZones.
func NewHandler(
	store *blocklist.Store,
	counter *stats.Counter,
	upstreams []string,
	logger Logger,
	blockMode string,
	blockTTL uint32,
	c *cache.Cache,
	localPTR bool,
) *Handler {
	return &Handler{
		store:     store,
		counter:   counter,
		upstreams: upstreams,
		logger:    logger,
		blockMode: blockMode,
		blockTTL:  blockTTL,
		cache:     c,
		localPTR:  localPTR,
	}
}

// ServeDNS satisfies miekg/dns.Handler. It intercepts private-range PTR
// queries (when localPTR is enabled), returns a sinkhole reply for blocked
// domains, and otherwise serves from cache or forwards upstream.
func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	q := req.Question[0]
	domain := q.Name // already has trailing dot
	clientIP := clientAddr(w)

	// RFC 6303: answer PTR queries for private-range zones (10/8, 172.16/12,
	// 192.168/16, fc00::/7, fe80::/10) locally with authoritative NXDOMAIN.
	// No public resolver holds records for these addresses; forwarding wastes
	// a round-trip and leaks LAN addressing to the upstream. Checked before
	// the blocklist so these queries are never counted as blocked.
	if h.localPTR && isPrivatePTR(q.Qtype, domain) {
		h.counter.RecordQuery(clientIP, domain, false)
		h.counter.RecordLocalPTR()
		h.logger.Log(clientIP, domain, false)
		h.writeLocalNXDOMAIN(w, req)
		return
	}

	blocked := h.store.IsBlocked(domain)
	h.counter.RecordQuery(clientIP, domain, blocked)
	h.logger.Log(clientIP, domain, blocked)

	if blocked {
		h.writeSinkhole(w, req, q)
		return
	}

	// Serve from cache if available — avoids upstream round-trip entirely.
	if h.cache != nil {
		if cached, ok := h.cache.Get(q); ok {
			cached.Id = req.Id
			h.counter.RecordCacheHit()
			if err := w.WriteMsg(cached); err != nil {
				logger.Warn("write cached response failed", "err", err, "domain", domain)
			}
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), queryDeadline)
	defer cancel()
	resp, err := forward(ctx, req, h.upstreams)
	if err != nil {
		logger.Warn("upstream forward failed", "err", err, "domain", domain)
		dns.HandleFailed(w, req)
		return
	}

	if h.cache != nil {
		h.cache.Set(q, resp)
	}

	if err := w.WriteMsg(resp); err != nil {
		logger.Warn("write response failed", "err", err, "domain", domain)
	}
}

func (h *Handler) writeSinkhole(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	// Pass EDNS0 / OPT through so clients that advertised it do not retry
	// with a smaller buffer or fall back to legacy DNS. Mirrors what an
	// upstream resolver would do.
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	}

	if h.blockMode == "nxdomain" {
		resp.SetRcode(req, dns.RcodeNameError)
		if err := w.WriteMsg(resp); err != nil {
			logger.Warn("write sinkhole reply failed", "err", err, "domain", q.Name)
		}
		return
	}

	// Default: "zero" — return 0.0.0.0 / ::
	switch q.Qtype {
	case dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.blockTTL},
			A:   net.IPv4zero,
		})
	case dns.TypeAAAA:
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: h.blockTTL},
			AAAA: net.IPv6zero,
		})
	}
	// For MX, TXT, etc. return NOERROR with no answer — clients won't retry.
	if err := w.WriteMsg(resp); err != nil {
		logger.Warn("write sinkhole reply failed", "err", err, "domain", q.Name)
	}
}

// writeLocalNXDOMAIN sends an authoritative NXDOMAIN reply for a privately
// answered PTR query (RFC 6303). The EDNS0 OPT record is mirrored from the
// request for the same reason as in writeSinkhole: clients that advertised
// it must see it echoed or they fall back to legacy DNS.
func (h *Handler) writeLocalNXDOMAIN(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.SetRcode(req, dns.RcodeNameError)
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	}
	if err := w.WriteMsg(resp); err != nil {
		logger.Warn("write local PTR reply failed", "err", err, "domain", req.Question[0].Name)
	}
}

func clientAddr(w dns.ResponseWriter) string {
	addr := w.RemoteAddr()
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
