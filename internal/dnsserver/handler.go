// Package dnsserver implements the DNS sinkhole's listening servers and
// per-query handler. For each query the handler:
//  0. Refuses a query from outside the LAN (see lan.go). Answers SERVFAIL to a
//     query without exactly one question and NOTIMP to an opcode other than
//     QUERY, without counting or logging it.
//  1. Intercepts PTR queries for RFC 6303 private-range zones and returns
//     authoritative NXDOMAIN locally, without consulting the blocklist,
//     cache, or upstream (see privateReverseZones, isPrivatePTR).
//  2. Answers localhost names and never-resolved names (.onion, .invalid,
//     .alt) locally, and LAN-only names (such as "printer" or "nas.lan")
//     locally while no upstream is on the LAN (see localnames.go).
//  3. Consults the blocklist and writes a sinkhole reply for blocked domains.
//  4. Checks the in-memory response cache and returns cached replies.
//  5. Forwards cache misses upstream in a fresh query that carries nothing
//     from the client but the question and a few flags (see edns.go). A
//     LAN-only name goes only to upstreams on the LAN.
//
// UDP and TCP listeners (and the optional DNS-over-TLS listener, see dot.go)
// run in parallel and share this handler; clients fall back to TCP
// automatically when a UDP reply is truncated. On the upstream side the
// forwarder mirrors that fallback: a truncated UDP reply is retried over TCP
// against the same upstream before being returned. An "https://" upstream is
// forwarded over DNS-over-HTTPS (RFC 8484) instead. See exchange in upstream.go.
//
// Every reply except REFUSED (see refuse in lan.go) goes to the client through
// send (edns.go), which mirrors the client's EDNS0 OPT record without
// options, so clients that advertise EDNS0 do not fall back to legacy DNS. A
// query with a question count other than one gets SERVFAIL, and one with an
// opcode other than QUERY gets NOTIMP; neither is counted or logged.
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
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/logging"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

var logger = logging.For("dns")

// queryDeadline is the maximum time the handler is allowed to spend
// resolving a single query end-to-end (upstreams × per-upstream timeout
// is the worst case). Bounds the goroutine lifetime under pathological
// upstream behaviour.
const queryDeadline = 10 * time.Second

// Logger is the minimal log sink used by the DNS handler. Both the file
// and SQLite query loggers satisfy it; cmd/s-hole/main.go fans out to multiple via
// querylog.Multi. It takes a querylog.Record so a new per-query field does not
// change this signature.
type Logger interface {
	Log(rec querylog.Record)
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
	// 172.16.0.0/12 (second octet 16-31)
	"16.172.in-addr.arpa.", "17.172.in-addr.arpa.", "18.172.in-addr.arpa.",
	"19.172.in-addr.arpa.", "20.172.in-addr.arpa.", "21.172.in-addr.arpa.",
	"22.172.in-addr.arpa.", "23.172.in-addr.arpa.", "24.172.in-addr.arpa.",
	"25.172.in-addr.arpa.", "26.172.in-addr.arpa.", "27.172.in-addr.arpa.",
	"28.172.in-addr.arpa.", "29.172.in-addr.arpa.", "30.172.in-addr.arpa.",
	"31.172.in-addr.arpa.",
	// 192.168.0.0/16
	"168.192.in-addr.arpa.",
	// fc00::/7 ULA, covers fc::/8 and fd::/8
	"c.f.ip6.arpa.", "d.f.ip6.arpa.",
	// fe80::/10 link-local, third nibble is 8, 9, a, or b
	"8.e.f.ip6.arpa.", "9.e.f.ip6.arpa.", "a.e.f.ip6.arpa.", "b.e.f.ip6.arpa.",
}

// isPrivatePTR reports whether q is a PTR query whose name falls under one
// of the RFC 6303 private-range reverse zones. Non-PTR queries return false
// immediately without scanning the zone list.
func isPrivatePTR(qtype uint16, name string) bool {
	if qtype != dns.TypePTR {
		return false
	}
	// DNS names are case-insensitive (RFC 1035 §2.3.3) and miekg/dns preserves
	// the wire-format case verbatim, so a mixed-case name (e.g. from a dns-0x20
	// forwarder) must be folded before matching the lowercase zone list; the
	// same normalisation blocklist.normalize applies (b/032). Non-PTR queries
	// already returned above, so this allocation only ever hits real PTR queries.
	name = strings.ToLower(name)
	for _, zone := range privateReverseZones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}
	return false
}

// Handler is the per-query routing logic: LAN check → RFC 6303 local PTR
// check → local-name check → blocklist check → cache check → upstream
// forward. It is safe for
// concurrent use; miekg/dns invokes ServeDNS from a separate goroutine
// per request.
type Handler struct {
	store        *blocklist.Store
	counter      *stats.Counter
	upstreams    []string
	logger       Logger
	blockMode    string // "zero_ip" or "nxdomain"
	blockTTL     uint32
	cache        *cache.Cache // nil when caching is disabled
	localPTR     bool         // when true, answer RFC 6303 private PTR queries locally
	queryPrivacy string       // "drop", "subnet", or "full"; how the client IP is stored
	// logMode is query_log.mode: which queries are recorded. It decides what
	// reaches the Top Domains and Top Clients tallies and whether a WARN line
	// may name the query. The zero value records nothing.
	logMode  string
	failures *failureLog
	lan      *lanACL
	// upstreamIPs holds the address of each entry of upstreams, at the same
	// index, to find the LAN upstreams for a LAN-only name.
	upstreamIPs []netip.Addr
	// localDomains are the dns.local_domains suffixes, lowercase with the
	// trailing root dot.
	localDomains []string
}

// NewHandler wires together all dependencies needed to answer a query.
// c may be nil to disable response caching entirely (the handler then
// always forwards on a cache miss). localPTR enables authoritative NXDOMAIN
// replies for RFC 6303 private-range PTR queries; see privateReverseZones.
// queryPrivacy selects how the client IP is stored ("drop", "subnet", or
// "full"); see querylog.MaskClientIP.
func NewHandler(
	store *blocklist.Store,
	counter *stats.Counter,
	upstreams []string,
	logger Logger,
	blockMode string,
	blockTTL uint32,
	c *cache.Cache,
	localPTR bool,
	queryPrivacy string,
) *Handler {
	ips := make([]netip.Addr, len(upstreams))
	for i, u := range upstreams {
		ips[i], _ = upstreamIP(u)
	}
	return &Handler{
		store:        store,
		counter:      counter,
		upstreams:    upstreams,
		logger:       logger,
		blockMode:    blockMode,
		blockTTL:     blockTTL,
		cache:        c,
		localPTR:     localPTR,
		queryPrivacy: queryPrivacy,
		failures:     newFailureLog(),
		lan:          newLANACL(),
		upstreamIPs:  ips,
	}
}

// SetLocalDomains sets the dns.local_domains suffixes: names under them go
// only to upstreams on the LAN, like the built-in local names. Call it before
// the server starts.
func (h *Handler) SetLocalDomains(domains []string) {
	h.localDomains = localSuffixes(domains)
}

// SetQueryLogMode sets query_log.mode ("none", "blocked", or "all"). Call it
// before the server starts. Until it is called the handler records nothing,
// the most private choice.
func (h *Handler) SetQueryLogMode(mode string) {
	h.logMode = mode
}

// records reports whether the query log records a query with this outcome,
// the same rule the query loggers apply.
func (h *Handler) records(blocked bool) bool {
	switch h.logMode {
	case "all":
		return true
	case "blocked":
		return blocked
	default:
		return false
	}
}

// tally returns the client and domain to count in the Top Clients and Top
// Domains lists: both empty when the query log does not record this query,
// so query_log.mode governs the in-memory lists exactly as it governs the
// database and the log file.
func (h *Handler) tally(clientIP, domain string, blocked bool) (string, string) {
	if !h.records(blocked) {
		return "", ""
	}
	return clientIP, domain
}

// warnAttrs builds the attributes of a WARN line about one query: the safe
// part of the error (see writeErr), and the domain only when the query log
// records every query. A WARN line never holds the client address.
func (h *Handler) warnAttrs(err error, domain string) []any {
	attrs := []any{"err", writeErr(err)}
	if h.logMode == "all" {
		// Lowercase, as the query log records it (b/082); the reply writers
		// pass the name as sent.
		attrs = append(attrs, "domain", strings.ToLower(domain))
	}
	return attrs
}

// ServeDNS satisfies miekg/dns.Handler. It intercepts private-range PTR
// queries (when localPTR is enabled) and local-only names, returns a sinkhole
// reply for blocked domains, and otherwise serves from cache or forwards
// upstream.
func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	// Answer the LAN only (see lan.go). This runs first, so a query from
	// outside leaves no trace in the stats, the cache, or the query log.
	if ip := remoteIP(w); ip.IsValid() && !h.lan.allows(ip) {
		refuse(w, req)
		return
	}
	if len(req.Question) != 1 {
		h.writeRcode(w, req, dns.RcodeServerFailure, "")
		return
	}
	if req.Opcode != dns.OpcodeQuery {
		// s-hole forwards a fresh QUERY (see upstreamQuery), so it cannot
		// pass on another opcode, such as NOTIFY or UPDATE.
		h.writeRcode(w, req, dns.RcodeNotImplemented, "")
		return
	}

	q := req.Question[0]
	// The name as s-hole records it: lowercase, with the trailing dot. DNS
	// names are case-insensitive, and a dns-0x20 forwarder randomizes the
	// case, so recording q.Name as sent split one domain into several rows in
	// Top Blocked and missed the domain filter (b/082). Replies still echo
	// q.Name exactly, which the forwarder checks. strings.ToLower returns the
	// string unchanged, without an allocation, when it is lowercase already.
	domain := strings.ToLower(q.Name)
	// Mask the client once, at this single write-time choke point, so the
	// stats counter (Top Clients) and every query-log sink downstream see the
	// same value. See querylog.MaskClientIP and the query_log.clients config
	// setting.
	clientIP := querylog.MaskClientIP(clientAddr(w), h.queryPrivacy)

	// RFC 6303: answer PTR queries for private-range zones (10/8, 172.16/12,
	// 192.168/16, fc00::/7, fe80::/10) locally with authoritative NXDOMAIN.
	// No public resolver holds records for these addresses; forwarding wastes
	// a round-trip and leaks LAN addressing to the upstream. Checked before
	// the blocklist so these queries are never counted as blocked.
	if h.localPTR && isPrivatePTR(q.Qtype, domain) {
		ptrClient, ptrDomain := h.tally(clientIP, domain, false)
		h.counter.RecordQuery(ptrClient, ptrDomain, false)
		h.counter.RecordLocalPTR()
		h.logger.Log(querylog.Record{ClientIP: clientIP, Domain: domain, Rcode: dns.RcodeNameError, Synthesized: true})
		h.writeLocalNXDOMAIN(w, req, "write local PTR reply failed")
		return
	}

	// Local-only names (see localnames.go). Checked before the blocklist, so
	// a localhost name is never blocked and these local answers are never
	// counted as blocked. A LAN-only name with a LAN upstream goes on like a
	// public name, but only to the LAN upstreams.
	class := classify(q.Qtype, domain, h.localDomains)
	upstreams := h.upstreams
	if class == lanOnlyName {
		upstreams = h.lanUpstreams()
	}
	if class == localhostName || class == neverResolved || (class == lanOnlyName && len(upstreams) == 0) {
		localClient, localDomain := h.tally(clientIP, domain, false)
		h.counter.RecordQuery(localClient, localDomain, false)
		h.counter.RecordLocalName()
		if class == localhostName {
			h.logger.Log(querylog.Record{ClientIP: clientIP, Domain: domain, Rcode: dns.RcodeSuccess, Synthesized: true})
			h.writeLocalhost(w, req, q)
			return
		}
		h.logger.Log(querylog.Record{ClientIP: clientIP, Domain: domain, Rcode: dns.RcodeNameError, Synthesized: true})
		h.writeLocalNXDOMAIN(w, req, "write local name reply failed")
		return
	}

	blocked := h.store.IsBlocked(domain)
	tallyClient, tallyDomain := h.tally(clientIP, domain, blocked)
	h.counter.RecordQuery(tallyClient, tallyDomain, blocked)

	// Log at the point each outcome is decided, so the query-log row records
	// the cache-hit flag (cache_hit) and the outcome (rcode + synthesized). A
	// blocked query short-circuits before the cache, and a local-PTR or
	// local-name answer never reaches it, so each logs CacheHit=false; total =
	// blocked + localPTR + localName + cached + forwarded. The block reply is
	// synthesized locally: NXDOMAIN in "nxdomain" mode, NOERROR otherwise
	// (matching writeSinkhole), neither a failure rcode.
	if blocked {
		blockRcode := dns.RcodeSuccess
		if h.blockMode == "nxdomain" {
			blockRcode = dns.RcodeNameError
		}
		h.logger.Log(querylog.Record{ClientIP: clientIP, Domain: domain, Blocked: true, Rcode: blockRcode, Synthesized: true})
		h.writeSinkhole(w, req, q)
		return
	}

	// Serve from cache if available; avoids upstream round-trip entirely.
	if h.cache != nil {
		if cached, ok := h.cache.Get(q); ok {
			h.counter.RecordCacheHit()
			// Relayed from cache, not synthesized. The cache stores only
			// NOERROR-with-answers replies, so cached.Rcode is NOERROR.
			h.logger.Log(querylog.Record{ClientIP: clientIP, Domain: domain, CacheHit: true, Rcode: cached.Rcode})
			h.send(w, req, cached, "write cached response failed", domain)
			return
		}
	}

	// Cache miss: forward, then log with the outcome the forward produced.
	// The log call moved after the forward (it was before it for the cache_hit
	// work in CL 76) so the row records rcode and the synthesized flag. A
	// forwarded query is still always logged, in both the error and success
	// branches, so the move does not lose the row a failed upstream used to log.
	ctx, cancel := context.WithTimeout(context.Background(), queryDeadline)
	defer cancel()
	resp, err := forward(ctx, upstreamQuery(req), upstreams)
	if err != nil {
		// Unresolved: every upstream failed at the transport level or the
		// deadline hit, so s-hole synthesizes the SERVFAIL.
		// The failure goes into the once-a-minute summary (RunFailureReport),
		// not a per-query WARN, so an outage does not write every failed name
		// to the system log.
		failedDomain := ""
		if h.logMode == "all" {
			failedDomain = domain
		}
		h.failures.record(err, failedDomain)
		h.counter.RecordForwardFailure()
		h.logger.Log(querylog.Record{ClientIP: clientIP, Domain: domain, Rcode: dns.RcodeServerFailure, Synthesized: true})
		h.writeRcode(w, req, dns.RcodeServerFailure, domain)
		return
	}

	// A live upstream answered. If it relayed a failure rcode (SERVFAIL or
	// REFUSED), that is an upstream error, distinct from an unresolved query:
	// s-hole relayed it, it did not synthesize it.
	if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
		h.counter.RecordUpstreamError()
	}
	h.logger.Log(querylog.Record{ClientIP: clientIP, Domain: domain, Rcode: resp.Rcode})

	// The upstream's OPT record goes before the cache stores the reply, so a
	// cached reply holds no options; send gives each client its own.
	stripOPT(resp)
	if h.cache != nil {
		h.cache.Set(q, resp)
	}
	h.send(w, req, resp, "write response failed", domain)
}

func (h *Handler) writeSinkhole(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	if h.blockMode == "nxdomain" {
		resp.SetRcode(req, dns.RcodeNameError)
		h.send(w, req, resp, "write sinkhole reply failed", q.Name)
		return
	}

	// Default: "zero_ip" returns 0.0.0.0 / ::
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
	// For MX, TXT, etc. return NOERROR with no answer; clients won't retry.
	h.send(w, req, resp, "write sinkhole reply failed", q.Name)
}

// writeRcode sends an empty reply with rcode: SERVFAIL for an unresolved or
// malformed query, NOTIMP for an opcode s-hole does not forward. It goes
// through send like every other reply, so the client keeps its OPT record and
// a DoT client its padding.
func (h *Handler) writeRcode(w dns.ResponseWriter, req *dns.Msg, rcode int, domain string) {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	h.send(w, req, resp, "write error reply failed", domain)
}

// writeLocalNXDOMAIN sends an authoritative NXDOMAIN reply for a name that
// s-hole answers locally: a private-range PTR query (RFC 6303) or a local-only
// name (see localnames.go). warnMsg is logged if the write fails.
func (h *Handler) writeLocalNXDOMAIN(w dns.ResponseWriter, req *dns.Msg, warnMsg string) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.SetRcode(req, dns.RcodeNameError)
	h.send(w, req, resp, warnMsg, req.Question[0].Name)
}

// clientAddr returns the query source IP (no port) for the stats top-clients
// tracker and the query log. It runs on every query, so it reads the IP
// directly from the concrete address type. The former SplitHostPort(addr.String())
// form built "ip:port" (a JoinHostPort allocation) only to parse the port back
// off, two allocations per query for a value we throw away. The type switch
// keeps just the one IP.String() allocation; the SplitHostPort path stays as a
// fallback for any other net.Addr implementation.
func clientAddr(w dns.ResponseWriter) string {
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		if a == nil {
			return "unknown"
		}
		return a.IP.String()
	case *net.TCPAddr:
		if a == nil {
			return "unknown"
		}
		return a.IP.String()
	case nil:
		return "unknown"
	default:
		host, _, err := net.SplitHostPort(a.String())
		if err != nil {
			return a.String()
		}
		return host
	}
}
