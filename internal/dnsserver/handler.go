// Package dnsserver implements the DNS sinkhole's listening servers and
// per-query handler. For each query the handler:
//  0. Refuses a query from outside the LAN (see lan.go). Answers SERVFAIL to a
//     query without exactly one question, NOTIMP to an opcode other than
//     QUERY, and REFUSED to a query with RD=0, without counting or logging it.
//  1. Intercepts PTR queries for the private reverse zones (RFC 6303 and
//     RFC 6598) and for the LAN's own global IPv6 prefix, and returns
//     authoritative NXDOMAIN locally, without consulting the blocklist,
//     cache, or upstream (see privateReverseZones, ownPrefixPTR).
//  2. Answers localhost names and never-resolved names (.onion, .invalid,
//     .alt) locally, and LAN-only names (such as "printer" or "nas.lan")
//     locally while no upstream is on the LAN (see localnames.go).
//  3. Consults the blocklist and writes a sinkhole reply for blocked domains.
//  4. Checks the in-memory response cache and returns cached replies. The
//     cache key holds the query's CD and DO bits as well as the question.
//  5. Forwards cache misses upstream in a fresh query that carries nothing
//     from the client but the question and a few flags (see edns.go). A
//     LAN-only name goes only to upstreams on the LAN. A reply that does not
//     match the query is a failed attempt (see checkReply in upstream.go). At
//     most maxForwards queries wait for an upstream; a query over the limit
//     gets SERVFAIL at once.
//
// UDP and TCP listeners (and the optional DNS-over-TLS listener, see dot.go)
// run in parallel and share this handler; clients fall back to TCP
// automatically when a UDP reply is truncated. On the upstream side the
// forwarder mirrors that fallback: a truncated UDP reply is retried over TCP
// against the same upstream before being returned. An "https://" upstream is
// forwarded over DNS-over-HTTPS (RFC 8484) instead. See exchange in upstream.go.
//
// Every reply except the REFUSED to a source outside the LAN (see refuse in
// lan.go) goes to the client through send (edns.go), which mirrors the
// client's EDNS0 OPT record without options, so clients that advertise EDNS0
// do not fall back to legacy DNS. A query with a question count other than
// one gets SERVFAIL, one with an opcode other than QUERY gets NOTIMP, and one
// with RD=0 gets REFUSED; none of them is counted or logged.
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
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
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

// maxForwards caps the queries that wait for an upstream at the same time.
// A cache miss holds its goroutine, a socket, and an upstream connection for
// up to queryDeadline, so without a cap one LAN device that sends many unique
// names could hold thousands of them. A query over the cap gets SERVFAIL at
// once (see ServeDNS). A home LAN rarely has more than a few dozen
// forwards in flight, so 512 leaves wide headroom. The cap is global: a limit
// for each client would keep client addresses in memory. It is a constant,
// not a config setting, like maxDoTConns.
const maxForwards = 512

// forwardLimited counts the queries that got SERVFAIL because maxForwards
// queries were already waiting for an upstream.
var forwardLimited atomic.Uint64

// ForwardLimited returns the number of queries that got SERVFAIL because
// s-hole already had the maximum number of queries waiting for an upstream,
// since startup. /metrics shows it as shole_forward_limited_total.
func ForwardLimited() uint64 {
	return forwardLimited.Load()
}

// errForwardLimit is the failure-summary cause for a query that got SERVFAIL
// because maxForwards queries were already waiting for an upstream.
var errForwardLimit = errors.New("too many queries were waiting for an upstream")

// Logger is the minimal log sink used by the DNS handler. Both the file
// and SQLite query loggers satisfy it; cmd/s-hole/main.go fans out to multiple via
// querylog.Multi. It takes a querylog.Record so a new per-query field does not
// change this signature.
type Logger interface {
	Log(rec querylog.Record)
}

// privateReverseZones holds the reverse zones that s-hole answers itself
// when localPTR is on: the locally served zones of RFC 6303 (the IPv6
// documentation prefix included), with the shared address space that
// RFC 6598 adds to that list. A PTR query under one of them gets authoritative
// NXDOMAIN. No public resolver holds records for these addresses, so
// forwarding only wastes a round-trip and tells the upstream which LAN
// addresses the devices talk to.
//
// IPv4: 0/8, 10/8, 100.64/10 (RFC 6598, CGNAT and Tailscale), 127/8,
// 169.254/16, 172.16/12, 192.168/16, the three documentation networks
// (192.0.2/24, 198.51.100/24, 203.0.113/24), and 255.255.255.255.
// IPv6: the unspecified (::) and loopback (::1) addresses, ULA fc00::/7,
// link-local fe80::/10, and documentation 2001:db8::/32.
//
// The keys are lowercase with the trailing root dot.
var privateReverseZones = reverseZones()

func reverseZones() map[string]bool {
	zones := []string{
		"0.in-addr.arpa.",
		"10.in-addr.arpa.",
		"127.in-addr.arpa.",
		"254.169.in-addr.arpa.",
		"168.192.in-addr.arpa.",
		"2.0.192.in-addr.arpa.",
		"100.51.198.in-addr.arpa.",
		"113.0.203.in-addr.arpa.",
		"255.255.255.255.in-addr.arpa.",
		// :: and ::1, one label per nibble
		strings.Repeat("0.", 32) + "ip6.arpa.",
		"1." + strings.Repeat("0.", 31) + "ip6.arpa.",
		// fc00::/7 ULA, covers fc::/8 and fd::/8
		"c.f.ip6.arpa.", "d.f.ip6.arpa.",
		// fe80::/10 link-local, third nibble is 8, 9, a, or b
		"8.e.f.ip6.arpa.", "9.e.f.ip6.arpa.", "a.e.f.ip6.arpa.", "b.e.f.ip6.arpa.",
		// 2001:db8::/32 documentation
		"8.b.d.0.1.0.0.2.ip6.arpa.",
	}
	// 172.16.0.0/12: second octet 16-31
	for i := 16; i <= 31; i++ {
		zones = append(zones, strconv.Itoa(i)+".172.in-addr.arpa.")
	}
	// 100.64.0.0/10 (RFC 6598): second octet 64-127
	for i := 64; i <= 127; i++ {
		zones = append(zones, strconv.Itoa(i)+".100.in-addr.arpa.")
	}
	out := make(map[string]bool, len(zones))
	for _, z := range zones {
		out[z] = true
	}
	return out
}

// isPrivatePTR reports whether q is a PTR query whose name falls under one
// of privateReverseZones. Non-PTR queries return false immediately without
// scanning the zones.
func isPrivatePTR(qtype uint16, name string) bool {
	if qtype != dns.TypePTR {
		return false
	}
	// DNS names are case-insensitive (RFC 1035 §2.3.3) and miekg/dns preserves
	// the wire-format case verbatim, so a mixed-case name (e.g. from a dns-0x20
	// forwarder) must be folded before matching the lowercase zones (b/032).
	// strings.ToLower does not allocate for a lowercase name, the form
	// ServeDNS passes.
	name = strings.ToLower(name)
	// Try the name and each parent: one map lookup per label.
	for off, end := 0, false; !end; off, end = dns.NextLabel(name, off) {
		if privateReverseZones[name[off:]] {
			return true
		}
	}
	return false
}

// ip6Prefix reads a reverse-lookup name under ip6.arpa ("b.a.9.8.[...].ip6.arpa.")
// as the IPv6 prefix it names: each label is one hex nibble, the last
// nibble first, so a name with n labels names a prefix of n*4 bits. It
// returns false for a name with a label that is not one nibble, with more
// than 32 nibbles, or outside ip6.arpa. name is lowercase with the trailing
// root dot.
func ip6Prefix(name string) (netip.Prefix, bool) {
	const zone = ".ip6.arpa."
	if !strings.HasSuffix(name, zone) {
		return netip.Prefix{}, false
	}
	labels := strings.Split(strings.TrimSuffix(name, zone), ".")
	if len(labels) > 32 {
		return netip.Prefix{}, false
	}
	var b [16]byte
	for i, l := range labels {
		if len(l) != 1 {
			return netip.Prefix{}, false
		}
		v, err := strconv.ParseUint(l, 16, 8)
		if err != nil {
			return netip.Prefix{}, false
		}
		// The last label is the first nibble of the address.
		n := len(labels) - 1 - i
		if n%2 == 0 {
			b[n/2] |= byte(v) << 4
		} else {
			b[n/2] |= byte(v)
		}
	}
	return netip.PrefixFrom(netip.AddrFrom16(b), len(labels)*4), true
}

// ownPrefixPTR reports whether q is a PTR query for an address in a global
// IPv6 subnet of this host's interfaces, the LAN's own public prefix. An
// IPv6 address made from the device's MAC address (EUI-64) names the
// device, so these lookups stay on the LAN like the private ranges.
func (h *Handler) ownPrefixPTR(qtype uint16, name string) bool {
	if qtype != dns.TypePTR {
		return false
	}
	p, ok := ip6Prefix(name)
	return ok && h.lan.ownGlobalV6(p)
}

// Handler is the per-query routing logic: LAN check → local PTR
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
	localPTR     bool         // when true, answer private and own-prefix PTR queries locally
	queryPrivacy string       // "drop", "subnet", or "full"; how the client IP is stored
	// logMode is query_log.mode: which queries are recorded. It decides what
	// reaches the Top Domains and Top Clients tallies. The zero value records
	// nothing.
	logMode  string
	failures *failureLog
	replies  *replyLog
	lan      *lanACL
	// upstreamIPs holds the address of each entry of upstreams, at the same
	// index, to find the LAN upstreams for a LAN-only name.
	upstreamIPs []netip.Addr
	// localDomains are the dns.local_domains suffixes, lowercase with the
	// trailing root dot.
	localDomains []string
	// forwardSlots holds one token for each query that waits for an
	// upstream; its capacity is maxForwards.
	forwardSlots chan struct{}
}

// NewHandler wires together all dependencies needed to answer a query.
// c may be nil to disable response caching entirely (the handler then
// always forwards on a cache miss). localPTR enables authoritative NXDOMAIN
// replies for PTR queries under privateReverseZones and under the host's
// own global IPv6 prefixes.
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
		replies:      newReplyLog(),
		lan:          newLANACL(),
		upstreamIPs:  ips,
		forwardSlots: make(chan struct{}, maxForwards),
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

// ServeDNS satisfies miekg/dns.Handler. It intercepts private and
// own-prefix PTR queries (when localPTR is enabled) and local-only names,
// returns a sinkhole reply for blocked domains, and otherwise serves from
// cache or forwards upstream.
func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	// Answer the LAN only (see lan.go). This runs first, so a query from
	// outside leaves no trace in the stats, the cache, or the query log. A
	// source that s-hole cannot read is not on the LAN either: the check
	// fails closed (b/100).
	ip := remoteIP(w).Unmap().WithZone("")
	if !ip.IsValid() || !h.lan.allows(ip) {
		refuse(w, req)
		return
	}
	if len(req.Question) != 1 {
		h.writeRcode(w, req, dns.RcodeServerFailure)
		return
	}
	if req.Opcode != dns.OpcodeQuery {
		// s-hole forwards a fresh QUERY (see upstreamQuery), so it cannot
		// pass on another opcode, such as NOTIFY or UPDATE.
		h.writeRcode(w, req, dns.RcodeNotImplemented)
		return
	}
	if !req.RecursionDesired {
		// A query with RD=0 reads only the cache. A LAN
		// device could use it to read the cache without adding to it, and the
		// remaining TTL of a cached answer tells to the second when another
		// device looked the name up. Unbound refuses such a query by default,
		// and a stub resolver always sets RD, so s-hole refuses it too, before
		// the stats, the cache, and the query log see it.
		h.writeRcode(w, req, dns.RcodeRefused)
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
	clientIP := querylog.MaskClientIP(ip.String(), h.queryPrivacy)

	// Answer PTR queries for the private zones (RFC 6303, RFC 6598) and for
	// the LAN's own global IPv6 prefix locally with authoritative NXDOMAIN.
	// No public resolver holds records for the private addresses, and a
	// reverse lookup of a LAN address tells the upstream which LAN
	// addresses are in use. Checked before the blocklist so these queries are never counted
	// as blocked.
	if h.localPTR && (isPrivatePTR(q.Qtype, domain) || h.ownPrefixPTR(q.Qtype, domain)) {
		ptrClient, ptrDomain := h.tally(clientIP, domain, false)
		h.counter.RecordQuery(ptrClient, ptrDomain, false)
		h.counter.RecordLocalPTR()
		h.logger.Log(querylog.Record{ClientIP: clientIP, Domain: domain, Rcode: dns.RcodeNameError, Synthesized: true})
		h.writeLocalNXDOMAIN(w, req)
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
		h.writeLocalNXDOMAIN(w, req)
		return
	}

	blocked := h.store.IsBlocked(domain)
	tallyClient, tallyDomain := h.tally(clientIP, domain, blocked)
	h.counter.RecordQuery(tallyClient, tallyDomain, blocked)

	// Log at the point each outcome is decided, so the query-log row records
	// the cache-hit flag (cache_hit) and the outcome (rcode + synthesized). A
	// blocked query short-circuits before the cache, and a local-PTR or
	// local-name answer never reaches it, so each logs CacheHit=false; total =
	// blocked + localPTR + localName + cached + forwarded (the remainder,
	// including forward-limited queries). The block reply is
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
		if cached, ok := h.cache.Get(req); ok {
			h.counter.RecordCacheHit()
			// Relayed from cache, not synthesized. The cache stores only
			// NOERROR-with-answers replies, so cached.Rcode is NOERROR.
			h.logger.Log(querylog.Record{ClientIP: clientIP, Domain: domain, CacheHit: true, Rcode: cached.Rcode})
			h.send(w, req, cached)
			return
		}
	}

	// Cache miss: forward, then log with the outcome the forward produced.
	// The log call moved after the forward (it was before it for the cache_hit
	// work in CL 76) so the row records rcode and the synthesized flag. A
	// forwarded query is still always logged, in both the error and success
	// branches, so the move does not lose the row a failed upstream used to log.
	//
	// A query over maxForwards is not forwarded. It is unresolved like a query
	// that every upstream failed: s-hole synthesizes the SERVFAIL, and the
	// query goes into the stats, the query log, and the failure summary the
	// same way.
	var resp *dns.Msg
	var err error
	select {
	case h.forwardSlots <- struct{}{}:
		ctx, cancel := context.WithTimeout(context.Background(), queryDeadline)
		resp, err = forward(ctx, upstreamQuery(req), upstreams)
		cancel()
		<-h.forwardSlots
	default:
		forwardLimited.Add(1)
		err = errForwardLimit
	}
	if err != nil {
		// Unresolved: every upstream failed at the transport level, the
		// deadline hit, or the forward limit was reached, so s-hole
		// synthesizes the SERVFAIL.
		// The failure goes into the once-a-minute summary (RunFailureReport),
		// not a per-query WARN, and the summary holds no name, so the system
		// log gets no query data.
		h.failures.record(err)
		h.counter.RecordForwardFailure()
		h.logger.Log(querylog.Record{ClientIP: clientIP, Domain: domain, Rcode: dns.RcodeServerFailure, Synthesized: true})
		h.writeRcode(w, req, dns.RcodeServerFailure)
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
		h.cache.Set(req, resp)
	}
	h.send(w, req, resp)
}

func (h *Handler) writeSinkhole(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	if h.blockMode == "nxdomain" {
		resp.SetRcode(req, dns.RcodeNameError)
		h.send(w, req, resp)
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
	h.send(w, req, resp)
}

// writeRcode sends an empty reply with rcode: SERVFAIL for an unresolved or
// malformed query, NOTIMP for an opcode s-hole does not forward, and REFUSED
// for a query with RD=0. It goes through send like every reply except refuse
// (lan.go), so the client keeps its OPT record and a DoT client its padding.
func (h *Handler) writeRcode(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	h.send(w, req, resp)
}

// writeLocalNXDOMAIN sends an authoritative NXDOMAIN reply for a name that
// s-hole answers locally: a local PTR query (a private reverse zone or the
// LAN's own IPv6 prefix) or a local-only name (see localnames.go).
func (h *Handler) writeLocalNXDOMAIN(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.SetRcode(req, dns.RcodeNameError)
	h.send(w, req, resp)
}
