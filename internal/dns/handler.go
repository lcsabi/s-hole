// Package dns implements the DNS sinkhole's listening servers and per-query
// handler. The handler consults the blocklist, then the in-memory response
// cache, then upstream resolvers — in that order — and routes the reply
// back to the client. UDP and TCP listeners run in parallel; clients fall
// back to TCP automatically when a UDP reply is truncated.
package dns

import (
	"fmt"
	"net"

	"github.com/laszlo/s-hole/internal/blocklist"
	"github.com/laszlo/s-hole/internal/cache"
	"github.com/laszlo/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// Logger is the minimal log sink used by the DNS handler. Both the file
// and SQLite query loggers satisfy it; main.go fans out to multiple via
// querylog.Multi.
type Logger interface {
	Log(clientIP, domain string, blocked bool)
}

// Handler is the per-query routing logic: blocklist check → cache check
// → upstream forward. It is safe for concurrent use; miekg/dns invokes
// ServeDNS from a separate goroutine per request.
type Handler struct {
	store     *blocklist.Store
	counter   *stats.Counter
	upstreams []string
	logger    Logger
	blockMode string // "zero" or "nxdomain"
	blockTTL  uint32
	cache     *cache.Cache // nil when caching is disabled
}

// NewHandler wires together all dependencies needed to answer a query.
// c may be nil to disable response caching entirely (the handler then
// always forwards on a cache miss).
func NewHandler(
	store *blocklist.Store,
	counter *stats.Counter,
	upstreams []string,
	logger Logger,
	blockMode string,
	blockTTL uint32,
	c *cache.Cache,
) *Handler {
	return &Handler{
		store:     store,
		counter:   counter,
		upstreams: upstreams,
		logger:    logger,
		blockMode: blockMode,
		blockTTL:  blockTTL,
		cache:     c,
	}
}

// ServeDNS satisfies miekg/dns.Handler. It records the query in stats and
// loggers, returns a sinkhole reply if the domain is blocked, otherwise
// serves from cache or forwards upstream.
func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	q := req.Question[0]
	domain := q.Name // already has trailing dot
	clientIP := clientAddr(w)

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
				fmt.Printf("[dns] write cached: %v\n", err)
			}
			return
		}
	}

	resp, err := forward(req, h.upstreams)
	if err != nil {
		fmt.Printf("[dns] forward error: %v\n", err)
		dns.HandleFailed(w, req)
		return
	}

	if h.cache != nil {
		h.cache.Set(q, resp)
	}

	if err := w.WriteMsg(resp); err != nil {
		fmt.Printf("[dns] write: %v\n", err)
	}
}

func (h *Handler) writeSinkhole(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	if h.blockMode == "nxdomain" {
		resp.SetRcode(req, dns.RcodeNameError)
		if err := w.WriteMsg(resp); err != nil {
			fmt.Printf("[dns] write sinkhole: %v\n", err)
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
		fmt.Printf("[dns] write sinkhole: %v\n", err)
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
