package dnsserver

import "github.com/miekg/dns"

// CNAME inspection (blocking.cname_inspection, CL 117).
//
// A tracker can hide behind a subdomain of the site that uses it: the site
// points metrics.shop.example at shop.example.tracker.example with a CNAME
// record. The browser then sees a first-party name, the name is on no list,
// and the site's cookies go to the tracker. The resolver that answers the
// query follows the chain and returns it in the Answer section, so s-hole
// holds every target without a further lookup. chainBlocked checks them.
//
// Only CNAME targets are checked:
//   - the final A and AAAA addresses are not, because s-hole has no address
//     lists, and a tracker on a shared CDN shares its addresses with other
//     sites;
//   - a DNAME needs no check of its own, because the resolver also returns
//     the CNAME that it synthesizes from the DNAME;
//   - the target of an HTTPS or SVCB record needs none, because the client
//     looks that name up itself, through s-hole, which checks the name.
//
// s-hole cannot see a chain that the site's DNS provider resolves itself and
// returns as A records only (CNAME flattening), or a site server that sends
// the data on to the tracker.

// chainBlocked reports whether a CNAME target in resp is blocked. It is false
// when inspection is off, when resp carries a failure, and when the queried
// name (domain) is allowlisted: the operator's allowlist entry for a site
// keeps its answer, wherever the chain leads. A target that is allowlisted
// does not count either, because IsBlocked applies the allowlist to it. The
// check does not allocate, so it costs a few hash-set probes per CNAME.
func (h *Handler) chainBlocked(domain string, resp *dns.Msg) bool {
	if !h.cnameInspection || resp == nil || resp.Rcode != dns.RcodeSuccess {
		return false
	}
	hasCNAME := false
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.CNAME); ok {
			hasCNAME = true
			break
		}
	}
	if !hasCNAME || h.store.IsAllowlisted(domain) {
		return false
	}
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok && h.store.IsBlocked(c.Target) {
			return true
		}
	}
	return false
}
