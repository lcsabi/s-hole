package dnsserver

import (
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/miekg/dns"
)

// Some names mean something only on the local network, or nothing at all in
// the public DNS. Sending one to a public resolver tells it which devices and
// services the household has ("printer", "nas.lan", "wpad") and gets no
// useful answer. s-hole keeps these names off the internet. There is no
// setting to turn this off; dns.local_domains only adds suffixes.

// nameClass is how the handler routes a query name.
type nameClass int

const (
	// publicName is forwarded to every upstream, in order.
	publicName nameClass = iota
	// localhostName is "localhost" or a name under it (RFC 6761). s-hole
	// answers it with the loopback address and never forwards it.
	localhostName
	// neverResolved is a name that no DNS server can resolve: .invalid
	// (RFC 6761), .onion (RFC 7686), and .alt (RFC 9476). s-hole answers
	// NXDOMAIN and never forwards it, not even to a LAN upstream.
	neverResolved
	// lanOnlyName is forwarded only to upstreams on the LAN, such as the
	// router. With no LAN upstream, s-hole answers NXDOMAIN.
	lanOnlyName
)

// neverResolvedSuffixes are the special-use top-level domains that are not
// resolved through the DNS at all.
var neverResolvedSuffixes = []string{"invalid.", "onion.", "alt."}

// lanOnlySuffixes are the special-use and private-use domains that only a
// LAN server can answer: mDNS (.local, RFC 6762), the home network domain
// (home.arpa, RFC 8375), .internal (reserved by ICANN for private use), .test
// (RFC 6761), and the private TLDs that RFC 6762 Appendix G lists as in common
// use (.intranet, .private, .corp, .home, .lan), plus .localdomain, the domain
// of many hosts files and routers.
var lanOnlySuffixes = []string{
	"local.", "home.arpa.", "internal.", "test.",
	"intranet.", "private.", "corp.", "home.", "lan.", "localdomain.",
}

// classify returns the class of a query name. name is lowercase with the
// trailing root dot, as ServeDNS records it. localDomains are the extra
// suffixes from dns.local_domains, in the same form.
func classify(qtype uint16, name string, localDomains []string) nameClass {
	if underSuffix(name, "localhost.") {
		return localhostName
	}
	for _, s := range neverResolvedSuffixes {
		if underSuffix(name, s) {
			return neverResolved
		}
	}
	for _, s := range lanOnlySuffixes {
		if underSuffix(name, s) {
			return lanOnlyName
		}
	}
	for _, s := range localDomains {
		if underSuffix(name, s) {
			return lanOnlyName
		}
	}
	if dns.CountLabel(name) == 1 && !zoneType(qtype) {
		// A single-label name such as "printer" or "wpad" is a LAN host
		// name: no public resolver has an address for it.
		return lanOnlyName
	}
	return publicName
}

// zoneType reports whether qtype is a type that a stub or a validating
// resolver asks about a top-level domain itself, such as "com. DS" during
// DNSSEC validation or "org. NS". Such a query has a single-label name but is
// a public query, so it is forwarded as usual. dnsmasq's domain-needed option
// makes the same split from the other side: it keeps only A and AAAA
// queries for single-label names on the LAN.
func zoneType(qtype uint16) bool {
	switch qtype {
	case dns.TypeSOA, dns.TypeNS, dns.TypeDS, dns.TypeDNSKEY, dns.TypeRRSIG,
		dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeCDS, dns.TypeCDNSKEY:
		return true
	}
	return false
}

// underSuffix reports whether name is suffix or a name under it. Both are
// lowercase with the trailing root dot.
func underSuffix(name, suffix string) bool {
	return name == suffix || (strings.HasSuffix(name, suffix) && name[len(name)-len(suffix)-1] == '.')
}

// localSuffixes turns the dns.local_domains entries ("fritz.box") into the
// form classify matches: lowercase with the trailing root dot.
func localSuffixes(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		out = append(out, dns.Fqdn(strings.ToLower(d)))
	}
	return out
}

// upstreamIP returns the IP address of an upstream entry: the host of a DoH
// URL ("https://192.168.1.1/dns-query") or of a plain "IP:port" entry. config
// accepts only IP literals for both shapes, so no name is resolved here.
func upstreamIP(upstream string) (netip.Addr, bool) {
	var host string
	if strings.Contains(upstream, "://") {
		u, err := url.Parse(upstream)
		if err != nil {
			return netip.Addr{}, false
		}
		host = u.Hostname()
	} else {
		h, _, err := net.SplitHostPort(upstream)
		if err != nil {
			return netip.Addr{}, false
		}
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap().WithZone(""), true
}

// lanUpstreams returns the upstreams whose address is on the LAN, by the same
// rule the DNS server uses for its clients (see lanACL): a private, loopback,
// or link-local address, or one inside a subnet of this host's interfaces.
// The order of the upstream list is kept. A LAN upstream (usually the router)
// decides on its own what it forwards; s-hole cannot see that.
func (h *Handler) lanUpstreams() []string {
	var out []string
	for i, u := range h.upstreams {
		if ip := h.upstreamIPs[i]; ip.IsValid() && h.lan.allows(ip) {
			out = append(out, u)
		}
	}
	return out
}

// HasLANUpstream reports whether an upstream is on the LAN now, so local-only
// names such as "nas.lan" can be resolved. main logs a note at startup when
// there is none.
func (h *Handler) HasLANUpstream() bool {
	return len(h.lanUpstreams()) > 0
}

// localhostTTL is the TTL on a localhost answer. The answer never changes.
const localhostTTL = 3600

// writeLocalhost answers a localhost name (RFC 6761 section 6.3): the loopback
// address for A and AAAA, and an empty NOERROR answer for every other type.
func (h *Handler) writeLocalhost(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: localhostTTL}
	switch q.Qtype {
	case dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: net.IPv4(127, 0, 0, 1)})
	case dns.TypeAAAA:
		resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IPv6loopback})
	}
	h.send(w, req, resp)
}
