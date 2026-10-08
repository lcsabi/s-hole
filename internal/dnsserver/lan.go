package dnsserver

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// s-hole answers only clients on the local network. A resolver that answers
// anyone is an open resolver: on a host with a public IPv6 address and a
// permissive router, strangers could use it, their queries would land in the
// household's statistics, and they could probe the response cache for the
// names the household looked up (b/080). There is no setting to widen this.

// lanRanges are the source ranges that are local by definition: loopback,
// private IPv4 (RFC 1918), link-local, and IPv6 unique-local addresses.
var lanRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// lanRefreshInterval limits how often a query from an unknown source makes
// s-hole read the interface addresses again. The prefixes change when the
// ISP renumbers the IPv6 prefix or DHCP moves the host.
const lanRefreshInterval = 30 * time.Second

// readFailWarnInterval limits the WARN for a failed interface read to one an
// hour: a sandbox that blocks the read makes every refresh fail.
const readFailWarnInterval = time.Hour

// lanACL decides whether a source address is on the LAN: inside lanRanges,
// or inside a subnet of one of the host's own interfaces. The interface
// subnets cover a LAN that uses public IPv6 addresses, the usual case. A
// global IPv6 address with a prefix longer than /64 (a DHCPv6 /128, for
// example) counts as its /64, the size of an IPv6 LAN. An IPv4 interface
// subnet counts only inside lanRanges: a public or shared (CGNAT,
// 100.64.0.0/10) IPv4 subnet usually faces the internet provider or a VPN,
// and its other hosts are not the household's devices.
type lanACL struct {
	onLink    atomic.Pointer[[]netip.Prefix]
	mu        sync.Mutex // serialises refreshes
	refreshed time.Time  // guarded by mu
	// readFailWarned is when the last interface read failure was logged.
	// Guarded by mu.
	readFailWarned time.Time
	// notAdmitted holds the IPv4 interface subnets of the last good read
	// that are outside lanRanges, so each one is logged once, when it
	// appears. Guarded by mu.
	notAdmitted map[netip.Prefix]bool
	addrs       func() ([]net.Addr, error)
}

func newLANACL() *lanACL {
	a := &lanACL{addrs: net.InterfaceAddrs}
	a.refresh(time.Now())
	return a
}

func (a *lanACL) refresh(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.refreshed.IsZero() && now.Sub(a.refreshed) < lanRefreshInterval {
		return
	}
	a.refreshed = now
	addrs, err := a.addrs()
	if err != nil {
		// Keep the last good list. Without one, only lanRanges are answered.
		if a.readFailWarned.IsZero() || now.Sub(a.readFailWarned) >= readFailWarnInterval {
			a.readFailWarned = now
			logger.Warn("interface address read failed", "err", err,
				"hint", "s-hole cannot see the subnets of this host's interfaces. Until a read works, it refuses devices that use a public IPv6 address, and reverse lookups for the LAN's own IPv6 prefix go upstream. Under systemd, the unit must allow AF_NETLINK in RestrictAddressFamilies")
		}
		return
	}
	var out []netip.Prefix
	refused := map[netip.Prefix]bool{}
	for _, ad := range addrs {
		n, ok := ad.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		bits, _ := n.Mask.Size()
		if ip.Is4() && bits > 32 {
			bits -= 96
		}
		if ip.Is6() && ip.IsGlobalUnicast() && bits > 64 {
			bits = 64
		}
		p, err := ip.Prefix(bits)
		if err != nil {
			continue
		}
		if p.Addr().Is4() && !inLANRanges(p) {
			refused[p] = true
			continue
		}
		out = append(out, p)
	}
	for p := range refused {
		if !a.notAdmitted[p] {
			logger.Warn("an interface subnet is not treated as LAN", "subnet", p.String(),
				"hint", "s-hole refuses queries from this subnet. A public or shared (CGNAT, 100.64.0.0/10) IPv4 subnet usually faces the internet provider or a VPN. s-hole answers IPv4 devices only from 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and link-local addresses")
		}
	}
	a.notAdmitted = refused
	a.onLink.Store(&out)
}

// inLANRanges reports whether the whole of p is inside one of lanRanges.
func inLANRanges(p netip.Prefix) bool {
	for _, r := range lanRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func (a *lanACL) contains(ip netip.Addr) bool {
	for _, p := range lanRanges {
		if p.Contains(ip) {
			return true
		}
	}
	if p := a.onLink.Load(); p != nil {
		for _, pr := range *p {
			if pr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// ownGlobalV6 reports whether p is inside a global IPv6 subnet of one of the
// host's interfaces: a reverse-lookup name under the LAN's own public IPv6
// prefix. On a miss it reads the interface addresses again, like allows.
func (a *lanACL) ownGlobalV6(p netip.Prefix) bool {
	if a.underGlobalV6(p) {
		return true
	}
	a.refresh(time.Now())
	return a.underGlobalV6(p)
}

func (a *lanACL) underGlobalV6(p netip.Prefix) bool {
	links := a.onLink.Load()
	if links == nil {
		return false
	}
	for _, l := range *links {
		ip := l.Addr()
		if ip.Is6() && ip.IsGlobalUnicast() && !ip.IsPrivate() &&
			l.Bits() <= p.Bits() && l.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// allows reports whether a query from ip may be answered. On a miss it reads
// the interface addresses again (at most once per lanRefreshInterval), so a
// renumbered prefix is accepted without a restart.
func (a *lanACL) allows(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if a.contains(ip) {
		return true
	}
	a.refresh(time.Now())
	return a.contains(ip)
}

// refusedQueries counts queries refused because they came from outside the
// LAN. They are not counted in the query total and not logged.
var refusedQueries atomic.Uint64

// RefusedQueries returns the number of queries refused from outside the LAN
// since startup. /metrics shows it as shole_refused_total, and main repeats
// it in the security warnings.
func RefusedQueries() uint64 {
	return refusedQueries.Load()
}

// remoteIP returns the query's source address, or the zero Addr when the
// transport gives none.
func remoteIP(w dns.ResponseWriter) netip.Addr {
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		if a != nil {
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				return ip
			}
		}
	case *net.TCPAddr:
		if a != nil {
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				return ip
			}
		}
	case nil:
	default:
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			return ap.Addr()
		}
	}
	return netip.Addr{}
}

// refuse answers a query from outside the LAN with REFUSED. Nothing is
// logged and nothing reaches the stats or the query log.
func refuse(w dns.ResponseWriter, req *dns.Msg) {
	refusedQueries.Add(1)
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeRefused)
	_ = w.WriteMsg(resp)
}
