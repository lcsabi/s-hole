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

// lanACL decides whether a source address is on the LAN: inside lanRanges,
// or inside a subnet of one of the host's own interfaces. The interface
// subnets cover a LAN that uses public addresses, which is the usual case
// for IPv6. A global IPv6 address with a prefix longer than /64 (a DHCPv6
// /128, for example) counts as its /64, the size of an IPv6 LAN.
type lanACL struct {
	onLink    atomic.Pointer[[]netip.Prefix]
	mu        sync.Mutex // serialises refreshes
	refreshed time.Time  // guarded by mu
	addrs     func() ([]net.Addr, error)
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
		return // keep the last good list
	}
	var out []netip.Prefix
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
		if p, err := ip.Prefix(bits); err == nil {
			out = append(out, p)
		}
	}
	a.onLink.Store(&out)
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
