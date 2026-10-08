package main

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// The host that runs s-hole must not use s-hole as its own DNS server. After
// the router hands out s-hole's address, DHCP gives that address to the s-hole
// host too, unless the host's resolver is set by hand. Then the host cannot
// resolve names while s-hole is down: s-hole cannot download its blocklists
// at startup, a package upgrade that restarts s-hole cannot finish, and a
// host without a battery-backed clock cannot reach its time server, which
// DoH needs to check certificates. README.md ("Keep the s-hole host off
// s-hole") shows how to set the host's resolver.

// Resolver addresses that are not s-hole even though they are loopback:
// systemd-resolved's stub listeners and Docker's embedded DNS server.
var notShole = map[netip.Addr]bool{
	netip.MustParseAddr("127.0.0.53"): true,
	netip.MustParseAddr("127.0.0.54"): true,
	netip.MustParseAddr("127.0.0.11"): true,
}

// resolvFiles are the files that list the host's resolvers. The second is
// systemd-resolved's list of the servers behind its stub.
var resolvFiles = []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"}

// nameservers reads the nameserver lines of the resolver files that exist.
func nameservers(files []string) []netip.Addr {
	var out []netip.Addr
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 && fields[0] == "nameserver" {
				if a, err := netip.ParseAddr(fields[1]); err == nil {
					out = append(out, a.WithZone(""))
				}
			}
		}
		_ = fh.Close()
	}
	return out
}

// searchDomains reads the search and domain lines of the resolver files that
// exist: the domains that the host, and usually every device on the LAN
// (they get the same DHCP search domain), append to a short name. It
// returns each domain once, lowercase, with no trailing dot.
func searchDomains(files []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 || (fields[0] != "search" && fields[0] != "domain") {
				continue
			}
			for _, d := range fields[1:] {
				d = strings.TrimSuffix(strings.ToLower(d), ".")
				if _, ok := dns.IsDomainName(d); !ok || d == "" || seen[d] {
					continue
				}
				seen[d] = true
				out = append(out, d)
			}
		}
		_ = fh.Close()
	}
	return out
}

// logSearchDomains logs an INFO line for each search domain whose names
// s-hole sends to every upstream. A device that uses the search domain asks
// for "laptop.<domain>", and when the domain is the router's domain for LAN
// devices, that name then reaches the public upstream. s-hole does not add
// the domain on its own: a search domain can be a public domain that the
// router cannot answer, and its names would then get NXDOMAIN.
func logSearchDomains(log *slog.Logger, domains []string, keepsLocal func(string) bool) {
	for _, d := range domains {
		if keepsLocal(d) {
			continue
		}
		log.Info("a search domain of this host is not a local domain", "domain", d,
			"hint", "s-hole sends names under this domain to every upstream. If the router uses this domain for the devices on the LAN, add it to dns.local_domains. Do not add a public domain")
	}
}

// hostUsesShole reports whether one of the host's resolvers is this s-hole:
// a loopback address (other than the systemd-resolved and Docker resolvers)
// or one of the host's own addresses, that s-hole listens on at port 53.
func hostUsesShole(servers []netip.Addr, own map[netip.Addr]bool, dnsListen string) (netip.Addr, bool) {
	host, port, err := net.SplitHostPort(dnsListen)
	if err != nil || port != "53" {
		return netip.Addr{}, false // a resolver always uses port 53
	}
	var bound netip.Addr
	wildcard := host == ""
	if !wildcard {
		a, err := netip.ParseAddr(host)
		if err != nil {
			return netip.Addr{}, false
		}
		bound = a.Unmap()
		wildcard = bound.IsUnspecified()
	}
	for _, s := range servers {
		s = s.Unmap()
		if notShole[s] {
			continue
		}
		local := s.IsLoopback() || own[s]
		if local && (wildcard || s == bound) {
			return s, true
		}
	}
	return netip.Addr{}, false
}

// ownAddrs returns the host's interface addresses.
func ownAddrs() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out[ip.Unmap()] = true
			}
		}
	}
	return out
}

// runResolverCheck warns when the host uses s-hole as its own resolver. It
// checks at startup and then hourly, because a DHCP renewal after the router
// change can switch the host to s-hole while s-hole runs. It logs again only
// when the state changes.
func runResolverCheck(ctx context.Context, log *slog.Logger, dnsListen string) {
	warned := false
	check := func() {
		server, uses := hostUsesShole(nameservers(resolvFiles), ownAddrs(), dnsListen)
		switch {
		case uses && !warned:
			log.Warn("this host uses s-hole as its own DNS server", "resolver", server.String(),
				"hint", "while s-hole is down, this host cannot resolve names: s-hole cannot download its blocklists, and the host may not reach its time server. Point this host's resolver at the router or at public resolvers; see \"Keep the s-hole host off s-hole\" in README.md")
		case !uses && warned:
			log.Info("this host no longer uses s-hole as its own DNS server")
		}
		warned = uses
	}
	check()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}
