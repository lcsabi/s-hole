package api

import (
	"net"
	"sort"
)

// clientLabeler resolves a stored client value to a display label from the
// config client_names map. It is read-only attribution, built once when the
// map is injected, and it keys off the value that reached the store (already
// masked by query_privacy), never a raw IP. So a label can never reveal more
// than the active privacy mode already exposes: under "subnet" the stored
// value is a network address, so only a CIDR or network-address key resolves;
// under "drop" the value is empty, so nothing resolves.
//
// This is the first net.ParseCIDR / IPNet.Contains use in the repo. An empty
// or nil map yields a labeler that returns "" for everything (feature off).
type clientLabeler struct {
	exact map[string]string // exact IP or network-address key -> label
	cidrs []cidrLabel       // CIDR keys, most specific first
}

type cidrLabel struct {
	net   *net.IPNet
	label string
}

// newClientLabeler builds a labeler from the config map. Keys are already
// validated as an IP or CIDR by config.filterClientNames, so a key that fails
// to parse here is skipped defensively rather than trusted. CIDRs are sorted
// by prefix length descending so the most specific match wins.
func newClientLabeler(m map[string]string) *clientLabeler {
	l := &clientLabeler{exact: make(map[string]string, len(m))}
	for key, label := range m {
		if net.ParseIP(key) != nil {
			l.exact[key] = label
			continue
		}
		if _, ipNet, err := net.ParseCIDR(key); err == nil {
			l.cidrs = append(l.cidrs, cidrLabel{net: ipNet, label: label})
		}
	}
	sort.SliceStable(l.cidrs, func(i, j int) bool {
		iOnes, _ := l.cidrs[i].net.Mask.Size()
		jOnes, _ := l.cidrs[j].net.Mask.Size()
		return iOnes > jOnes
	})
	return l
}

// label returns the display label for a stored client value, or "" if none.
// An empty value (query_privacy "drop") and an unparseable value both yield
// "". An exact key wins over any CIDR; among CIDRs the most specific wins.
func (l *clientLabeler) label(stored string) string {
	if l == nil || stored == "" {
		return ""
	}
	if lbl, ok := l.exact[stored]; ok {
		return lbl
	}
	ip := net.ParseIP(stored)
	if ip == nil {
		return ""
	}
	for _, c := range l.cidrs {
		if c.net.Contains(ip) {
			return c.label
		}
	}
	return ""
}
