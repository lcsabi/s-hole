// Package blocklist owns the blocked-domain set: downloading lists from
// operator-configured URLs, parsing them (hosts-file and plain-domain
// formats), caching them on disk, and serving membership lookups to the
// DNS handler.
//
// Store is the in-memory hash set queried by every DNS request; loader
// handles the periodic refresh and disk cache. Both are safe for concurrent
// use.
package blocklist

import (
	"strings"
	"sync"
	"unicode/utf8"
)

// Store is a thread-safe in-memory set of blocked domains plus an in-memory
// whitelist that overrides it. A lookup walks the domain's label suffixes
// (see IsBlocked), so it costs O(labels) hash-set probes, effectively
// constant for real domain names.
type Store struct {
	mu        sync.RWMutex
	blocked   map[string]struct{}
	whitelist map[string]struct{}
}

// NewStore returns an empty Store. The block set is populated by the first
// call to Update; the whitelist by SetWhitelist or the runtime
// Add/RemoveFromWhitelist methods.
func NewStore() *Store {
	return &Store{
		blocked:   make(map[string]struct{}),
		whitelist: make(map[string]struct{}),
	}
}

// SetWhitelist replaces the entire whitelist with the given domains.
// Typically called once at startup from the YAML config.
func (s *Store) SetWhitelist(domains []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.whitelist = make(map[string]struct{}, len(domains))
	for _, d := range domains {
		s.whitelist[normalize(d)] = struct{}{}
	}
}

// Replace atomically swaps the blocked set. Concurrent IsBlocked calls
// see either the old set or the new set, never a partial update.
// TestStore_ReplaceIsAtomic guards this.
func (s *Store) Replace(domains []string) {
	next := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		next[normalize(d)] = struct{}{}
	}
	s.mu.Lock()
	s.blocked = next
	s.mu.Unlock()
}

// IsBlocked reports whether domain (or any of its parent domains) is on
// the block set, with the whitelist overriding at every level. The lookup
// walks the label suffixes of domain from most specific to least
// (a.b.example.com → b.example.com → example.com → com), so a list entry of
// "ads.example.com" now also blocks "x.ads.example.com": blocking a domain
// blocks the whole subtree beneath it. This closes the subdomain-rotation
// gap that exact-match blocking left open (ROADMAP #3).
//
// Whitelist precedence is global rather than per-level: if the queried
// domain OR any of its parents is whitelisted, the domain is reported as not
// blocked, even when a more specific parent sits on the block set. The
// whitelist is therefore the escape hatch for an over-broad block entry.
// Whitelisting "safe.doubleclick.net" lets that name (and its subtree)
// through while "ads.doubleclick.net" stays blocked; whitelisting
// "example.com" exempts everything under it.
//
// Cost is O(labels) lookups against two O(1) hash sets, with no new data
// structure and no per-query allocation (the walk reslices domain in place).
// BenchmarkStore_IsBlocked guards the speed; TestStore_IsBlocked_ZeroAlloc
// guards the zero-allocation property.
func (s *Store) IsBlocked(domain string) bool {
	name := normalize(domain)
	s.mu.RLock()
	defer s.mu.RUnlock()
	blocked := false
	for {
		if _, ok := s.whitelist[name]; ok {
			// Whitelist wins at any level; stop as soon as one matches.
			return false
		}
		if !blocked {
			if _, ok := s.blocked[name]; ok {
				// Keep walking: a broader parent could still be whitelisted.
				blocked = true
			}
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return blocked
		}
		name = name[i+1:]
	}
}

// AddToWhitelist adds domain to the runtime whitelist. Effective
// immediately; not persisted across restarts.
func (s *Store) AddToWhitelist(domain string) {
	d := normalize(domain)
	s.mu.Lock()
	s.whitelist[d] = struct{}{}
	s.mu.Unlock()
}

// RemoveFromWhitelist removes domain from the runtime whitelist. A no-op
// if the domain is not currently whitelisted.
func (s *Store) RemoveFromWhitelist(domain string) {
	d := normalize(domain)
	s.mu.Lock()
	delete(s.whitelist, d)
	s.mu.Unlock()
}

// GetWhitelist returns a snapshot of all whitelisted domains in
// unspecified order. Suitable for serialisation to the REST API.
func (s *Store) GetWhitelist() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.whitelist))
	for d := range s.whitelist {
		out = append(out, d)
	}
	return out
}

// Len returns the number of domains currently in the block set.
// The whitelist is not counted.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.blocked)
}

// WhitelistLen returns the number of domains in the runtime whitelist.
// Cheap counterpart to GetWhitelist for the /metrics scrape path; see
// R34. Lock-held read; runs in O(1).
func (s *Store) WhitelistLen() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.whitelist)
}

// normalize strips the trailing dot that DNS uses and lowercases.
func normalize(d string) string {
	if len(d) > 0 && d[len(d)-1] == '.' {
		d = d[:len(d)-1]
	}
	hasUpper := false
	for i := 0; i < len(d); i++ {
		c := d[i]
		if c >= utf8.RuneSelf {
			return strings.ToLower(d)
		}
		if 'A' <= c && c <= 'Z' {
			hasUpper = true
		}
	}
	if !hasUpper {
		return d
	}
	b := make([]byte, len(d))
	for i := 0; i < len(d); i++ {
		c := d[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
