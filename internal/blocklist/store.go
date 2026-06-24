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
)

// Store is a thread-safe in-memory set of blocked domains plus an in-memory
// whitelist that overrides it. Lookups are O(1).
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
// see either the old set or the new set — never a partial update.
func (s *Store) Replace(domains []string) {
	next := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		next[normalize(d)] = struct{}{}
	}
	s.mu.Lock()
	s.blocked = next
	s.mu.Unlock()
}

// IsBlocked reports whether domain is in the block set. The whitelist
// takes precedence: a domain that appears in both is reported as not
// blocked.
func (s *Store) IsBlocked(domain string) bool {
	domain = normalize(domain)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.whitelist[domain]; ok {
		return false
	}
	_, ok := s.blocked[domain]
	return ok
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
// Cheap counterpart to GetWhitelist for the /metrics scrape path — see
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
	return strings.ToLower(d)
}
