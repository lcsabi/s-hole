package blocklist

import (
	"strings"
	"sync"
)

// Store is a thread-safe in-memory set of blocked domains.
type Store struct {
	mu        sync.RWMutex
	blocked   map[string]struct{}
	whitelist map[string]struct{}
}

func NewStore() *Store {
	return &Store{
		blocked:   make(map[string]struct{}),
		whitelist: make(map[string]struct{}),
	}
}

func (s *Store) SetWhitelist(domains []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.whitelist = make(map[string]struct{}, len(domains))
	for _, d := range domains {
		s.whitelist[normalize(d)] = struct{}{}
	}
}

// Replace atomically swaps the blocked set.
func (s *Store) Replace(domains []string) {
	next := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		next[normalize(d)] = struct{}{}
	}
	s.mu.Lock()
	s.blocked = next
	s.mu.Unlock()
}

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

func (s *Store) AddToWhitelist(domain string) {
	d := normalize(domain)
	s.mu.Lock()
	s.whitelist[d] = struct{}{}
	s.mu.Unlock()
}

func (s *Store) RemoveFromWhitelist(domain string) {
	d := normalize(domain)
	s.mu.Lock()
	delete(s.whitelist, d)
	s.mu.Unlock()
}

func (s *Store) GetWhitelist() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.whitelist))
	for d := range s.whitelist {
		out = append(out, d)
	}
	return out
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.blocked)
}

// normalize strips the trailing dot that DNS uses and lowercases.
func normalize(d string) string {
	if len(d) > 0 && d[len(d)-1] == '.' {
		d = d[:len(d)-1]
	}
	return strings.ToLower(d)
}
