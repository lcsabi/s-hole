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
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// SourceStatus is the per-source health of one configured blocklist URL,
// captured at each refresh and exposed read-only via /api/stats and /metrics.
// Count is the number of domains the source contributed BEFORE the in-memory
// set deduplicates them, so the sum of Count across sources is greater than or
// equal to the aggregate blocklist size. The three states encode as:
//   - fresh:         Stale=false, LastRefresh=refresh time.
//   - stale cache:   Stale=true,  LastRefresh=cached snapshot's mtime.
//   - hard failure:  Stale=true,  LastRefresh=zero (never loaded, no cache).
type SourceStatus struct {
	URL         string    `json:"url"`
	Count       int       `json:"count"`
	LastRefresh time.Time `json:"last_refresh"`
	Stale       bool      `json:"stale"`
}

// Store is a thread-safe in-memory set of blocked domains plus an in-memory
// whitelist that overrides it. A lookup walks the domain's label suffixes
// (see IsBlocked), so it costs O(labels) hash-set probes, effectively
// constant for real domain names.
type Store struct {
	mu        sync.RWMutex
	blocked   map[string]struct{}
	whitelist map[string]struct{}

	// sources holds the last refresh's per-source health. It is kept in an
	// atomic pointer rather than under mu so the /api/stats poll never
	// contends the RWMutex that every IsBlocked call takes. Update swaps it;
	// Sources reads it.
	sources atomic.Pointer[[]SourceStatus]
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

// setSources swaps in the per-source health from the latest refresh. Called
// by Update, which runs single-flight, so there is one writer at a time.
func (s *Store) setSources(sources []SourceStatus) {
	s.sources.Store(&sources)
}

// Sources returns the per-source health captured at the last refresh, or an
// empty slice before the first Update. The returned slice is not copied;
// callers must not mutate it (Update replaces the pointer, never the backing
// array, so a reader holding an old slice keeps a consistent snapshot).
func (s *Store) Sources() []SourceStatus {
	if p := s.sources.Load(); p != nil {
		return *p
	}
	return nil
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

// LevelResult is one label-suffix visited by Explain, with its block-set and
// whitelist membership at that level.
type LevelResult struct {
	Suffix      string `json:"suffix"`
	Blocked     bool   `json:"blocked"`
	Whitelisted bool   `json:"whitelisted"`
}

// Explanation is the outcome of the block decision for one domain, plus the
// full suffix walk that produced it. Decision is "blocked", "whitelisted", or
// "allowed". MatchedBlock is the most-specific suffix on the block set (empty
// if none); MatchedWhitelist is the most-specific whitelisted suffix (empty if
// none). A non-empty MatchedWhitelist always wins, so an entry can be both on
// the block set and allowed: the operator sees the matched block entry and the
// whitelist entry that overrides it.
type Explanation struct {
	Domain           string        `json:"domain"`
	Decision         string        `json:"decision"`
	MatchedBlock     string        `json:"matched_block,omitempty"`
	MatchedWhitelist string        `json:"matched_whitelist,omitempty"`
	Walk             []LevelResult `json:"walk"`
}

// Explain runs domain through the same block decision as IsBlocked and returns
// the full walk and the reason. It is a diagnostic for the /api/check endpoint,
// not a hot-path call, so unlike IsBlocked it allocates freely (the walk slice
// and the strings) and does not need to stay zero-alloc. Decision semantics
// mirror IsBlocked: a whitelist match at any level wins over a block match at
// any level.
func (s *Store) Explain(domain string) Explanation {
	name := normalize(domain)
	exp := Explanation{Domain: name}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for cur := name; ; {
		_, blk := s.blocked[cur]
		_, wl := s.whitelist[cur]
		exp.Walk = append(exp.Walk, LevelResult{Suffix: cur, Blocked: blk, Whitelisted: wl})
		if blk && exp.MatchedBlock == "" {
			exp.MatchedBlock = cur
		}
		if wl && exp.MatchedWhitelist == "" {
			exp.MatchedWhitelist = cur
		}
		i := strings.IndexByte(cur, '.')
		if i < 0 {
			break
		}
		cur = cur[i+1:]
	}
	switch {
	case exp.MatchedWhitelist != "":
		exp.Decision = "whitelisted"
	case exp.MatchedBlock != "":
		exp.Decision = "blocked"
	default:
		exp.Decision = "allowed"
	}
	return exp
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
