package dnsserver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// perUpstreamTimeout caps how long one Exchange may take before we move to
// the next configured resolver. Combined with the ambient ctx deadline,
// this is the upper bound on total forward latency for a single query.
const perUpstreamTimeout = 3 * time.Second

// upstreamCooldown is how long a failed upstream is skipped before being
// retried. Short enough that recovery is quick on the next sweep, long
// enough that one bad resolver does not add latency to every query
// during an outage window.
const upstreamCooldown = 30 * time.Second

// upstreamTracker remembers when each configured upstream last failed.
// Forward consults it: an upstream whose last failure is within
// upstreamCooldown is skipped on the first sweep. If every upstream is in
// cooldown, the tracker is bypassed and every upstream is tried once —
// failing to do that would make all queries fail just because the
// preferred upstream is briefly down.
type upstreamTracker struct {
	mu      sync.Mutex
	lastErr map[string]time.Time
}

func newUpstreamTracker() *upstreamTracker {
	return &upstreamTracker{lastErr: make(map[string]time.Time)}
}

func (t *upstreamTracker) shouldSkip(addr string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	last, ok := t.lastErr[addr]
	if !ok {
		return false
	}
	return now.Sub(last) < upstreamCooldown
}

func (t *upstreamTracker) recordFailure(addr string, now time.Time) {
	t.mu.Lock()
	t.lastErr[addr] = now
	t.mu.Unlock()
}

func (t *upstreamTracker) recordSuccess(addr string) {
	t.mu.Lock()
	delete(t.lastErr, addr)
	t.mu.Unlock()
}

// forwardTracker is the package-level tracker shared by every call to
// forward(). Stateful but per-process; tests construct their own via
// forwardWith.
var forwardTracker = newUpstreamTracker()

// forward tries each upstream in order and returns the first successful
// reply. Upstreams that failed within upstreamCooldown are skipped on the
// first sweep; if all are skipped, every upstream is tried as a fallback.
// ctx is honored both as an overall deadline and as a cancellation
// signal; if it is canceled mid-attempt, no further upstreams are tried.
// On total failure the caller surfaces SERVFAIL via dns.HandleFailed.
func forward(ctx context.Context, req *dns.Msg, upstreams []string) (*dns.Msg, error) {
	return forwardWith(ctx, req, upstreams, forwardTracker)
}

func forwardWith(ctx context.Context, req *dns.Msg, upstreams []string, tracker *upstreamTracker) (*dns.Msg, error) {
	client := &dns.Client{Timeout: perUpstreamTimeout}
	now := time.Now()

	// First sweep: skip upstreams in cooldown.
	for _, upstream := range upstreams {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if tracker.shouldSkip(upstream, now) {
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, perUpstreamTimeout)
		resp, _, err := client.ExchangeContext(attemptCtx, req, upstream)
		cancel()
		if err == nil {
			tracker.recordSuccess(upstream)
			return resp, nil
		}
		tracker.recordFailure(upstream, time.Now())
	}

	// Second sweep: every non-cooldown upstream we tried in sweep 1 has
	// failed. Now retry the ones that were in cooldown *at function
	// entry* — those are upstreams that failed within the last 30 s on
	// some prior call, not the ones that just failed in sweep 1 above.
	//
	// We deliberately keep the entry-time `now` here rather than refreshing
	// to time.Now(): sweep 1 just recorded fresh failures, so a refreshed
	// `now` would mark those same upstreams as still in cooldown and we'd
	// retry them again. Using the entry `now` means shouldSkip returns
	// true only for upstreams that were *already* in cooldown when we
	// arrived, which is exactly the set we haven't tried yet.
	for _, upstream := range upstreams {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !tracker.shouldSkip(upstream, now) {
			continue // already tried in sweep 1
		}
		attemptCtx, cancel := context.WithTimeout(ctx, perUpstreamTimeout)
		resp, _, err := client.ExchangeContext(attemptCtx, req, upstream)
		cancel()
		if err == nil {
			tracker.recordSuccess(upstream)
			return resp, nil
		}
		tracker.recordFailure(upstream, time.Now())
	}

	return nil, fmt.Errorf("all upstreams failed for %s", req.Question[0].Name)
}
