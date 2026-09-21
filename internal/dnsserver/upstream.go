package dnsserver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
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
// cooldown, the tracker is bypassed and every upstream is tried once;
// failing to do that would make all queries fail just because the
// preferred upstream is briefly down.
type upstreamTracker struct {
	mu      sync.Mutex
	lastErr map[string]time.Time
	// transportFailures is the cumulative per-upstream transport-failure count,
	// surfaced as shole_upstream_transport_failures_total{upstream=...}. Unlike
	// lastErr, a success does not reset it: it is a monotonic counter for
	// /metrics, not cooldown state. It counts only transport failures
	// (recordFailure), never a relayed upstream failure rcode, which arrives as
	// a successful exchange.
	transportFailures map[string]uint64
}

func newUpstreamTracker() *upstreamTracker {
	return &upstreamTracker{
		lastErr:           make(map[string]time.Time),
		transportFailures: make(map[string]uint64),
	}
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
	t.transportFailures[addr]++
	t.mu.Unlock()
}

func (t *upstreamTracker) recordSuccess(addr string) {
	t.mu.Lock()
	delete(t.lastErr, addr)
	t.mu.Unlock()
}

// TransportFailureCounts returns a copy of the cumulative per-upstream
// transport-failure counts. The copy is safe to read after the call returns;
// the map is small (one entry per configured upstream).
func (t *upstreamTracker) TransportFailureCounts() map[string]uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]uint64, len(t.transportFailures))
	for addr, n := range t.transportFailures {
		out[addr] = n
	}
	return out
}

// forwardTracker is the package-level tracker shared by every call to
// forward(). Stateful but per-process; tests construct their own via
// forwardWith.
var forwardTracker = newUpstreamTracker()

// UpstreamTransportFailures returns the cumulative per-upstream
// transport-failure counts from the shared forward tracker, keyed by upstream
// address. cmd/s-hole wires it into the API so /metrics can emit
// shole_upstream_transport_failures_total per upstream, the "which upstream is
// flaky" signal the query log cannot give (forward aggregates several upstreams
// into one generic error).
func UpstreamTransportFailures() map[string]uint64 {
	return forwardTracker.TransportFailureCounts()
}

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
	now := time.Now()

	// tried records the upstreams actually contacted in the first sweep, so the
	// second sweep retries only the ones the first sweep skipped for cooldown.
	// Deriving that set from timestamps does not work: the first sweep stamps
	// each fresh failure with a time after `now`, so a shouldSkip(now) check
	// would read those just-failed upstreams as still in cooldown and contact
	// them a second time (b/045). The set keeps each upstream to one contact
	// per query.
	tried := make(map[string]bool, len(upstreams))

	// First sweep: skip upstreams in cooldown, try the rest.
	for _, upstream := range upstreams {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if tracker.shouldSkip(upstream, now) {
			continue
		}
		tried[upstream] = true
		resp, err := exchange(ctx, req, upstream)
		if err == nil {
			tracker.recordSuccess(upstream)
			return resp, nil
		}
		tracker.recordFailure(upstream, time.Now())
	}

	// Second sweep: every upstream tried in sweep 1 has failed. Retry the ones
	// sweep 1 skipped (the cooldown set at entry), so a transient outage of the
	// preferred upstream does not turn into a hard failure. Skipping the tried
	// set means no upstream is contacted twice.
	for _, upstream := range upstreams {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if tried[upstream] {
			continue // already contacted in sweep 1
		}
		resp, err := exchange(ctx, req, upstream)
		if err == nil {
			tracker.recordSuccess(upstream)
			return resp, nil
		}
		tracker.recordFailure(upstream, time.Now())
	}

	return nil, fmt.Errorf("all upstreams failed for %s", req.Question[0].Name)
}

// exchange dispatches an "https://" upstream to exchangeDoH (DNS-over-HTTPS).
// Otherwise it performs one UDP exchange with upstream, retrying once over
// TCP when the reply comes back truncated (TC bit set). Without the
// retry, the truncated answer would be relayed verbatim, and because
// queries arriving over TCP are also forwarded over UDP, the client's
// own TCP fallback would loop straight back into the same truncated
// reply, dead-ending the fallback chain documented in DESIGN.md (T2).
//
// If the TCP retry fails (e.g. 53/tcp filtered on the upstream path),
// the truncated UDP reply is returned instead: the upstream is
// demonstrably alive, and a TC-flagged partial answer is more useful to
// the client than a SERVFAIL.
// udpClient and tcpClient are reused across queries. dns.Client is a
// concurrency-safe config object with no per-call state, so one of each
// suffices instead of allocating a fresh pair per cache-miss query (matching
// forwardTracker's package-level lifetime above).
var (
	udpClient = &dns.Client{Timeout: perUpstreamTimeout}
	tcpClient = &dns.Client{Net: "tcp", Timeout: perUpstreamTimeout}
)

// dohClient carries DNS-over-HTTPS upstream queries (RFC 8484). It is reused
// across queries like udpClient/tcpClient, so its connection pool keeps a DoH
// upstream's TLS connection alive: only the first query after startup or a long
// idle gap pays the handshake, the rest reuse the warm connection. The
// per-attempt deadline rides on the request context (like the UDP/TCP path), so
// no Client.Timeout is set. Tests swap this var to trust an httptest TLS server.
var dohClient = &http.Client{
	Transport: &http.Transport{
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: perUpstreamTimeout,
	},
}

// maxDoHResponse caps a DoH response body read. dns.MaxMsgSize (65535) is the
// DNS-over-TCP message ceiling, so no legitimate answer exceeds it; the cap
// stops a hostile or broken endpoint from streaming an unbounded body.
const maxDoHResponse = dns.MaxMsgSize

// dohMediaType is the RFC 8484 content type for a wire-format DNS message.
const dohMediaType = "application/dns-message"

func exchange(ctx context.Context, req *dns.Msg, upstream string) (*dns.Msg, error) {
	if strings.HasPrefix(upstream, "https://") {
		return exchangeDoH(ctx, req, upstream)
	}

	attemptCtx, cancel := context.WithTimeout(ctx, perUpstreamTimeout)
	resp, _, err := udpClient.ExchangeContext(attemptCtx, req, upstream)
	cancel()
	if err != nil || !resp.Truncated {
		return resp, err
	}

	attemptCtx, cancel = context.WithTimeout(ctx, perUpstreamTimeout)
	full, _, tcpErr := tcpClient.ExchangeContext(attemptCtx, req, upstream)
	cancel()
	if tcpErr != nil {
		return resp, nil
	}
	return full, nil
}

// exchangeDoH POSTs the wire-format query to a DoH endpoint and unpacks the
// wire-format reply (RFC 8484). It needs no TC/TCP retry: an HTTP body is never
// DNS-truncated. A non-200 status, a transport error, or an unparsable body all
// return an error, so forwardWith records a transport failure and fails over to
// the next upstream, exactly as a UDP failure does. The query ID is left as
// sent; a compliant server echoes it.
func exchangeDoH(ctx context.Context, req *dns.Msg, upstream string) (*dns.Msg, error) {
	packed, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DoH query: %w", err)
	}

	attemptCtx, cancel := context.WithTimeout(ctx, perUpstreamTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, upstream, bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("building DoH request: %w", err)
	}
	httpReq.Header.Set("Content-Type", dohMediaType)
	httpReq.Header.Set("Accept", dohMediaType)

	httpResp, err := dohClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DoH request to %s: %w", upstream, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request to %s: status %d", upstream, httpResp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxDoHResponse))
	if err != nil {
		return nil, fmt.Errorf("reading DoH response from %s: %w", upstream, err)
	}

	var out dns.Msg
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpacking DoH response from %s: %w", upstream, err)
	}
	return &out, nil
}
