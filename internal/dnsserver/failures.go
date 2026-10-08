package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lcsabi/s-hole/internal/redact"
)

// failureReportInterval is how often the unresolved-query and failed-reply
// summaries are logged. One summary line per interval replaces the old
// per-query WARN, which put every failed name in the system log, and, during
// an outage, one line per query (b/078).
const failureReportInterval = time.Minute

// failureLog collects unresolved queries between two summary lines: how many
// there were, the last error from each upstream, whether any error looks like
// a wrong system clock, and whether the forward limit was reached. It holds no
// query name and no client: the system journal keeps a log line where
// retention and purge cannot reach it, so the name stays in the query log
// only.
type failureLog struct {
	mu     sync.Mutex
	count  int
	causes map[string]string // upstream, "forward limit", or "query" -> last error text
	clock  bool
	// limited is set when a query got SERVFAIL because maxForwards queries
	// were already waiting for an upstream.
	limited bool
}

func newFailureLog() *failureLog {
	return &failureLog{causes: make(map[string]string)}
}

// record adds one unresolved query.
func (f *failureLog) record(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
	var fe *ForwardError
	if errors.As(err, &fe) {
		for _, c := range fe.Causes {
			f.causes[redact.URL(c.Upstream)] = c.Err.Error()
			if clockSuspect(c.Err) {
				f.clock = true
			}
		}
		return
	}
	if errors.Is(err, errForwardLimit) {
		f.limited = true
		f.causes["forward limit"] = err.Error()
		return
	}
	f.causes["query"] = err.Error()
}

// flush logs the summary for the interval, if there was a failure, and
// starts a new interval.
func (f *failureLog) flush() {
	f.mu.Lock()
	count, causes, clock, limited := f.count, f.causes, f.clock, f.limited
	f.count, f.causes, f.clock, f.limited = 0, make(map[string]string), false, false
	f.mu.Unlock()
	if count == 0 {
		return
	}
	ups := make([]string, 0, len(causes))
	for u := range causes {
		ups = append(ups, u)
	}
	sort.Strings(ups)
	parts := make([]string, len(ups))
	for i, u := range ups {
		parts[i] = u + ": " + causes[u]
	}
	hint := "every upstream failed for these queries. Check the network path to the upstreams"
	switch {
	case clock:
		hint = "an upstream's TLS certificate looks expired or not yet valid, which usually means the system clock is wrong. Check the clock and NTP (timedatectl), then the network path to the upstreams"
	case limited && len(causes) == 1:
		hint = fmt.Sprintf("s-hole already had %d queries waiting for an upstream, so it answered SERVFAIL at once. A slow upstream or a device that sends many queries can cause this. Check the network path to the upstreams", maxForwards)
	case limited:
		hint = fmt.Sprintf("some queries got SERVFAIL at once because s-hole already had %d queries waiting for an upstream, and every upstream failed for the others. Check the network path to the upstreams", maxForwards)
	}
	logger.Warn("queries could not be resolved", "queries", count, "interval", failureReportInterval.String(),
		"causes", strings.Join(parts, "; "), "hint", hint)
}

// maxReplyErrors caps the distinct error texts that one failed-reply summary
// keeps. A failed write has few causes (a closed connection, a timeout, a
// full buffer), so the cap only bounds memory.
const maxReplyErrors = 8

// replyLog collects the replies that s-hole could not send to a client
// between two summary lines: how many there were and the distinct errors.
// It holds no query name and no client, and an error keeps no address (see
// redact.NetError). One summary line replaces the old WARN for each failed
// write, which named the query under query_log.mode "all".
type replyLog struct {
	mu    sync.Mutex
	count int
	errs  map[string]struct{}
}

func newReplyLog() *replyLog {
	return &replyLog{errs: make(map[string]struct{})}
}

// record adds one failed reply write.
func (r *replyLog) record(err error) {
	text := redact.NetError(err)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	if len(r.errs) < maxReplyErrors {
		r.errs[text] = struct{}{}
	}
}

// flush logs the summary for the interval, if a write failed, and starts a
// new interval.
func (r *replyLog) flush() {
	r.mu.Lock()
	count, errs := r.count, r.errs
	r.count, r.errs = 0, make(map[string]struct{})
	r.mu.Unlock()
	if count == 0 {
		return
	}
	texts := make([]string, 0, len(errs))
	for e := range errs {
		texts = append(texts, e)
	}
	sort.Strings(texts)
	logger.Warn("replies could not be sent", "replies", count, "interval", failureReportInterval.String(),
		"errors", strings.Join(texts, "; "),
		"hint", "a client closed the connection or left the network before s-hole replied. Many failures can mean a network problem on the s-hole host")
}

// RunFailureReport logs the unresolved-query summary, the failed-reply
// summary, and the plaintext fallback count once per interval until ctx is
// cancelled. main runs it in a goroutine next to the stats ticker.
func (h *Handler) RunFailureReport(ctx context.Context) {
	t := time.NewTicker(failureReportInterval)
	defer t.Stop()
	last := PlaintextFallbacks()
	report := func() {
		h.failures.flush()
		h.replies.flush()
		now := PlaintextFallbacks()
		if n := now - last; n > 0 {
			logger.Warn("queries were sent unencrypted", "queries", n, "interval", failureReportInterval.String(),
				"hint", "every DoH upstream failed, so s-hole used a plain upstream and the queries left the network unencrypted. Check the network path to the DoH upstreams; for DoH only, remove the plain upstreams")
		}
		last = now
	}
	for {
		select {
		case <-ctx.Done():
			report()
			return
		case <-t.C:
			report()
		}
	}
}
