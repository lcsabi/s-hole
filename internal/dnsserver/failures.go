package dnsserver

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// failureReportInterval is how often the unresolved-query summary is logged.
// One summary line per interval replaces the old per-query WARN, which put
// every failed name in the system log, and, during an outage, one line per
// query (b/078).
const failureReportInterval = time.Minute

// failureLog collects unresolved queries between two summary lines: how many
// there were, the last error from each upstream, and whether any error looks
// like a wrong system clock. It keeps a query name only when the query log
// records every query (query_log.mode "all"), so the summary never holds
// more than the query log.
type failureLog struct {
	mu         sync.Mutex
	count      int
	causes     map[string]string // upstream -> last error text
	clock      bool
	lastDomain string
}

func newFailureLog() *failureLog {
	return &failureLog{causes: make(map[string]string)}
}

// record adds one unresolved query. domain is "" unless the query log
// records every query.
func (f *failureLog) record(err error, domain string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
	if domain != "" {
		f.lastDomain = domain
	}
	var fe *ForwardError
	if errors.As(err, &fe) {
		for _, c := range fe.Causes {
			f.causes[c.Upstream] = c.Err.Error()
			if clockSuspect(c.Err) {
				f.clock = true
			}
		}
		return
	}
	f.causes["query"] = err.Error()
}

// flush logs the summary for the interval, if there was a failure, and
// starts a new interval.
func (f *failureLog) flush() {
	f.mu.Lock()
	count, causes, clock, domain := f.count, f.causes, f.clock, f.lastDomain
	f.count, f.causes, f.clock, f.lastDomain = 0, make(map[string]string), false, ""
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
	attrs := []any{"queries", count, "interval", failureReportInterval.String(), "causes", strings.Join(parts, "; ")}
	if domain != "" {
		attrs = append(attrs, "last_domain", domain)
	}
	hint := "every upstream failed for these queries. Check the network path to the upstreams"
	if clock {
		hint = "an upstream's TLS certificate looks expired or not yet valid, which usually means the system clock is wrong. Check the clock and NTP (timedatectl), then the network path to the upstreams"
	}
	attrs = append(attrs, "hint", hint)
	logger.Warn("queries could not be resolved", attrs...)
}

// RunFailureReport logs the unresolved-query summary once per interval until
// ctx is cancelled. main runs it in a goroutine next to the stats ticker.
func (h *Handler) RunFailureReport(ctx context.Context) {
	t := time.NewTicker(failureReportInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			h.failures.flush()
			return
		case <-t.C:
			h.failures.flush()
		}
	}
}

// writeErr is the part of a reply-write error that is safe to log. A write
// to a client returns a *net.OpError whose text includes the client's
// address, which must not reach the system log (b/078), so only the
// operation and the underlying error are kept.
func writeErr(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Op + ": " + op.Err.Error()
	}
	return err.Error()
}
