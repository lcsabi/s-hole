package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/lcsabi/s-hole/internal/config"
	"github.com/lcsabi/s-hole/internal/querylog"
)

// staleCheckInterval is how often the stored history is checked for rows
// written under a less private setting. It matches the hourly retention
// prune, so the warning goes away within an hour after retention removes
// the last of those rows.
const staleCheckInterval = time.Hour

// privacyReport holds the privacy and security warnings in effect: the
// settings that are less private than their defaults (config.Warnings), and
// the conditions s-hole finds while it runs. Every warning is logged at
// startup and repeated with each stats line, and none can be turned off; the
// operator can only remove the cause.
type privacyReport struct {
	settings []config.Warning
	// plaintext returns the plaintext fallback count since startup
	// (dnsserver.PlaintextFallbacks); lastPlaintext is the count at the last
	// stats line.
	plaintext     func() uint64
	lastPlaintext uint64
	// refused returns the count of queries refused from outside the LAN
	// since startup; lastRefused is the count at the last stats line. nil
	// leaves it out.
	refused     func() uint64
	lastRefused uint64

	mu    sync.Mutex
	stale querylog.StaleReport // guarded by mu
}

// logSettings logs one WARN line for each setting that is less private than
// its default. Startup and -check-config call it.
func logSettings(log *slog.Logger, warnings []config.Warning) {
	for _, w := range warnings {
		log.Warn("privacy warning", "key", w.Key, "detail", w.Detail, "hint", w.Hint)
	}
}

// staleWarning describes stored rows that hold more than the current
// settings would write.
func staleWarning(r querylog.StaleReport) string {
	rows := fmt.Sprintf("%d rows", r.Rows)
	if r.Rows == 1 {
		rows = "1 row"
	}
	expiry := "retention does not remove them, because query_log.retention_days is 0"
	if !r.Expires.IsZero() {
		expiry = "retention removes the last of them by " + r.Expires.Format("2006-01-02")
	}
	return fmt.Sprintf("the query database holds %s written under a less private setting; %s. Run s-hole -purge to delete all history now", rows, expiry)
}

// checkStale runs the stored-history check and logs a WARN when it finds
// rows that hold more than the current settings would write. It only reads.
func (p *privacyReport) checkStale(ctx context.Context, log *slog.Logger, db *querylog.DBLogger, clients string, announce bool) {
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	rep, err := db.StaleRows(cctx, clients)
	if err != nil {
		log.Warn("query history check failed", "err", err)
		return
	}
	p.mu.Lock()
	p.stale = rep
	p.mu.Unlock()
	if announce && rep.Rows > 0 {
		log.Warn("privacy warning", "key", "query_log.database", "detail", staleWarning(rep),
			"hint", "the setting applies to new rows only; s-hole never rewrites stored rows on its own")
	}
}

// runStaleChecks repeats the stored-history check hourly until ctx ends.
func (p *privacyReport) runStaleChecks(ctx context.Context, log *slog.Logger, db *querylog.DBLogger, clients string) {
	t := time.NewTicker(staleCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.checkStale(ctx, log, db, clients, false)
		}
	}
}

// current returns the warnings in effect for the dashboard: the settings,
// stale stored rows, and the plaintext fallbacks and refused queries since
// startup (the log line counts those since the last stats line instead).
func (p *privacyReport) current() []string {
	var items []string
	for _, w := range p.settings {
		items = append(items, w.Key+": "+w.Detail)
	}
	p.mu.Lock()
	stale := p.stale
	p.mu.Unlock()
	if stale.Rows > 0 {
		items = append(items, "query_log.database: "+staleWarning(stale))
	}
	if p.plaintext != nil {
		if n := p.plaintext(); n > 0 {
			items = append(items, fmt.Sprintf("dns.upstreams: %d queries were sent unencrypted since startup, because every DoH upstream had failed", n))
		}
	}
	if p.refused != nil {
		if n := p.refused(); n > 0 {
			items = append(items, fmt.Sprintf("dns.listen: %d queries from outside the LAN were refused since startup", n))
		}
	}
	return items
}

// logPeriodic logs all warnings in effect as one combined WARN line. The
// stats ticker calls it after the stats line, so an operator who reads the
// log at any time sees what is less private than the defaults.
func (p *privacyReport) logPeriodic(log *slog.Logger) {
	var items []string
	for _, w := range p.settings {
		items = append(items, w.Key+": "+w.Detail)
	}
	p.mu.Lock()
	stale := p.stale
	p.mu.Unlock()
	if stale.Rows > 0 {
		items = append(items, "query_log.database: "+staleWarning(stale))
	}
	if p.plaintext != nil {
		now := p.plaintext()
		if n := now - p.lastPlaintext; n > 0 {
			items = append(items, fmt.Sprintf("dns.upstreams: %d queries were sent unencrypted since the last stats line, because every DoH upstream had failed", n))
		}
		p.lastPlaintext = now
	}
	if p.refused != nil {
		now := p.refused()
		if n := now - p.lastRefused; n > 0 {
			items = append(items, fmt.Sprintf("dns.listen: %d queries from outside the LAN were refused since the last stats line", n))
		}
		p.lastRefused = now
	}
	if len(items) == 0 {
		return
	}
	log.Warn("privacy and security warnings in effect", "count", len(items), "warnings", strings.Join(items, " | "))
}
