// Package querylog provides asynchronous query log sinks: a plain-text
// file logger (one RFC3339 line per query) and a batched SQLite logger
// for historical queries surfaced through the REST API. Both implement
// the Logger interface; querylog.Multi fans out to any combination.
//
// Both backends respect the log_queries config setting ("all", "blocked",
// or "none") and never block the calling DNS goroutine: the SQLite logger
// buffers entries in a channel and drops on overflow rather than applying
// back-pressure to query handling. Drops are counted in DBLogger.dropped
// and exposed as shole_query_log_dropped_total via /metrics so operators
// see when flush_interval is too long for the query volume.
//
// The SQLite logger supports a TTL-based retention prune: when
// query_db_retention_days is set, a goroutine deletes rows older than
// the cutoff every pruneTickPeriod.
//
// Recent and TopBlocked accept a context.Context so HTTP handlers can
// propagate client cancellation into the underlying QueryContext call.
package querylog

import (
	"fmt"
	"log/slog"
	"os"
	"time"
)

var logger = slog.With("pkg", "querylog")

// FileLogger writes one line per query to a flat file, or to stdout when
// the configured path is empty. The format is fixed for easy parsing by
// shell tools (grep, tail): "<RFC3339> <ALLOW|BLOCK> <client> <domain>",
// with an optional trailing marker on ALLOW lines: " CACHED" on a cache hit
// or " FAILED" on a failed query (unresolved or a relayed upstream failure).
// The two markers are mutually exclusive, and a blocked query carries
// neither (it never reaches the cache and its rcode is not a failure).
type FileLogger struct {
	f          *os.File
	logQueries string
}

// NewFileLogger opens path for append (creating it if needed). If path is
// empty or the open fails, the logger falls back to os.Stdout so the
// caller does not need to special-case logging availability. logQueries
// filters which queries are recorded ("all", "blocked", or "none").
func NewFileLogger(path, logQueries string) *FileLogger {
	if path == "" {
		return &FileLogger{f: os.Stdout, logQueries: logQueries}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Warn("cannot open file log, falling back to stdout", "path", path, "err", err)
		return &FileLogger{f: os.Stdout, logQueries: logQueries}
	}
	return &FileLogger{f: f, logQueries: logQueries}
}

// Log writes a single line to the underlying file. Respects the
// logQueries filter; a no-op for queries that should not be logged.
// Write errors are deliberately ignored: query logging is best-effort
// and must never fail or slow the DNS path (the same contract as
// DBLogger's drop-on-full channel).
func (l *FileLogger) Log(rec Record) {
	if l.logQueries == "none" {
		return
	}
	if l.logQueries == "blocked" && !rec.Blocked {
		return
	}
	action := "ALLOW"
	if rec.Blocked {
		action = "BLOCK"
	}
	marker := ""
	if rec.CacheHit {
		marker = " CACHED"
	} else if rec.Failed() {
		marker = " FAILED"
	}
	fmt.Fprintf(l.f, "%s %s %s %s%s\n", time.Now().Format(time.RFC3339), action, rec.ClientIP, rec.Domain, marker)
}

// Close flushes and closes the underlying file. A no-op when the logger
// is writing to stdout (since stdout outlives the process).
func (l *FileLogger) Close() error {
	if l.f != os.Stdout {
		return l.f.Close()
	}
	return nil
}

// Record is one query log entry passed to Log. It is a struct rather than
// positional arguments so a new per-query field does not churn every Logger
// implementation's signature.
//
// Rcode and Synthesized together record the query outcome (CL 77). Rcode is
// the DNS rcode of the reply s-hole sent or relayed (0 = NOERROR).
// Synthesized is true when s-hole built the reply itself (a block, a local
// PTR answer, or a synthesized SERVFAIL) and false when it relayed an
// upstream or cached message. The Failed helpers derive the operator-facing
// outcome from the two: see Failed, Unresolved, and UpstreamError.
type Record struct {
	ClientIP    string
	Domain      string
	Blocked     bool
	CacheHit    bool // served from the response cache; ALLOW queries only
	Rcode       int  // DNS rcode of the reply s-hole sent or relayed; 0 = NOERROR
	Synthesized bool // s-hole built the reply itself, vs relayed from upstream/cache
}

// DNS failure rcodes, kept as local constants so querylog stays free of a
// miekg/dns import (it is a pure logging and storage package).
const (
	rcodeServerFailure = 2 // SERVFAIL
	rcodeRefused       = 5 // REFUSED
)

// Failed reports whether the query ended in a failure an operator cares
// about: an unresolved query or a relayed upstream failure. NXDOMAIN is a
// valid answer, not a failure, so it is not counted here.
func (r Record) Failed() bool {
	return r.Unresolved() || r.UpstreamError()
}

// Unresolved reports the query s-hole could not answer: it synthesized a
// SERVFAIL because every upstream failed at the transport level or the
// query deadline hit.
func (r Record) Unresolved() bool {
	return r.Synthesized && r.Rcode == rcodeServerFailure
}

// UpstreamError reports a failure rcode relayed verbatim from a live
// upstream (SERVFAIL or REFUSED). This is usually not s-hole's fault (a
// broken authoritative server, a DNSSEC failure, or a refusal).
func (r Record) UpstreamError() bool {
	return !r.Synthesized && (r.Rcode == rcodeServerFailure || r.Rcode == rcodeRefused)
}

// Logger is the interface that all query log backends must implement.
type Logger interface {
	Log(rec Record)
}

// Compile-time interface checks.
var _ Logger = (*FileLogger)(nil)
var _ Logger = (*DBLogger)(nil)
var _ Logger = (*Multi)(nil)

// Multi fans out a single Log call to all wrapped loggers in order.
// It is the composition primitive used by cmd/s-hole/main.go to combine the file
// and SQLite backends.
type Multi struct {
	loggers []Logger
}

// NewMulti returns a Multi that delegates Log to every supplied logger,
// in the order they were passed.
func NewMulti(loggers ...Logger) *Multi {
	return &Multi{loggers: loggers}
}

// Log calls Log on every wrapped logger. Sequential, not parallel; the
// underlying loggers are non-blocking so this is cheap.
func (m *Multi) Log(rec Record) {
	for _, l := range m.loggers {
		l.Log(rec)
	}
}
