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
// shell tools (grep, tail): "<RFC3339> <ALLOW|BLOCK> <client> <domain>".
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
func (l *FileLogger) Log(clientIP, domain string, blocked bool) {
	if l.logQueries == "none" {
		return
	}
	if l.logQueries == "blocked" && !blocked {
		return
	}
	action := "ALLOW"
	if blocked {
		action = "BLOCK"
	}
	fmt.Fprintf(l.f, "%s %s %s %s\n", time.Now().Format(time.RFC3339), action, clientIP, domain)
}

// Close flushes and closes the underlying file. A no-op when the logger
// is writing to stdout (since stdout outlives the process).
func (l *FileLogger) Close() error {
	if l.f != os.Stdout {
		return l.f.Close()
	}
	return nil
}

// Logger is the interface that all query log backends must implement.
type Logger interface {
	Log(clientIP, domain string, blocked bool)
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

// Log calls Log on every wrapped logger. Sequential, not parallel — the
// underlying loggers are non-blocking so this is cheap.
func (m *Multi) Log(clientIP, domain string, blocked bool) {
	for _, l := range m.loggers {
		l.Log(clientIP, domain, blocked)
	}
}
