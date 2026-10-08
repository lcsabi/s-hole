// Package querylog provides asynchronous query log sinks: a plain-text
// file logger (one RFC3339 line per query) and a batched SQLite logger
// for historical queries surfaced through the REST API. Both implement
// the Logger interface; querylog.Multi fans out to any combination.
//
// Both backends respect the query_log.mode config setting ("all", "blocked",
// or "none") and never block the calling DNS goroutine: each buffers entries
// in a channel and drops on overflow rather than applying back-pressure to
// query handling. Drops are counted and exposed via /metrics
// (shole_query_log_dropped_total for the database,
// shole_query_log_file_dropped_total for the file or standard output) so
// operators see when an output cannot keep up with the query volume.
//
// The SQLite logger supports a TTL-based retention prune: when
// query_log.retention_days is set, a goroutine deletes rows older than
// the cutoff every pruneTickPeriod.
//
// Recent and TopBlocked accept a context.Context so HTTP handlers can
// propagate client cancellation into the underlying QueryContext call.
package querylog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lcsabi/s-hole/internal/logging"
)

var logger = logging.For("querylog")

// FileLogger writes one line per recorded query to a file or to standard
// output (query_log.file). The format is fixed for easy parsing by shell
// tools (grep, tail): "<RFC3339 UTC> <ALLOW|BLOCK> <client> <domain>", with an
// optional trailing marker on ALLOW lines: " CACHED" on a cache hit or
// " FAILED" on a failed query (unresolved or a relayed upstream failure).
// The two markers are mutually exclusive, and a blocked query carries
// neither (it never reaches the cache and its rcode is not a failure).
//
// Log never blocks the DNS goroutine. It hands the line to a writer goroutine
// through a buffered channel and drops the line when the channel is full,
// the same contract as DBLogger. A direct write blocked queries whenever the
// reader fell behind: under systemd the reader is journald, which also rate
// limits the stream (b/075).
type FileLogger struct {
	w          io.Writer
	closer     io.Closer // nil for standard output, which outlives the process
	path       string    // the file path; "" for standard output
	logQueries string
	ch         chan string
	done       chan struct{}
	wg         sync.WaitGroup
	dropped    atomic.Uint64
	purgeCh    chan chan error
}

// fileQueueSize is the line buffer between Log and the writer goroutine.
const fileQueueSize = 1024

// NewFileLogger starts a FileLogger. dest is "stdout" for standard output or
// a file path, which is opened for append and created with mode 0600 (an
// existing file is tightened to 0600). logQueries filters which queries are
// recorded ("all", "blocked", or "none"). An open failure is returned to the
// caller, which turns the output off: falling back to standard output would
// send the query history to the system journal, which s-hole cannot delete
// (b/079).
func NewFileLogger(dest, logQueries string) (*FileLogger, error) {
	l := &FileLogger{
		logQueries: logQueries,
		ch:         make(chan string, fileQueueSize),
		done:       make(chan struct{}),
		purgeCh:    make(chan chan error),
	}
	if dest == "stdout" {
		l.w = os.Stdout
	} else {
		f, err := OpenPrivateFile(dest)
		if err != nil {
			return nil, err
		}
		l.w, l.closer, l.path = f, f, dest
	}
	l.wg.Add(1)
	go l.run()
	return l, nil
}

// OpenPrivateFile opens path for append, creating it with mode 0600, and
// sets an existing file to 0600, so a query log written by an older build
// with mode 0644 stops being readable by other users (b/076).
func OpenPrivateFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		logger.Warn("query log file permissions could not be set to owner-only", "path", path, "err", err)
	}
	return f, nil
}

// Log queues one line. It respects the logQueries filter and drops the line,
// counting it, when the writer has fallen behind.
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
	line := fmt.Sprintf("%s %s %s %s%s\n", time.Now().UTC().Format(time.RFC3339), action, rec.ClientIP, rec.Domain, marker)
	select {
	case l.ch <- line:
	default:
		l.dropped.Add(1)
	}
}

// Dropped returns the number of lines Log dropped because the writer had
// fallen behind. /metrics shows it as shole_query_log_file_dropped_total.
func (l *FileLogger) Dropped() uint64 {
	return l.dropped.Load()
}

// run writes queued lines until Close. Write errors are ignored: query
// logging is best-effort and must never fail or slow the DNS path.
func (l *FileLogger) run() {
	defer l.wg.Done()
	for {
		select {
		case line := <-l.ch:
			_, _ = io.WriteString(l.w, line)
		case reply := <-l.purgeCh:
			reply <- l.truncate()
		case <-l.done:
			for {
				select {
				case line := <-l.ch:
					_, _ = io.WriteString(l.w, line)
				default:
					return
				}
			}
		}
	}
}

// ErrStdoutNotPurgeable is returned by Purge when the lines go to standard
// output: they are in the system journal or the container log, which s-hole
// cannot change.
var ErrStdoutNotPurgeable = errors.New("query lines go to standard output; s-hole cannot delete them from the system journal or the container log")

// ErrNotOverwritten is returned by Purge when it emptied the log file but
// could not overwrite it with zeros first.
var ErrNotOverwritten = errors.New("emptied, but not overwritten with zeros")

// Purge discards the queued lines, overwrites the log file with zeros (see
// ZeroFile), and empties it. It runs in the writer goroutine, so no queued
// line is written after it.
func (l *FileLogger) Purge(ctx context.Context) error {
	reply := make(chan error, 1)
	select {
	case l.purgeCh <- reply:
	case <-l.done:
		return errors.New("query log file is closed")
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *FileLogger) truncate() error {
	for {
		select {
		case <-l.ch:
			continue
		default:
		}
		break
	}
	f, ok := l.w.(*os.File)
	if !ok || l.closer == nil {
		return ErrStdoutNotPurgeable
	}
	// The file is open for append, which writes only at the end, so the
	// zeros go through a second handle on the same file. A failed overwrite
	// still empties the file, and Purge reports the failure.
	fi, zerr := f.Stat()
	if zerr == nil {
		zerr = zeroFile(l.path, fi)
	}
	if err := f.Truncate(0); err != nil {
		// On Windows a handle opened for append has no right to write
		// data, so Truncate fails (b/105). Empty the file through a second
		// handle, as for the zeros.
		if fi == nil || truncateFile(l.path, fi) != nil {
			return err
		}
	}
	if zerr != nil {
		return fmt.Errorf("%w: %w", ErrNotOverwritten, zerr)
	}
	return nil
}

// Close writes the queued lines, stops the writer, and closes the file. It
// does not close standard output. Call Close once; a second call panics.
func (l *FileLogger) Close() error {
	close(l.done)
	l.wg.Wait()
	if l.closer != nil {
		return l.closer.Close()
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

// isUnresolved and isUpstreamError classify a stored outcome (the reply rcode
// plus the synthesized flag) into the two failure kinds. Record and QueryRow
// both derive from them, so the failure rule lives in one place. The
// History/Search SQL and the dashboard cannot call Go, so they mirror the same
// rule (rcode 2 = SERVFAIL, 5 = REFUSED); keep the copies in step.
func isUnresolved(rcode int, synthesized bool) bool {
	return synthesized && rcode == rcodeServerFailure
}

func isUpstreamError(rcode int, synthesized bool) bool {
	return !synthesized && (rcode == rcodeServerFailure || rcode == rcodeRefused)
}

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
	return isUnresolved(r.Rcode, r.Synthesized)
}

// UpstreamError reports a failure rcode relayed verbatim from a live
// upstream (SERVFAIL or REFUSED). This is usually not s-hole's fault (a
// broken authoritative server, a DNSSEC failure, or a refusal).
func (r Record) UpstreamError() bool {
	return isUpstreamError(r.Rcode, r.Synthesized)
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

// MaskClientIP applies the query_log.clients transform to a client address
// before it is recorded. The modes are:
//
//	drop   return "" so no client identity is stored (the default, and the
//	       result for any unknown mode, so a bad value fails closed).
//	subnet zero the host bits: IPv4 to /24, IPv6 to /64, keeping the subnet as
//	       a meaningful group on segmented or VLAN networks.
//	full   return the address unchanged.
//
// Under subnet, a value that net.ParseIP cannot read (such as an IPv6
// address with a zone, "fe80::1%eth0") gives "": masking fails closed and
// never stores a value it could not mask (b/101). The DNS handler masks
// every query with it, StaleRows uses it to find stored values that are less
// masked than the current mode, and the admin API masks the requester of an
// allowlist change with it (the audit line).
func MaskClientIP(ip, mode string) string {
	switch mode {
	case "full":
		return ip
	case "subnet":
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return ""
		}
		if v4 := parsed.To4(); v4 != nil {
			return v4.Mask(net.CIDRMask(24, 32)).String()
		}
		return parsed.Mask(net.CIDRMask(64, 128)).String()
	default:
		return ""
	}
}
