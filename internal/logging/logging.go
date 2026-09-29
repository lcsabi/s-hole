// Package logging builds the application's slog loggers and handlers.
//
// Every package logs through a logger from For, which tags each record with
// pkg=<name>. main installs the output handler with slog.SetDefault after the
// packages are initialised, so a package logger cannot bind the handler when
// its package-level var is set. It looks up slog.Default() for each record
// instead (b/062).
package logging

import (
	"context"
	"io"
	"log/slog"
	"sync"
)

// For returns the logger for package pkg. Records go to the handler that
// slog.Default() has when they are logged, not when For is called, so a
// package-level `var logger = logging.For("x")` follows main's SetDefault.
//
// Do not pass a For logger, or its handler, to slog.SetDefault: the handler
// would then look itself up and recurse.
func For(pkg string) *slog.Logger {
	return slog.New(lateHandler{wrap: func(h slog.Handler) slog.Handler {
		return h.WithAttrs([]slog.Attr{slog.String("pkg", pkg)})
	}})
}

// lateHandler resolves its target from slog.Default() on each call. wrap
// replays the attributes and groups that were added with WithAttrs and
// WithGroup onto that target, in order.
//
// A logger built with slog.With at package init binds slog's initial default
// handler. After main calls SetDefault, that handler writes through the log
// package, which SetDefault redirects into the new handler. The record was
// then formatted twice, at level INFO, with its level, message, and attributes
// inside msg (b/062).
type lateHandler struct {
	wrap func(slog.Handler) slog.Handler
}

func (h lateHandler) target() slog.Handler { return h.wrap(slog.Default().Handler()) }

func (h lateHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return slog.Default().Handler().Enabled(ctx, l)
}

func (h lateHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.target().Handle(ctx, r)
}

func (h lateHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return lateHandler{wrap: func(t slog.Handler) slog.Handler { return h.wrap(t).WithAttrs(attrs) }}
}

func (h lateHandler) WithGroup(name string) slog.Handler {
	return lateHandler{wrap: func(t slog.Handler) slog.Handler { return h.wrap(t).WithGroup(name) }}
}

// NewStdoutHandler returns the handler for stdout: text, or JSON when json is
// true. When journal is true (stdout is the systemd journal, see
// StdoutIsJournal), each line starts with its syslog priority, such as <4> for
// WARN. journald removes the prefix and stores the line at that priority, so
// `journalctl -p warning` shows only warnings and errors. Text lines then also
// drop the time field, because journald records the time of each line. JSON
// lines keep it for tools that parse the JSON.
func NewStdoutHandler(w io.Writer, json, journal bool) slog.Handler {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if !journal {
		return newHandler(w, json, opts)
	}
	if !json {
		opts.ReplaceAttr = dropTime
	}
	mu := &sync.Mutex{}
	var h journalHandler
	for i, p := range priorities {
		h.byLevel[i] = newHandler(&prefixWriter{w: w, prefix: p, mu: mu}, json, opts)
	}
	return h
}

func newHandler(w io.Writer, json bool, opts *slog.HandlerOptions) slog.Handler {
	if json {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

func dropTime(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}

// priorities are the sd-daemon(3) line prefixes for DEBUG, INFO, WARN, and
// ERROR, in the order of journalHandler.byLevel.
var priorities = [4]string{"<7>", "<6>", "<4>", "<3>"}

// journalHandler sends each record to the handler for its level, so the
// record's line gets that level's priority prefix.
type journalHandler struct {
	byLevel [4]slog.Handler
}

func (h journalHandler) pick(l slog.Level) slog.Handler {
	switch {
	case l < slog.LevelInfo:
		return h.byLevel[0]
	case l < slog.LevelWarn:
		return h.byLevel[1]
	case l < slog.LevelError:
		return h.byLevel[2]
	default:
		return h.byLevel[3]
	}
}

func (h journalHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.pick(l).Enabled(ctx, l)
}

func (h journalHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.pick(r.Level).Handle(ctx, r)
}

func (h journalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var out journalHandler
	for i, sub := range h.byLevel {
		out.byLevel[i] = sub.WithAttrs(attrs)
	}
	return out
}

func (h journalHandler) WithGroup(name string) slog.Handler {
	var out journalHandler
	for i, sub := range h.byLevel {
		out.byLevel[i] = sub.WithGroup(name)
	}
	return out
}

// prefixWriter writes prefix and the line in one Write. slog writes one
// complete line per Write call. The four level handlers share mu, so their
// lines never interleave on the shared writer.
type prefixWriter struct {
	w      io.Writer
	prefix string
	mu     *sync.Mutex
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	line := make([]byte, 0, len(p.prefix)+len(b))
	line = append(append(line, p.prefix...), b...)
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.w.Write(line); err != nil {
		return 0, err
	}
	return len(b), nil
}
