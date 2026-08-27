package service

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
)

// eventWriter is the subset of *eventlog.Log the handler needs. The real
// Windows event log satisfies it, and a test injects a fake. Keeping it an
// interface is what lets the handler logic compile and be tested off Windows,
// while the eventlog.Open syscall stays build-tagged in eventlog_windows.go.
type eventWriter interface {
	Info(eid uint32, msg string) error
	Warning(eid uint32, msg string) error
	Error(eid uint32, msg string) error
}

// eventID is the single event identifier stamped on every s-hole record. The
// slog level maps to the Event Log severity (Info/Warning/Error), which is the
// axis operators filter on in Event Viewer, so a per-message ID scheme would
// add no signal here.
const eventID = 1

// eventLogHandler is a slog.Handler that writes each record to the Windows
// Event Log. It renders the record with an inner slog.TextHandler (so attrs
// and groups format exactly as they do on stdout) into a shared buffer, then
// forwards the text to the event log at the severity mapped from the record
// level. It drops the time and level attributes from the text: the Event Log
// stamps its own timestamp and carries the severity out of band, so repeating
// them in the message is noise.
//
// The mutex guards the shared buffer. slog may call Handle from many
// goroutines, and the inner handler writes into one buffer that Handle then
// reads back. WithAttrs and WithGroup share the same writer, mutex, and buffer
// so derived loggers stay serialized against the same event-log handle.
type eventLogHandler struct {
	w     eventWriter
	mu    *sync.Mutex
	buf   *bytes.Buffer
	inner slog.Handler
}

// newEventLogHandler builds an eventLogHandler over w. The Windows constructor
// passes a real *eventlog.Log; a test passes a fake.
func newEventLogHandler(w eventWriter) slog.Handler {
	buf := &bytes.Buffer{}
	inner := slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Drop time and level at the top level; the event log records
			// both itself. A same-named attr inside a group is a user attr,
			// so it is left alone.
			if len(groups) == 0 && (a.Key == slog.TimeKey || a.Key == slog.LevelKey) {
				return slog.Attr{}
			}
			return a
		},
	})
	return &eventLogHandler{w: w, mu: &sync.Mutex{}, buf: buf, inner: inner}
}

func (h *eventLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *eventLogHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf.Reset()
	if err := h.inner.Handle(ctx, r); err != nil {
		return err
	}
	msg := strings.TrimRight(h.buf.String(), "\n")
	switch {
	case r.Level >= slog.LevelError:
		return h.w.Error(eventID, msg)
	case r.Level >= slog.LevelWarn:
		return h.w.Warning(eventID, msg)
	default:
		return h.w.Info(eventID, msg)
	}
}

func (h *eventLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &eventLogHandler{w: h.w, mu: h.mu, buf: h.buf, inner: h.inner.WithAttrs(attrs)}
}

func (h *eventLogHandler) WithGroup(name string) slog.Handler {
	return &eventLogHandler{w: h.w, mu: h.mu, buf: h.buf, inner: h.inner.WithGroup(name)}
}
