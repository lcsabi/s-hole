package service

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// fakeEventWriter records the severity and message of every event, standing in
// for *eventlog.Log so the handler logic can be tested off Windows.
type fakeEventWriter struct {
	mu     sync.Mutex
	events []fakeEvent
}

type fakeEvent struct {
	severity string // "info", "warning", or "error"
	msg      string
}

func (f *fakeEventWriter) record(severity, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, fakeEvent{severity: severity, msg: msg})
	return nil
}

func (f *fakeEventWriter) Info(_ uint32, msg string) error    { return f.record("info", msg) }
func (f *fakeEventWriter) Warning(_ uint32, msg string) error { return f.record("warning", msg) }
func (f *fakeEventWriter) Error(_ uint32, msg string) error   { return f.record("error", msg) }

func (f *fakeEventWriter) snapshot() []fakeEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeEvent, len(f.events))
	copy(out, f.events)
	return out
}

// TestEventLogHandler_SeverityMapping pins the slog level to Event Log severity
// mapping: Debug/Info fold to Info, Warn to Warning, Error to Error.
func TestEventLogHandler_SeverityMapping(t *testing.T) {
	fw := &fakeEventWriter{}
	log := slog.New(newEventLogHandler(fw))

	log.Debug("d")
	log.Info("i")
	log.Warn("w")
	log.Error("e")

	got := fw.snapshot()
	// Debug is below the handler's LevelInfo threshold, so it is dropped.
	want := []struct{ severity, msgSub string }{
		{"info", "i"},
		{"warning", "w"},
		{"error", "e"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d events, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].severity != w.severity {
			t.Errorf("event %d severity = %q, want %q", i, got[i].severity, w.severity)
		}
		if !strings.Contains(got[i].msg, "msg="+w.msgSub) {
			t.Errorf("event %d msg = %q, want it to contain msg=%q", i, got[i].msg, w.msgSub)
		}
	}
}

// TestEventLogHandler_StripsTimeAndLevel verifies the emitted message carries
// msg and custom attrs but not the time or level keys, which the Event Log
// records itself.
func TestEventLogHandler_StripsTimeAndLevel(t *testing.T) {
	fw := &fakeEventWriter{}
	log := slog.New(newEventLogHandler(fw))

	log.Info("starting", "pkg", "main", "err", "boom")

	got := fw.snapshot()
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	msg := got[0].msg
	for _, banned := range []string{"time=", "level="} {
		if strings.Contains(msg, banned) {
			t.Errorf("message %q should not contain %q", msg, banned)
		}
	}
	for _, want := range []string{`msg=starting`, "pkg=main", "err=boom"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q should contain %q", msg, want)
		}
	}
}

// TestEventLogHandler_WithAttrsAndGroup checks that attributes added via
// With/WithGroup reach the emitted message, proving the derived handlers share
// the event writer and format through the inner handler.
func TestEventLogHandler_WithAttrsAndGroup(t *testing.T) {
	fw := &fakeEventWriter{}
	base := slog.New(newEventLogHandler(fw))

	base.With("pkg", "api").Info("served")
	base.WithGroup("req").Info("done", "method", "GET")

	got := fw.snapshot()
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(got), got)
	}
	if !strings.Contains(got[0].msg, "pkg=api") {
		t.Errorf("With attr missing: %q", got[0].msg)
	}
	if !strings.Contains(got[1].msg, "req.method=GET") {
		t.Errorf("WithGroup attr missing: %q", got[1].msg)
	}
}

// TestEventLogHandler_ConcurrentHandle exercises the shared buffer under many
// goroutines so the mutex guard is verified by `go test -race`.
func TestEventLogHandler_ConcurrentHandle(t *testing.T) {
	fw := &fakeEventWriter{}
	log := slog.New(newEventLogHandler(fw))

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			log.Info("concurrent", "i", i)
		}(i)
	}
	wg.Wait()

	if got := len(fw.snapshot()); got != n {
		t.Fatalf("got %d events, want %d", got, n)
	}
}

// TestEventLogHandler_Enabled confirms the handler honors the LevelInfo
// threshold, so a Debug record is filtered before any event is written.
func TestEventLogHandler_Enabled(t *testing.T) {
	h := newEventLogHandler(&fakeEventWriter{})
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Debug should be disabled at the default LevelInfo threshold")
	}
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info should be enabled")
	}
}
