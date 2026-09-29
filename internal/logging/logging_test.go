package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// initLogger is set at package init, before any test calls slog.SetDefault.
// This is the pattern every production package uses, and the one that broke
// in b/062.
var initLogger = For("initpkg")

// restoreDefault saves the process-wide slog default and restores it when
// the test ends. slog.SetDefault is process-global, so the tests in this
// package do not use t.Parallel.
func restoreDefault(t *testing.T) {
	t.Helper()
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
}

// useJSON installs a JSON handler at level as the slog default and returns
// the buffer it writes to.
func useJSON(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level})))
	return &buf
}

// decodeLines decodes each line of buf as one JSON object.
func decodeLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line is not JSON: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// TestFor_PackageVarFollowsLaterSetDefault is the regression test for b/062.
// A logger created at package init must send records to the handler that
// main installs later. Each record keeps its level, its exact message, and
// its attributes as separate fields. The bug logged every WARN and ERROR at
// level INFO, with the level and the attributes inside msg.
func TestFor_PackageVarFollowsLaterSetDefault(t *testing.T) {
	restoreDefault(t)
	buf := useJSON(t, slog.LevelDebug)

	initLogger.Warn("download failed", "url", "http://x.test/list")
	initLogger.Error("reload failed", "err", "boom")

	recs := decodeLines(t, buf)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2: %q", len(recs), buf.String())
	}
	want := []struct{ level, msg, key, val string }{
		{"WARN", "download failed", "url", "http://x.test/list"},
		{"ERROR", "reload failed", "err", "boom"},
	}
	for i, w := range want {
		r := recs[i]
		if r["level"] != w.level {
			t.Errorf("record %d: level = %v, want %s", i, r["level"], w.level)
		}
		if r["msg"] != w.msg {
			t.Errorf("record %d: msg = %q, want %q", i, r["msg"], w.msg)
		}
		if r["pkg"] != "initpkg" {
			t.Errorf("record %d: pkg = %v, want initpkg", i, r["pkg"])
		}
		if r[w.key] != w.val {
			t.Errorf("record %d: %s = %v, want %q", i, w.key, r[w.key], w.val)
		}
	}
}

// TestFor_CreatedBeforeSetDefault covers a logger made inside the test,
// before SetDefault, while a different handler is the default. No record may
// reach that earlier handler (b/062).
func TestFor_CreatedBeforeSetDefault(t *testing.T) {
	restoreDefault(t)
	old := useJSON(t, slog.LevelDebug)
	l := For("blocklist")
	buf := useJSON(t, slog.LevelDebug)

	l.Warn("block set is empty", "hint", "check the lists")

	if old.Len() != 0 {
		t.Errorf("earlier default handler got output: %q", old.String())
	}
	recs := decodeLines(t, buf)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1: %q", len(recs), buf.String())
	}
	r := recs[0]
	if r["level"] != "WARN" || r["msg"] != "block set is empty" || r["pkg"] != "blocklist" || r["hint"] != "check the lists" {
		t.Errorf("record = %v, want level=WARN msg=%q pkg=blocklist hint=%q", r, "block set is empty", "check the lists")
	}
}

// TestFor_FollowsEverySetDefault checks that the same logger follows a
// second SetDefault and stops writing to the first handler.
func TestFor_FollowsEverySetDefault(t *testing.T) {
	restoreDefault(t)
	l := For("x")

	first := useJSON(t, slog.LevelDebug)
	l.Info("one")
	second := useJSON(t, slog.LevelDebug)
	l.Info("two")

	if got := decodeLines(t, first); len(got) != 1 || got[0]["msg"] != "one" {
		t.Errorf("first handler records = %v, want only msg=one", got)
	}
	if got := decodeLines(t, second); len(got) != 1 || got[0]["msg"] != "two" {
		t.Errorf("second handler records = %v, want only msg=two", got)
	}
}

// TestFor_WithAndWithGroupApplyAtLogTime checks that With and WithGroup,
// called before SetDefault, apply to the handler found at log time, in
// order: attributes added after a group nest under that group.
func TestFor_WithAndWithGroupApplyAtLogTime(t *testing.T) {
	restoreDefault(t)
	l := For("x").With("a", 1).WithGroup("g").With("b", 2)
	buf := useJSON(t, slog.LevelDebug)

	l.Info("m", "c", 3)

	want := `"msg":"m","pkg":"x","a":1,"g":{"b":2,"c":3}}`
	if got := buf.String(); !strings.Contains(got, want) {
		t.Errorf("output = %q, want it to contain %q", got, want)
	}
}

// TestFor_EnabledFollowsDefaultLevel checks that the level filter is the
// current default handler's level, not the level at For time.
func TestFor_EnabledFollowsDefaultLevel(t *testing.T) {
	restoreDefault(t)
	l := For("x")
	ctx := context.Background()

	info := useJSON(t, slog.LevelInfo)
	if l.Enabled(ctx, slog.LevelDebug) {
		t.Error("Enabled(DEBUG) = true with an INFO default handler, want false")
	}
	l.Debug("hidden")
	if info.Len() != 0 {
		t.Errorf("DEBUG record written with an INFO default handler: %q", info.String())
	}

	debug := useJSON(t, slog.LevelDebug)
	if !l.Enabled(ctx, slog.LevelDebug) {
		t.Error("Enabled(DEBUG) = false with a DEBUG default handler, want true")
	}
	l.Debug("shown")
	if got := decodeLines(t, debug); len(got) != 1 || got[0]["msg"] != "shown" || got[0]["level"] != "DEBUG" {
		t.Errorf("records = %v, want one DEBUG record msg=shown", got)
	}
}

// writeRecorder keeps each Write call as a separate chunk.
type writeRecorder struct {
	mu     sync.Mutex
	chunks []string
}

func (w *writeRecorder) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.chunks = append(w.chunks, string(b))
	return len(b), nil
}

func handle(t *testing.T, h slog.Handler, level slog.Level, msg string, attrs ...slog.Attr) {
	t.Helper()
	r := slog.NewRecord(time.Now(), level, msg, 0)
	r.AddAttrs(attrs...)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle: %v", err)
	}
}

func TestNewStdoutHandler_PlainText(t *testing.T) {
	var w writeRecorder
	h := NewStdoutHandler(&w, false, false)
	handle(t, h, slog.LevelWarn, "m", slog.String("k", "v"))

	if len(w.chunks) != 1 {
		t.Fatalf("got %d writes, want 1: %q", len(w.chunks), w.chunks)
	}
	line := w.chunks[0]
	if !strings.HasPrefix(line, "time=") {
		t.Errorf("line = %q, want it to start with time= and no priority prefix", line)
	}
	if !strings.HasSuffix(line, " level=WARN msg=m k=v\n") {
		t.Errorf("line = %q, want suffix %q", line, " level=WARN msg=m k=v\n")
	}
}

func TestNewStdoutHandler_PlainJSON(t *testing.T) {
	var w writeRecorder
	h := NewStdoutHandler(&w, true, false)
	handle(t, h, slog.LevelError, "m", slog.String("k", "v"))

	if len(w.chunks) != 1 {
		t.Fatalf("got %d writes, want 1: %q", len(w.chunks), w.chunks)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(w.chunks[0]), &m); err != nil {
		t.Fatalf("line is not bare JSON (no prefix allowed): %q: %v", w.chunks[0], err)
	}
	if _, ok := m["time"]; !ok {
		t.Errorf("JSON line has no time key: %q", w.chunks[0])
	}
	if m["level"] != "ERROR" || m["msg"] != "m" || m["k"] != "v" {
		t.Errorf("JSON line = %v, want level=ERROR msg=m k=v", m)
	}
}

// journalLevels maps each level to its sd-daemon prefix and its text name.
// Levels between the named ones take the prefix of the nearest lower one.
var journalLevels = []struct {
	level  slog.Level
	prefix string
	name   string
}{
	{slog.LevelDebug, "<7>", "DEBUG"},
	{slog.LevelInfo, "<6>", "INFO"},
	{slog.LevelInfo + 1, "<6>", "INFO+1"},
	{slog.LevelWarn, "<4>", "WARN"},
	{slog.LevelWarn + 1, "<4>", "WARN+1"},
	{slog.LevelError, "<3>", "ERROR"},
	{slog.LevelError + 4, "<3>", "ERROR+4"},
}

// TestNewStdoutHandler_JournalTextPrefixes checks the priority prefix per
// level and that journal text lines have no time field. Handle is called
// directly so that DEBUG reaches the handler; the INFO minimum is checked
// by Enabled (see TestNewStdoutHandler_MinimumLevelInfo).
func TestNewStdoutHandler_JournalTextPrefixes(t *testing.T) {
	for _, tc := range journalLevels {
		t.Run(tc.name, func(t *testing.T) {
			var w writeRecorder
			h := NewStdoutHandler(&w, false, true)
			handle(t, h, tc.level, "m", slog.String("k", "v"))
			if len(w.chunks) != 1 {
				t.Fatalf("got %d writes, want 1: %q", len(w.chunks), w.chunks)
			}
			want := tc.prefix + "level=" + tc.name + " msg=m k=v\n"
			if w.chunks[0] != want {
				t.Errorf("line = %q, want %q", w.chunks[0], want)
			}
		})
	}
}

// TestNewStdoutHandler_JournalJSONPrefixes checks the priority prefix per
// level and that journal JSON lines keep the time key.
func TestNewStdoutHandler_JournalJSONPrefixes(t *testing.T) {
	for _, tc := range journalLevels {
		t.Run(tc.name, func(t *testing.T) {
			var w writeRecorder
			h := NewStdoutHandler(&w, true, true)
			handle(t, h, tc.level, "m", slog.String("k", "v"))
			if len(w.chunks) != 1 {
				t.Fatalf("got %d writes, want 1: %q", len(w.chunks), w.chunks)
			}
			line := w.chunks[0]
			if !strings.HasPrefix(line, tc.prefix+"{") {
				t.Fatalf("line = %q, want prefix %q then JSON", line, tc.prefix)
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, tc.prefix)), &m); err != nil {
				t.Fatalf("rest of line is not JSON: %q: %v", line, err)
			}
			if _, ok := m["time"]; !ok {
				t.Errorf("journal JSON line has no time key: %q", line)
			}
			if m["level"] != tc.name || m["msg"] != "m" || m["k"] != "v" {
				t.Errorf("JSON = %v, want level=%s msg=m k=v", m, tc.name)
			}
		})
	}
}

// TestNewStdoutHandler_JournalWithAttrsAndGroup checks that WithAttrs and
// WithGroup on the journal handler reach the handler of every level.
func TestNewStdoutHandler_JournalWithAttrsAndGroup(t *testing.T) {
	for _, tc := range journalLevels {
		t.Run(tc.name, func(t *testing.T) {
			var w writeRecorder
			h := NewStdoutHandler(&w, false, true).
				WithAttrs([]slog.Attr{slog.String("pkg", "p")}).
				WithGroup("g")
			handle(t, h, tc.level, "m", slog.Int("n", 1))
			want := tc.prefix + "level=" + tc.name + " msg=m pkg=p g.n=1\n"
			if len(w.chunks) != 1 || w.chunks[0] != want {
				t.Errorf("writes = %q, want one write %q", w.chunks, want)
			}
		})
	}
}

// TestNewStdoutHandler_MinimumLevelInfo checks that every mode drops DEBUG
// and keeps INFO.
func TestNewStdoutHandler_MinimumLevelInfo(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []struct{ json, journal bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprintf("json=%v,journal=%v", mode.json, mode.journal), func(t *testing.T) {
			var w writeRecorder
			h := NewStdoutHandler(&w, mode.json, mode.journal)
			if h.Enabled(ctx, slog.LevelDebug) {
				t.Error("Enabled(DEBUG) = true, want false")
			}
			if !h.Enabled(ctx, slog.LevelInfo) {
				t.Error("Enabled(INFO) = false, want true")
			}
			l := slog.New(h)
			l.Debug("hidden")
			l.Info("shown")
			if len(w.chunks) != 1 || !strings.Contains(w.chunks[0], "shown") {
				t.Errorf("writes = %q, want only the INFO record", w.chunks)
			}
		})
	}
}

// overlapWriter fails the test if two Write calls run at the same time, and
// keeps each Write as one chunk. It yields inside Write to widen the window
// for an overlap.
type overlapWriter struct {
	inFlight atomic.Int32
	overlap  atomic.Bool
	buf      bytes.Buffer // guarded by the handler; -race reports it if not
	writes   atomic.Int64
}

func (w *overlapWriter) Write(b []byte) (int, error) {
	if w.inFlight.Add(1) != 1 {
		w.overlap.Store(true)
	}
	defer w.inFlight.Add(-1)
	w.writes.Add(1)
	runtime.Gosched()
	return w.buf.Write(b)
}

// TestNewStdoutHandler_JournalConcurrentLinesDoNotInterleave logs from many
// goroutines at mixed levels through one journal handler. Each record must
// be one Write, the writes must not overlap, and every line must be whole
// with the prefix of its level. Run it under -race.
func TestNewStdoutHandler_JournalConcurrentLinesDoNotInterleave(t *testing.T) {
	levels := []struct {
		level  slog.Level
		prefix string
		name   string
	}{
		{slog.LevelInfo, "<6>", "INFO"},
		{slog.LevelWarn, "<4>", "WARN"},
		{slog.LevelError, "<3>", "ERROR"},
	}
	const goroutines, perG = 16, 200

	for _, isJSON := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", isJSON), func(t *testing.T) {
			var w overlapWriter
			l := slog.New(NewStdoutHandler(&w, isJSON, true))
			var wg sync.WaitGroup
			for g := range goroutines {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range perG {
						lv := levels[(g+i)%len(levels)]
						l.Log(context.Background(), lv.level, "msg-"+lv.name, "g", g, "i", i)
					}
				}()
			}
			wg.Wait()

			if w.overlap.Load() {
				t.Error("two Write calls ran at the same time on the shared writer")
			}
			if got := w.writes.Load(); got != goroutines*perG {
				t.Errorf("got %d writes, want %d (one per record)", got, goroutines*perG)
			}
			lines := strings.Split(strings.TrimSuffix(w.buf.String(), "\n"), "\n")
			if len(lines) != goroutines*perG {
				t.Fatalf("got %d lines, want %d", len(lines), goroutines*perG)
			}
			for _, line := range lines {
				ok := false
				for _, lv := range levels {
					if !strings.HasPrefix(line, lv.prefix) {
						continue
					}
					rest := strings.TrimPrefix(line, lv.prefix)
					if isJSON {
						var m map[string]any
						ok = json.Unmarshal([]byte(rest), &m) == nil && m["level"] == lv.name && m["msg"] == "msg-"+lv.name
					} else {
						ok = strings.HasPrefix(rest, "level="+lv.name+" msg=msg-"+lv.name+" g=") && strings.Count(line, "level=") == 1
					}
				}
				if !ok {
					t.Fatalf("malformed line or wrong prefix for its level: %q", line)
				}
			}
		})
	}
}

type errWriter struct{}

var errWrite = errors.New("disk full")

func (errWriter) Write([]byte) (int, error) { return 0, errWrite }

// TestNewStdoutHandler_WriteErrorReturned checks that Handle returns the
// error from the writer in every mode.
func TestNewStdoutHandler_WriteErrorReturned(t *testing.T) {
	for _, mode := range []struct{ json, journal bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprintf("json=%v,journal=%v", mode.json, mode.journal), func(t *testing.T) {
			h := NewStdoutHandler(errWriter{}, mode.json, mode.journal)
			err := h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelWarn, "m", 0))
			if !errors.Is(err, errWrite) {
				t.Errorf("Handle error = %v, want %v", err, errWrite)
			}
		})
	}
}
