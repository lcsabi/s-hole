package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/querylog"
)

// captureStdout redirects os.Stdout to a pipe for the duration of fn and
// returns whatever fn wrote. Used to exercise the banner / printer
// helpers without breaking the test harness.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

func TestSetupLogger_TextDefault(t *testing.T) {
	t.Setenv("S_HOLE_LOG_FORMAT", "") // unset
	// Snapshot the default logger so other tests are unaffected by our mutation.
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	setupLogger()
	if slog.Default() == prev {
		t.Error("setupLogger did not replace the default logger")
	}
}

func TestSetupLogger_JSONMode(t *testing.T) {
	t.Setenv("S_HOLE_LOG_FORMAT", "json")
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	// Redirect stdout because the handler writes there.
	out := captureStdout(t, func() {
		setupLogger()
		slog.Info("hello", "k", "v")
	})
	if !strings.Contains(out, `"msg":"hello"`) {
		t.Errorf("JSON handler not active; got: %q", out)
	}
}

func TestUseASCIIBanner(t *testing.T) {
	cases := []struct {
		name     string
		envFmt   string
		envASCII string
		want     bool
	}{
		{"defaults are unicode", "", "", false},
		{"json forces ascii", "json", "", true},
		{"ascii env opt-in", "", "1", true},
		{"ascii env explicit zero stays unicode", "", "0", false},
		{"ascii env explicit false stays unicode", "", "false", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("S_HOLE_LOG_FORMAT", tc.envFmt)
			t.Setenv("S_HOLE_ASCII_BANNER", tc.envASCII)
			if got := useASCIIBanner(); got != tc.want {
				t.Errorf("useASCIIBanner = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPrintNetworkHint_EmitsBanner(t *testing.T) {
	// We can't make net.InterfaceAddrs return a fixed list, but every
	// machine has at least one non-loopback interface in CI/dev. If the
	// test environment somehow has none, we skip rather than fail.
	t.Setenv("S_HOLE_LOG_FORMAT", "")
	t.Setenv("S_HOLE_ASCII_BANNER", "")
	out := captureStdout(t, func() {
		printNetworkHint("53", "8080")
	})
	if !strings.Contains(out, "Router setup") {
		t.Skipf("no LAN interface in test env; banner skipped (got: %q)", out)
	}
	if !strings.Contains(out, ":53") {
		t.Errorf("banner missing DNS port; got: %q", out)
	}
	if !strings.Contains(out, "http://") {
		t.Errorf("banner missing Admin UI URL; got: %q", out)
	}
}

func TestPrintNetworkHint_ASCIIFallback(t *testing.T) {
	t.Setenv("S_HOLE_ASCII_BANNER", "1")
	out := captureStdout(t, func() {
		printNetworkHint("53", "8080")
	})
	if strings.Contains(out, "─") || strings.Contains(out, "│") || strings.Contains(out, "┌") {
		t.Errorf("ASCII fallback still emitted box-drawing characters:\n%s", out)
	}
	if strings.Contains(out, "Router setup") {
		// Some host has a LAN interface; verify the ASCII separators are present.
		if !strings.Contains(out, "+--") {
			t.Errorf("ASCII fallback did not use '+--' separator:\n%s", out)
		}
	}
}

func TestBuildMultiLogger_NoDBReturnsFileLogger(t *testing.T) {
	fl := querylog.NewFileLogger("", "all")
	got := buildMultiLogger(fl, nil)
	if _, ok := got.(*querylog.FileLogger); !ok {
		t.Errorf("buildMultiLogger(fl, nil) = %T, want *querylog.FileLogger", got)
	}
}

func TestBuildMultiLogger_WithDBReturnsMulti(t *testing.T) {
	fl := querylog.NewFileLogger("", "all")
	dbPath := t.TempDir() + "/q.db"
	db, err := querylog.NewDBLogger(dbPath, "all", time.Hour, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	defer db.Close()

	got := buildMultiLogger(fl, db)
	if _, ok := got.(*querylog.Multi); !ok {
		t.Errorf("buildMultiLogger(fl, db) = %T, want *querylog.Multi", got)
	}
}

func TestRunTickerOnce_RecoversFromPanic(t *testing.T) {
	// R8 regression. If runTickerOnce did not recover, the test goroutine
	// would propagate the panic and crash the runtime.
	called := false
	runTickerOnce(func() {
		called = true
		panic("boom")
	})
	if !called {
		t.Fatal("fn never executed")
	}
	// Reaching this line at all means recover() caught the panic.
}

func TestRunTickerOnce_LogsPanicWithStack(t *testing.T) {
	// R45 regression. The panic-recovery log line must include the panic
	// value AND a goroutine stack — without the stack, a panic in the
	// field is undiagnosable from logs alone. We swap slog's default
	// handler with one writing to a buffer, then assert the captured
	// output mentions both the panic message and a stack-trace marker.
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	runTickerOnce(func() { panic("diagnostic-marker-boom") })

	out := buf.String()
	if !strings.Contains(out, "diagnostic-marker-boom") {
		t.Errorf("recovery log missing panic value:\n%s", out)
	}
	if !strings.Contains(out, "stack=") {
		t.Errorf("recovery log missing stack=… attribute (R45 regression):\n%s", out)
	}
	// The stack must reference the recovery site so an operator can
	// locate the panic; runTickerOnce is the canonical marker.
	if !strings.Contains(out, "runTickerOnce") {
		t.Errorf("recovery stack does not reference runTickerOnce:\n%s", out)
	}
}

func TestRunTicker_StopsOnContextCancel(t *testing.T) {
	// S8 regression. runTicker must exit promptly when its context is
	// cancelled — otherwise the goroutine leaks past doStop and we are
	// back to relying on os.Exit to reclaim it.
	calls := atomic.Int32{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		runTicker(ctx, 5*time.Millisecond, func() {
			calls.Add(1)
		})
		close(done)
	}()

	// Let a few ticks fire, then cancel.
	time.Sleep(40 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("runTicker did not exit within 500 ms of context cancel")
	}

	if calls.Load() == 0 {
		t.Fatal("runTicker fired no ticks before cancel — interval may be too short")
	}

	// Cancellation must stop the tick stream entirely; one more grace
	// period should not record any further calls.
	before := calls.Load()
	time.Sleep(40 * time.Millisecond)
	if calls.Load() != before {
		t.Errorf("calls still incrementing after cancel: %d → %d", before, calls.Load())
	}
}

func TestWaitWithDeadline_ReturnsWhenWGDone(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		wg.Done()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	start := time.Now()
	waitWithDeadline(ctx, &wg, slog.With("pkg", "test"), "thing")
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Errorf("waitWithDeadline blocked longer than the WaitGroup needed: %v", elapsed)
	}
}

func TestWaitWithDeadline_GivesUpOnDeadline(t *testing.T) {
	// WaitGroup never drains; ctx must cancel.
	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Done() // satisfy go vet's wg.Done balance

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	waitWithDeadline(ctx, &wg, slog.With("pkg", "test"), "thing-that-hangs")
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Errorf("waitWithDeadline returned before deadline: %v", elapsed)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("waitWithDeadline ignored the deadline: %v", elapsed)
	}
}
