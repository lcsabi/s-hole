package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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
		printNetworkHint("53", "", "0.0.0.0", "8080", true)
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

func TestPrintNetworkHint_AdminDownShowsUnavailable(t *testing.T) {
	// b/052: when the admin listener failed to bind, the banner must not
	// advertise a URL that refuses connections; it says the UI is unavailable.
	t.Setenv("S_HOLE_LOG_FORMAT", "")
	t.Setenv("S_HOLE_ASCII_BANNER", "")
	out := captureStdout(t, func() {
		printNetworkHint("53", "", "127.0.0.1", "8080", false)
	})
	if !strings.Contains(out, "Router setup") {
		t.Skipf("no LAN interface in test env; banner skipped (got: %q)", out)
	}
	if strings.Contains(out, "http://") {
		t.Errorf("banner advertised an Admin UI URL while the bind failed:\n%s", out)
	}
	if !strings.Contains(out, "unavailable") {
		t.Errorf("banner missing the admin-unavailable note:\n%s", out)
	}
}

func TestPrintNetworkHint_LoopbackAPIPointsAtLocalhost(t *testing.T) {
	// T4 regression: with the localhost-only api_listen default, the
	// banner must not advertise http://<lan-ip>:8080. That URL is
	// connection-refused for every other device on the LAN.
	t.Setenv("S_HOLE_LOG_FORMAT", "")
	t.Setenv("S_HOLE_ASCII_BANNER", "")
	out := captureStdout(t, func() {
		printNetworkHint("53", "", "127.0.0.1", "8080", true)
	})
	if !strings.Contains(out, "Router setup") {
		t.Skipf("no LAN interface in test env; banner skipped (got: %q)", out)
	}
	if !strings.Contains(out, "http://127.0.0.1:8080") {
		t.Errorf("banner missing loopback Admin UI URL:\n%s", out)
	}
	if !strings.Contains(out, "(this machine only)") {
		t.Errorf("banner missing the loopback-scope note:\n%s", out)
	}
	if n := strings.Count(out, "Admin UI"); n != 1 {
		t.Errorf("banner has %d Admin UI lines, want exactly 1:\n%s", n, out)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"localhost", true},
		{"::1", true},
		{"0.0.0.0", false},
		{"", false}, // empty host binds every interface
		{"192.168.1.10", false},
	}
	for _, tc := range cases {
		if got := isLoopbackHost(tc.host); got != tc.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestPrintNetworkHint_ASCIIFallback(t *testing.T) {
	t.Setenv("S_HOLE_ASCII_BANNER", "1")
	out := captureStdout(t, func() {
		printNetworkHint("53", "", "0.0.0.0", "8080", true)
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
	// value AND a goroutine stack. Without the stack, a panic in the
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
	// cancelled. Otherwise the goroutine leaks past doStop and we are
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
		t.Fatal("runTicker fired no ticks before cancel: interval may be too short")
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

// gatedWork is a reload pass the test steps through. Each pass signals on
// entered, then blocks until the test calls step. It counts passes and fails
// the test if two passes overlap. Every wait is bounded, so a closure that runs
// too many or too few passes fails the test instead of hanging it.
type gatedWork struct {
	t        *testing.T
	entered  chan struct{}
	release  chan struct{}
	abort    chan struct{} // closed at cleanup to free a pass the test never stepped
	active   atomic.Int32
	started  atomic.Int32
	finished atomic.Int32
}

func newGatedWork(t *testing.T) *gatedWork {
	g := &gatedWork{
		t:       t,
		entered: make(chan struct{}, 64),
		release: make(chan struct{}),
		abort:   make(chan struct{}),
	}
	t.Cleanup(func() { close(g.abort) })
	return g
}

func (g *gatedWork) run() {
	if g.active.Add(1) != 1 {
		g.t.Error("two reload passes ran at the same time")
	}
	g.started.Add(1)
	g.entered <- struct{}{}
	select {
	case <-g.release:
	case <-g.abort:
	}
	g.finished.Add(1)
	g.active.Add(-1)
}

// waitEntered waits for the next pass to start.
func (g *gatedWork) waitEntered() {
	g.t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		g.t.Fatal("reload pass did not start")
	}
}

// step lets the pass that is blocked in run finish.
func (g *gatedWork) step() {
	g.t.Helper()
	select {
	case g.release <- struct{}{}:
	case <-time.After(5 * time.Second):
		g.t.Fatal("no reload pass was waiting to finish")
	}
}

// assertNoPassStarts checks that no further pass starts within a short wait.
func (g *gatedWork) assertNoPassStarts(msg string) {
	g.t.Helper()
	select {
	case <-g.entered:
		g.t.Fatal(msg)
	case <-time.After(50 * time.Millisecond):
	}
}

// waitIdle waits for wg with a bound, so a surplus pass fails the test.
func waitIdle(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reload closure did not go idle")
	}
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestNewReloadFn_SingleFlight pins the b/022 invariant on the real closure
// the timer, the API, and SIGHUP all share: while one pass runs, a second call
// returns false and does not start a concurrent pass. b/022 was a mutex in
// api.Server that the periodic timer bypassed. Since b/061 the rejected call
// is queued, so exactly one follow-up pass runs after the first one.
func TestNewReloadFn_SingleFlight(t *testing.T) {
	var wg sync.WaitGroup
	g := newGatedWork(t)
	reload := newReloadFn(context.Background(), discardLog(), &wg, g.run)

	if !reload() {
		t.Fatal("first reload() = false, want true")
	}
	g.waitEntered()
	if reload() {
		t.Error("second reload() = true while a pass runs, want false")
	}
	g.assertNoPassStarts("a second pass started while the first one ran")

	g.step()        // finish pass 1
	g.waitEntered() // b/061: the queued pass runs
	g.step()
	waitIdle(t, &wg)

	if got := g.started.Load(); got != 2 {
		t.Errorf("work ran %d times, want 2 (first pass plus the queued pass)", got)
	}
}

// TestNewReloadFn_ManyCallsQueueOnePass pins b/061: any number of calls
// during one pass queue a single follow-up pass, not one per call.
func TestNewReloadFn_ManyCallsQueueOnePass(t *testing.T) {
	var wg sync.WaitGroup
	g := newGatedWork(t)
	reload := newReloadFn(context.Background(), discardLog(), &wg, g.run)

	if !reload() {
		t.Fatal("first reload() = false, want true")
	}
	g.waitEntered()
	for i := 0; i < 10; i++ {
		if reload() {
			t.Fatalf("call %d during a pass returned true, want false", i)
		}
	}
	g.step()
	g.waitEntered()
	g.step()
	g.assertNoPassStarts("more than one follow-up pass ran for one burst of calls")
	waitIdle(t, &wg)
	if got := g.started.Load(); got != 2 {
		t.Errorf("work ran %d times, want 2", got)
	}
}

// TestNewReloadFn_CallDuringFollowUpQueuesAgain pins b/061: a call that
// arrives while the queued pass runs queues one more pass.
func TestNewReloadFn_CallDuringFollowUpQueuesAgain(t *testing.T) {
	var wg sync.WaitGroup
	g := newGatedWork(t)
	reload := newReloadFn(context.Background(), discardLog(), &wg, g.run)

	reload()
	g.waitEntered()
	reload() // queue pass 2
	g.step()
	g.waitEntered()
	if reload() { // queue pass 3 while pass 2 runs
		t.Error("call during the follow-up pass returned true, want false")
	}
	g.step()
	g.waitEntered()
	g.step()
	waitIdle(t, &wg)
	if got := g.started.Load(); got != 3 {
		t.Errorf("work ran %d times, want 3", got)
	}
}

// TestNewReloadFn_WaitGroupCoversFollowUp pins b/061: doStop waits on wg, so
// wg.Wait must not return between the first pass and the queued pass. After
// it returns the closure is idle, so a new call starts a pass.
func TestNewReloadFn_WaitGroupCoversFollowUp(t *testing.T) {
	var wg sync.WaitGroup
	g := newGatedWork(t)
	reload := newReloadFn(context.Background(), discardLog(), &wg, g.run)

	reload()
	g.waitEntered()
	reload() // queue a follow-up

	waited := make(chan struct{})
	go func() { wg.Wait(); close(waited) }()

	g.step() // finish pass 1; the follow-up starts
	g.waitEntered()
	select {
	case <-waited:
		t.Fatal("wg.Wait returned while the queued pass was still running")
	case <-time.After(50 * time.Millisecond):
	}
	g.step()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("wg.Wait did not return after the last pass finished")
	}
	if f := g.finished.Load(); f != 2 {
		t.Errorf("finished passes at wg.Wait return = %d, want 2", f)
	}

	// Idle again: the next call must start its own pass.
	if !reload() {
		t.Fatal("reload() after wg.Wait = false, want true (closure not idle)")
	}
	g.waitEntered()
	g.step()
	waitIdle(t, &wg)
	if got := g.started.Load(); got != 3 {
		t.Errorf("work ran %d times, want 3", got)
	}
}

// TestNewReloadFn_CancelDropsQueuedPass pins b/061: after shutdown cancels
// ctx, a queued pass does not run, but the pass in flight completes.
func TestNewReloadFn_CancelDropsQueuedPass(t *testing.T) {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := newGatedWork(t)
	reload := newReloadFn(ctx, discardLog(), &wg, g.run)

	reload()
	g.waitEntered()
	if reload() {
		t.Fatal("second reload() = true, want false (queued)")
	}
	cancel()
	g.step()
	g.assertNoPassStarts("queued pass ran after ctx was cancelled")
	waitIdle(t, &wg)
	if got := g.started.Load(); got != 1 {
		t.Errorf("work ran %d times, want 1", got)
	}
	if got := g.finished.Load(); got != 1 {
		t.Errorf("in-flight pass finished %d times, want 1", got)
	}
}

// TestNewReloadFn_LogsQueueOncePerPass pins the b/061 log lines: one
// "queued" line per pass, however many calls queue it, and one "queued
// reload started" line per follow-up pass.
func TestNewReloadFn_LogsQueueOncePerPass(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	var wg sync.WaitGroup
	g := newGatedWork(t)
	reload := newReloadFn(context.Background(), log, &wg, g.run)

	reload()
	g.waitEntered()
	reload()
	reload()
	reload() // three calls, one queue line
	g.step()
	g.waitEntered()
	reload()
	reload() // two calls during the follow-up, one more queue line
	g.step()
	g.waitEntered()
	g.step()
	waitIdle(t, &wg)

	out := buf.String()
	if n := strings.Count(out, `msg="reload queued until the running reload ends"`); n != 2 {
		t.Errorf("queued lines = %d, want 2:\n%s", n, out)
	}
	if n := strings.Count(out, `msg="queued reload started"`); n != 2 {
		t.Errorf("follow-up lines = %d, want 2:\n%s", n, out)
	}
	if !strings.Contains(out, "level=INFO") || strings.Contains(out, "level=WARN") {
		t.Errorf("want the queue lines at INFO:\n%s", out)
	}
}

// TestNewReloadFn_NoOverlapNoLostRequestUnderStress pins b/061 under load.
// Many goroutines call the closure at once while short passes run. Passes
// must never overlap, and every call must be followed by a pass that starts
// after it: a call that lands just as a pass checks the queue must not be
// lost. Each call bumps gen first; each pass records the gen it saw at start.
// The last pass must see the final gen. Run with -race.
func TestNewReloadFn_NoOverlapNoLostRequestUnderStress(t *testing.T) {
	for iter := 0; iter < 200; iter++ {
		var wg sync.WaitGroup
		var gen, lastSeen, active atomic.Int64
		work := func() {
			if active.Add(1) != 1 {
				t.Error("two reload passes ran at the same time")
			}
			lastSeen.Store(gen.Load())
			runtime.Gosched()
			active.Add(-1)
		}
		reload := newReloadFn(context.Background(), discardLog(), &wg, work)

		var callers sync.WaitGroup
		for c := 0; c < 8; c++ {
			callers.Add(1)
			go func() {
				defer callers.Done()
				for i := 0; i < 20; i++ {
					gen.Add(1)
					reload()
					if i%4 == 0 {
						runtime.Gosched()
					}
				}
			}()
		}
		callers.Wait()
		wg.Wait()
		if got, want := lastSeen.Load(), gen.Load(); got != want {
			t.Fatalf("iteration %d: last pass saw gen %d, want %d (a request was lost)", iter, got, want)
		}
		if !reload() {
			t.Fatalf("iteration %d: reload() after wg.Wait = false, want true", iter)
		}
		wg.Wait()
	}
}

// TestShutdown_TeardownOrder pins the teardown sequence. The order matters:
// tickers stop, then the DNS server stops so no query touches the cache or
// loggers, then HTTP drains, then an in-flight refresh finishes its rename,
// and only then the cache and loggers close. A wrong order risks a
// write-to-closed-DB or a half-written cache file.
func TestShutdown_TeardownOrder(t *testing.T) {
	var order []string
	rec := func(name string) func() { return func() { order = append(order, name) } }

	shutdown(slog.With("pkg", "test"), 50*time.Millisecond, shutdownDeps{
		cancelTickers: rec("cancel"),
		logStats:      rec("stats"),
		stopDNS:       rec("dns"),
		drainHTTP:     func(context.Context) error { order = append(order, "http"); return nil },
		waitForReload: func(context.Context) { order = append(order, "reload") },
		closeCache:    rec("cache"),
		closeFileLog:  func() error { order = append(order, "filelog"); return nil },
		closeDB:       func() error { order = append(order, "db"); return nil },
	})

	want := []string{"cancel", "stats", "dns", "http", "reload", "cache", "filelog", "db"}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("teardown order = %v, want %v", order, want)
	}
}

// TestShutdown_ContinuesAfterErrors verifies a drainHTTP or close error is
// logged, not fatal: every later step still runs, so a failed HTTP drain
// cannot strand an in-flight refresh or leak the cache.
func TestShutdown_ContinuesAfterErrors(t *testing.T) {
	var order []string
	rec := func(name string) func() { return func() { order = append(order, name) } }

	shutdown(slog.With("pkg", "test"), 50*time.Millisecond, shutdownDeps{
		cancelTickers: rec("cancel"),
		logStats:      rec("stats"),
		stopDNS:       rec("dns"),
		drainHTTP:     func(context.Context) error { order = append(order, "http"); return errors.New("drain failed") },
		waitForReload: func(context.Context) { order = append(order, "reload") },
		closeCache:    rec("cache"),
		closeFileLog:  func() error { order = append(order, "filelog"); return errors.New("filelog close failed") },
		closeDB:       func() error { order = append(order, "db"); return errors.New("db close failed") },
	})

	want := []string{"cancel", "stats", "dns", "http", "reload", "cache", "filelog", "db"}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("teardown did not complete after errors: order = %v, want %v", order, want)
	}
}

// TestBlockUntilStopped_WaitsForTeardown pins the b/043 guarantee: the process
// exits only after the full ordered teardown runs. It composes the real
// shutdown() with a doStop that closes done afterward, and asserts the last
// teardown step (closeDB) has run by the time blockUntilStopped returns. The
// pre-fix code returned as soon as stopDNS unblocked Start(), before http,
// reload, cache, and db ran. On a clean stop, blockUntilStopped must not call
// stop itself: the signal path already did.
func TestBlockUntilStopped_WaitsForTeardown(t *testing.T) {
	done := make(chan struct{})
	var mu sync.Mutex
	var order []string
	rec := func(n string) { mu.Lock(); order = append(order, n); mu.Unlock() }

	// start models dnsServer.Start(): it blocks until stopDNS unblocks it, then
	// returns nil (a clean shutdown).
	dnsStopped := make(chan struct{})
	start := func() error { <-dnsStopped; return nil }

	// doStop models main's closure: run the ordered teardown, then close done.
	doStop := func() {
		shutdown(slog.With("pkg", "test"), 50*time.Millisecond, shutdownDeps{
			cancelTickers: func() { rec("cancel") },
			logStats:      func() { rec("stats") },
			stopDNS:       func() { rec("dns"); close(dnsStopped) },
			drainHTTP:     func(context.Context) error { rec("http"); return nil },
			waitForReload: func(context.Context) { rec("reload") },
			closeCache:    func() { rec("cache") },
			closeFileLog:  func() error { rec("filelog"); return nil },
			closeDB:       func() error { rec("db"); return nil },
		})
		close(done)
	}

	// The stop callback given to blockUntilStopped only counts; the signal
	// path below runs the real doStop.
	var stopCalls atomic.Int32
	go doStop()

	if code := blockUntilStopped(start, func() { stopCalls.Add(1) }, done); code != 0 {
		t.Fatalf("blockUntilStopped code = %d, want 0", code)
	}
	if n := stopCalls.Load(); n != 0 {
		t.Errorf("stop called %d times on a clean stop, want 0", n)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"cancel", "stats", "dns", "http", "reload", "cache", "filelog", "db"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("teardown incomplete at exit: order = %v, want %v", order, want)
	}
}

// TestBlockUntilStopped_StartErrorStopsThenWaits pins b/064: when the DNS
// server fails at runtime, blockUntilStopped logs, calls stop exactly once,
// and returns 1 only after done closes. Returning before done closes would
// exit mid-teardown and break the b/043 guarantee.
func TestBlockUntilStopped_StartErrorStopsThenWaits(t *testing.T) {
	done := make(chan struct{})
	stopCalled := make(chan struct{}, 4)
	var stopCalls atomic.Int32
	stop := func() {
		stopCalls.Add(1)
		stopCalled <- struct{}{}
	}
	start := func() error { return errors.New("dns: listener failed") }

	result := make(chan int, 1)
	go func() { result <- blockUntilStopped(start, stop, done) }()

	select {
	case <-stopCalled:
	case code := <-result:
		t.Fatalf("blockUntilStopped returned %d before it called stop", code)
	case <-time.After(3 * time.Second):
		t.Fatal("stop was not called after start failed")
	}

	// done is still open, so blockUntilStopped must still be waiting. A
	// negative check needs a short wait; 100 ms is enough to catch an early
	// return on any host.
	select {
	case code := <-result:
		t.Fatalf("blockUntilStopped returned %d before done closed", code)
	case <-time.After(100 * time.Millisecond):
	}

	close(done)
	select {
	case code := <-result:
		if code != 1 {
			t.Errorf("blockUntilStopped code = %d, want 1", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blockUntilStopped did not return after done closed")
	}
	if n := stopCalls.Load(); n != 1 {
		t.Errorf("stop called %d times, want exactly 1", n)
	}
}

// TestBlockUntilStopped_StartErrorRunsFullTeardown composes the b/064 path
// with the real shutdown(): a start error triggers doStop, and every teardown
// step has run when blockUntilStopped returns 1 (b/043).
func TestBlockUntilStopped_StartErrorRunsFullTeardown(t *testing.T) {
	done := make(chan struct{})
	var mu sync.Mutex
	var order []string
	rec := func(n string) { mu.Lock(); order = append(order, n); mu.Unlock() }

	doStop := func() {
		shutdown(slog.With("pkg", "test"), 50*time.Millisecond, shutdownDeps{
			cancelTickers: func() { rec("cancel") },
			logStats:      func() { rec("stats") },
			stopDNS:       func() { rec("dns") },
			drainHTTP:     func(context.Context) error { rec("http"); return nil },
			waitForReload: func(context.Context) { rec("reload") },
			closeCache:    func() { rec("cache") },
			closeFileLog:  func() error { rec("filelog"); return nil },
			closeDB:       func() error { rec("db"); return nil },
		})
		close(done)
	}
	start := func() error { return errors.New("dns: listener failed") }

	result := make(chan int, 1)
	go func() { result <- blockUntilStopped(start, doStop, done) }()
	select {
	case code := <-result:
		if code != 1 {
			t.Fatalf("blockUntilStopped code = %d, want 1", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blockUntilStopped did not return; was stop called?")
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"cancel", "stats", "dns", "http", "reload", "cache", "filelog", "db"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("teardown incomplete at exit: order = %v, want %v", order, want)
	}
}

// TestBlockUntilStopped_NilStartIgnored verifies that a nil return from start
// is not a failure: blockUntilStopped does not call stop and does not return
// until done closes, and then it returns 0.
func TestBlockUntilStopped_NilStartIgnored(t *testing.T) {
	done := make(chan struct{})
	var stopCalls atomic.Int32
	startReturned := make(chan struct{})
	start := func() error { close(startReturned); return nil }

	result := make(chan int, 1)
	go func() { result <- blockUntilStopped(start, func() { stopCalls.Add(1) }, done) }()

	select {
	case <-startReturned:
	case <-time.After(3 * time.Second):
		t.Fatal("start was not called")
	}
	select {
	case code := <-result:
		t.Fatalf("blockUntilStopped returned %d after a nil start, want it to wait for done", code)
	case <-time.After(100 * time.Millisecond):
	}

	close(done)
	select {
	case code := <-result:
		if code != 0 {
			t.Errorf("blockUntilStopped code = %d, want 0", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blockUntilStopped did not return after done closed")
	}
	if n := stopCalls.Load(); n != 0 {
		t.Errorf("stop called %d times after a nil start, want 0", n)
	}
}

// TestShutdown_ReloadGetsOwnBudget pins open question B: a slow HTTP drain must
// not shrink the reload wait's timeout. drainHTTP consumes most of its budget,
// yet waitForReload must still see close to the full timeout remaining. A shared
// context (the pre-fix behavior) would leave it only timeout minus the drain.
func TestShutdown_ReloadGetsOwnBudget(t *testing.T) {
	const timeout = 200 * time.Millisecond
	var reloadBudget time.Duration

	shutdown(slog.With("pkg", "test"), timeout, shutdownDeps{
		cancelTickers: func() {},
		logStats:      func() {},
		stopDNS:       func() {},
		drainHTTP: func(context.Context) error {
			time.Sleep(120 * time.Millisecond) // burn most of the drain budget
			return nil
		},
		waitForReload: func(ctx context.Context) {
			if dl, ok := ctx.Deadline(); ok {
				reloadBudget = time.Until(dl)
			}
		},
		closeCache:   func() {},
		closeFileLog: func() error { return nil },
		closeDB:      func() error { return nil },
	})

	// Separate budgets: reload sees ~timeout. Shared budget would give ~80ms.
	if reloadBudget < 150*time.Millisecond {
		t.Errorf("reload budget = %v, want > 150ms (its own full timeout, not shared with drain)", reloadBudget)
	}
}

// ipNet builds a *net.IPNet address for the lanIPv4s tests.
func ipNet(t *testing.T, cidr string) net.Addr {
	t.Helper()
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	n.IP = ip
	return n
}

func TestLanIPv4s_SkipsVirtualAndUnusableInterfaces(t *testing.T) {
	// b/059: on a host that runs Docker, the banner offered the docker0 bridge
	// (172.17.0.1) as a DNS server for the router. A router cannot reach it.
	// The interface set mirrors the reporting VM plus the other cases.
	up := net.FlagUp | net.FlagBroadcast
	ifaces := []ifaceAddrs{
		{name: "lo", flags: net.FlagUp | net.FlagLoopback, addrs: []net.Addr{ipNet(t, "127.0.0.1/8")}},
		{name: "enp0s3", flags: up, addrs: []net.Addr{ipNet(t, "192.168.100.18/24"), ipNet(t, "fe80::1/64")}},
		{name: "docker0", flags: up, addrs: []net.Addr{ipNet(t, "172.17.0.1/16")}},
		{name: "br-3f2a9c1d", flags: up, addrs: []net.Addr{ipNet(t, "172.18.0.1/16")}},
		{name: "veth12ab", flags: up, addrs: []net.Addr{ipNet(t, "169.254.3.3/16")}},
		{name: "virbr0", flags: up, addrs: []net.Addr{ipNet(t, "192.168.122.1/24")}},
		{name: "tailscale0", flags: up, addrs: []net.Addr{ipNet(t, "100.101.102.103/32")}},
		{name: "wg0", flags: up, addrs: []net.Addr{ipNet(t, "10.8.0.1/24")}},
		{name: "eth1", flags: 0, addrs: []net.Addr{ipNet(t, "10.0.0.5/24")}},                // down
		{name: "wlan0", flags: up, addrs: []net.Addr{ipNet(t, "169.254.10.20/16")}},         // link-local only
		{name: "br0", flags: up, addrs: []net.Addr{ipNet(t, "192.168.1.10/24")}},            // a real LAN bridge
		{name: "eth2", flags: up, addrs: []net.Addr{&net.IPAddr{IP: net.IPv4(1, 2, 3, 4)}}}, // not an IPNet
	}
	got := lanIPv4s(ifaces)
	want := []string{"192.168.100.18", "192.168.1.10"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lanIPv4s = %v, want %v", got, want)
	}
}

func TestIsVirtualIface(t *testing.T) {
	for name, want := range map[string]bool{
		"docker0": true, "Docker0": true, "docker_gwbridge": true, "br-abc123": true,
		"veth9": true, "virbr0": true, "lxdbr0": true, "podman0": true, "cni0": true,
		"flannel.1": true, "cali1234": true, "vxlan.calico": true, "tailscale0": true,
		"wg0": true, "zt5u4y": true, "tun0": true, "tap0": true,
		"vboxnet0": true, "vmnet8": true, "incusbr0": true,
		"eth0": false, "enp0s3": false, "wlan0": false, "br0": false, "bond0": false, "vmbr0": false,
	} {
		if got := isVirtualIface(name); got != want {
			t.Errorf("isVirtualIface(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestSystemInterfaces_NoLoopbackInBanner(t *testing.T) {
	// A smoke test against the real host: systemInterfaces must report the
	// loopback interface, and lanIPv4s must never return an address from it.
	ifaces := systemInterfaces()
	if len(ifaces) == 0 {
		t.Skip("no network interfaces visible in this environment")
	}
	sawLoopback := false
	for _, ifc := range ifaces {
		if ifc.flags&net.FlagLoopback != 0 {
			sawLoopback = true
		}
	}
	if !sawLoopback {
		t.Error("systemInterfaces reported no loopback interface")
	}
	for _, ip := range lanIPv4s(ifaces) {
		if strings.HasPrefix(ip, "127.") {
			t.Errorf("lanIPv4s returned loopback address %s", ip)
		}
	}
}

// fakeCertReloader stands in for *dnsserver.CertReloader in the reload tests.
type fakeCertReloader struct {
	reloadErr error
	notAfter  time.Time
	reloads   int
}

func (f *fakeCertReloader) Reload() error       { f.reloads++; return f.reloadErr }
func (f *fakeCertReloader) NotAfter() time.Time { return f.notAfter }
func (f *fakeCertReloader) ExpiryWarning(now time.Time) string {
	if now.After(f.notAfter) {
		return "the DoT certificate has expired; clients will reject it"
	}
	return ""
}

func TestReloadWork_ReloadsCertificateThenRefreshes(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	certs := &fakeCertReloader{notAfter: time.Now().Add(90 * 24 * time.Hour)}
	refreshed := 0

	reloadWork(log, certs, func() {
		if certs.reloads != 1 {
			t.Error("blocklist refresh ran before the certificate reload")
		}
		refreshed++
	})()

	if certs.reloads != 1 || refreshed != 1 {
		t.Errorf("reloads = %d, refreshes = %d, want 1 and 1", certs.reloads, refreshed)
	}
	if !strings.Contains(buf.String(), "DoT certificate reloaded") {
		t.Errorf("missing reload log line:\n%s", buf.String())
	}
}

func TestReloadWork_FailedCertificateStillRefreshesBlocklists(t *testing.T) {
	// A bad certificate file must not stop the blocklist refresh; the
	// listener keeps its current certificate and the operator gets a WARN.
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	certs := &fakeCertReloader{reloadErr: errors.New("bad pem")}
	refreshed := 0

	reloadWork(log, certs, func() { refreshed++ })()

	if refreshed != 1 {
		t.Errorf("refreshes = %d, want 1 even though the certificate reload failed", refreshed)
	}
	out := buf.String()
	if !strings.Contains(out, "keeping the current certificate") || !strings.Contains(out, "level=WARN") {
		t.Errorf("want a WARN about keeping the current certificate:\n%s", out)
	}
}

func TestReloadWork_NoCertificateWhenDoTOff(t *testing.T) {
	refreshed := 0
	reloadWork(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, func() { refreshed++ })()
	if refreshed != 1 {
		t.Errorf("refreshes = %d, want 1", refreshed)
	}
}

func TestReloadWork_WarnsOnExpiredCertificate(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	certs := &fakeCertReloader{notAfter: time.Now().Add(-time.Hour)}

	reloadWork(log, certs, func() {})()

	if !strings.Contains(buf.String(), "has expired") {
		t.Errorf("want an expiry WARN after reloading an expired certificate:\n%s", buf.String())
	}
}

func TestPrintNetworkHint_DoTLine(t *testing.T) {
	t.Setenv("S_HOLE_LOG_FORMAT", "")
	for _, ascii := range []string{"", "1"} {
		t.Setenv("S_HOLE_ASCII_BANNER", ascii)
		out := captureStdout(t, func() {
			printNetworkHint("53", "853", "127.0.0.1", "8080", true)
		})
		if !strings.Contains(out, "Router setup") {
			t.Skipf("no LAN interface in test env; banner skipped (got: %q)", out)
		}
		if !strings.Contains(out, "port 853") || !strings.Contains(out, "certificate's hostname") {
			t.Errorf("banner (ascii=%q) missing the DoT line; got: %q", ascii, out)
		}
	}
	out := captureStdout(t, func() {
		printNetworkHint("53", "", "127.0.0.1", "8080", true)
	})
	if strings.Contains(out, "DoT") {
		t.Errorf("banner shows a DoT line with DoT off; got: %q", out)
	}
}

// writeExpiredKeyPair writes a self-signed certificate that expired an hour
// ago, plus its key, and returns the two paths. An expired pair still loads,
// which is the case -check-config must warn about.
func writeExpiredKeyPair(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dns.test"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		DNSNames:     []string{"dns.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestRunCheckConfig(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeExpiredKeyPair(t, dir)
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name     string
		cfg      string
		wantCode int
		wantLog  []string
	}{
		{"plain config", "", 0, []string{"config OK"}},
		{"invalid config", "block_mode: bogus\n", 1, []string{"level=ERROR"}},
		{"expired DoT certificate warns but passes",
			"dot_listen: \":853\"\ntls_cert: \"" + certFile + "\"\ntls_key: \"" + keyFile + "\"\n",
			0, []string{"has expired", "level=WARN", "config OK"}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			code := runCheckConfig(slog.New(slog.NewTextHandler(&buf, nil)), write(fmt.Sprintf("c%d.yaml", i), tc.cfg))
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d\n%s", code, tc.wantCode, buf.String())
			}
			for _, w := range tc.wantLog {
				if !strings.Contains(buf.String(), w) {
					t.Errorf("log missing %q:\n%s", w, buf.String())
				}
			}
		})
	}
}

// recordChdir returns a fake chdir that records each directory it gets and
// returns err.
func recordChdir(err error) (func(string) error, *[]string) {
	var calls []string
	return func(dir string) error {
		calls = append(calls, dir)
		return err
	}, &calls
}

// TestChdirToConfigDir_AbsolutePath verifies that an absolute config path makes
// chdir get the directory of that path, once (b/066).
func TestChdirToConfigDir_AbsolutePath(t *testing.T) {
	cfgDir := filepath.Join(t.TempDir(), "etc")
	cfgPath := filepath.Join(cfgDir, "s-hole.yaml")
	chdir, calls := recordChdir(nil)

	dir, err := chdirToConfigDir(cfgPath, chdir)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if dir != cfgDir {
		t.Errorf("dir = %q, want %q", dir, cfgDir)
	}
	if want := []string{cfgDir}; !reflect.DeepEqual(*calls, want) {
		t.Errorf("chdir calls = %q, want %q", *calls, want)
	}
}

// TestChdirToConfigDir_RelativePath verifies that a relative config path
// resolves against the working directory at call time, and chdir gets an
// absolute directory (b/066). The test changes the process working directory,
// so it must not run in parallel.
func TestChdirToConfigDir_RelativePath(t *testing.T) {
	cases := []struct {
		name    string
		cfgPath string
		subdir  string // directory under the working directory that chdir must get
	}{
		{"nested", filepath.Join("conf", "s-hole.yaml"), "conf"},
		{"bare file name", "config.yaml", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			wd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(wd, tc.subdir)
			chdir, calls := recordChdir(nil)

			dir, err := chdirToConfigDir(tc.cfgPath, chdir)
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if !filepath.IsAbs(dir) {
				t.Errorf("dir = %q, want an absolute path", dir)
			}
			if dir != want {
				t.Errorf("dir = %q, want %q", dir, want)
			}
			if !reflect.DeepEqual(*calls, []string{want}) {
				t.Errorf("chdir calls = %q, want [%q]", *calls, want)
			}
		})
	}
}

// TestChdirToConfigDir_ChdirError verifies that when chdir fails, the function
// returns chdir's error and still returns the directory, so main can log it
// (b/066).
func TestChdirToConfigDir_ChdirError(t *testing.T) {
	sentinel := errors.New("access denied")
	cfgDir := filepath.Join(t.TempDir(), "missing")
	chdir, calls := recordChdir(sentinel)

	dir, err := chdirToConfigDir(filepath.Join(cfgDir, "s-hole.yaml"), chdir)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want %v", err, sentinel)
	}
	if dir != cfgDir {
		t.Errorf("dir = %q, want %q", dir, cfgDir)
	}
	if len(*calls) != 1 {
		t.Errorf("chdir called %d times, want 1", len(*calls))
	}
}

// TestChdirToConfigDir_RealChdir verifies that with os.Chdir, the working
// directory becomes the config directory, and a relative data file such as
// queries.db lands there and not in the old working directory (b/066: under the
// Windows SCM the old working directory is C:\Windows\System32). The test
// changes the process working directory, so it must not run in parallel.
func TestChdirToConfigDir_RealChdir(t *testing.T) {
	startDir := t.TempDir()
	t.Chdir(startDir) // t.Chdir restores the original directory at cleanup
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "s-hole.yaml")

	dir, err := chdirToConfigDir(cfgPath, os.Chdir)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if dir != cfgDir {
		t.Errorf("dir = %q, want %q", dir, cfgDir)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if !sameDir(t, wd, cfgDir) {
		t.Errorf("working directory = %q, want %q", wd, cfgDir)
	}

	if err := os.WriteFile("queries.db", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "queries.db")); err != nil {
		t.Errorf("queries.db is not in the config directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(startDir, "queries.db")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("queries.db is in the start directory (stat err = %v)", err)
	}
}

// sameDir reports whether a and b name the same directory after symlinks
// resolve (a temp dir can sit behind a symlink, for example on macOS).
func sameDir(t *testing.T, a, b string) bool {
	t.Helper()
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := filepath.EvalSymlinks(b)
	if err != nil {
		t.Fatal(err)
	}
	return ra == rb
}
