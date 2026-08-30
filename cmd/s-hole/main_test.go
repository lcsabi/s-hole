package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"reflect"
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
		printNetworkHint("53", "0.0.0.0", "8080", true)
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
		printNetworkHint("53", "127.0.0.1", "8080", false)
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
		printNetworkHint("53", "127.0.0.1", "8080", true)
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
		printNetworkHint("53", "0.0.0.0", "8080", true)
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

// TestNewReloadFn_SingleFlight pins the b/022 invariant on the real closure
// the timer, the API, and SIGHUP all share: while one refresh holds the lock,
// a second call returns false and does not run the work. b/022 was a mutex
// living in api.Server that the periodic timer bypassed; the fix moved the
// lock into this closure. The rejected caller must not launch a concurrent
// refresh.
func TestNewReloadFn_SingleFlight(t *testing.T) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var calls atomic.Int32
	release := make(chan struct{})

	reload := newReloadFn(&mu, &wg, func() {
		calls.Add(1)
		<-release // hold the lock until the test lets go
	})

	// TryLock succeeds synchronously, so on return the lock is already held.
	if !reload() {
		t.Fatal("first reload() = false, want true (should win the lock)")
	}
	if reload() {
		t.Error("second reload() = true while a refresh is in flight, want false (single-flight)")
	}

	close(release) // let the in-flight refresh finish and release the lock
	wg.Wait()

	// After completion a fresh call wins again.
	if !reload() {
		t.Error("reload() after completion = false, want true")
	}
	wg.Wait()

	if got := calls.Load(); got != 2 {
		t.Errorf("work ran %d times, want 2 (the rejected middle call must not run work)", got)
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
		printStats:    rec("stats"),
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
		printStats:    rec("stats"),
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
// reload, cache, and db ran.
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
			printStats:    func() { rec("stats") },
			stopDNS:       func() { rec("dns"); close(dnsStopped) },
			drainHTTP:     func(context.Context) error { rec("http"); return nil },
			waitForReload: func(context.Context) { rec("reload") },
			closeCache:    func() { rec("cache") },
			closeFileLog:  func() error { rec("filelog"); return nil },
			closeDB:       func() error { rec("db"); return nil },
		})
		close(done)
	}

	go func() {
		time.Sleep(5 * time.Millisecond)
		doStop()
	}()

	if code := blockUntilStopped(start, done); code != 0 {
		t.Fatalf("blockUntilStopped code = %d, want 0", code)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"cancel", "stats", "dns", "http", "reload", "cache", "filelog", "db"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("teardown incomplete at exit: order = %v, want %v", order, want)
	}
}

// TestBlockUntilStopped_StartupErrorExitsNonZero verifies a startup serve error
// (a bind failure) returns exit code 1 without needing a stop signal.
func TestBlockUntilStopped_StartupErrorExitsNonZero(t *testing.T) {
	done := make(chan struct{}) // never closed: only the serve error should fire
	start := func() error { return errors.New("bind failed") }
	if code := blockUntilStopped(start, done); code != 1 {
		t.Fatalf("blockUntilStopped code = %d, want 1", code)
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
		printStats:    func() {},
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
