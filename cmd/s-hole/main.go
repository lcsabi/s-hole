// Command s-hole is the network-level DNS sinkhole entry point.
//
// Lifecycle:
//   - install the default slog handler (text on a TTY, JSON when
//     S_HOLE_LOG_FORMAT=json, or the Windows Event Log when launched by the
//     SCM, where stdout is discarded)
//   - parse flags; if -service is set, perform the SCM action and exit
//   - load and validate config (YAML + S_HOLE_* env-var overrides); bail
//     on any duration/enum failure
//   - construct the blocklist store, stats counter, query loggers, DNS
//     response cache, DNS handler, and DNS server
//   - construct the single-flight reload closure and the admin API server
//     (which exposes /healthz, /readyz, /metrics, and, opt-in via
//     enable_pprof, /debug/pprof/* alongside the REST API)
//   - launch background tickers for stats printing and blocklist refresh,
//     both panic-recovered
//   - either enter the Windows SCM event loop (service mode) or run the DNS
//     server in the background and block until doStop completes the ordered
//     teardown (interactive mode)
//
// Signals: SIGINT and SIGTERM trigger a clean shutdown. On non-Windows
// builds, SIGHUP triggers a blocklist refresh through the same
// single-flight closure used by the periodic timer and POST /api/reload.
// See signals_unix.go.
//
// Shutdown is funnelled through a single doStop closure used by both the
// signal handler and the Windows SCM stop control; this keeps the
// cleanup order consistent across the two entry points. An in-flight
// blocklist refresh is waited on (with a 5 s deadline) so the atomic
// rename can complete before the process exits.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/lcsabi/s-hole/internal/api"
	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/config"
	"github.com/lcsabi/s-hole/internal/dnsserver"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/service"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/lcsabi/s-hole/internal/version"
)

// setupLogger installs the default slog handler. Format is text on a TTY
// for human readability; switch to JSON via S_HOLE_LOG_FORMAT=json for
// production / container deployments.
//
// Under the Windows SCM the process has no console, so a stdout-bound handler
// is discarded and every startup error, refresh failure, and audit line is
// lost. When launched by the SCM, route slog to the Windows Event Log instead;
// if opening the source fails, fall through to the stdout handler so the
// process is never left with no logger (never worse than today). The
// interactive -service subcommands are not SCM-launched, so IsWindowsService()
// is false for them and their console output is unchanged; Linux is
// unaffected (journald captures stdout).
func setupLogger() {
	if service.IsWindowsService() {
		if h, err := service.NewEventLogHandler(); err == nil {
			slog.SetDefault(slog.New(h))
			return
		}
	}
	var h slog.Handler
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if os.Getenv("S_HOLE_LOG_FORMAT") == "json" {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(h))
}

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	svcAction := flag.String("service", "", "manage the system service: install|uninstall|start|stop")
	showVersion := flag.Bool("version", false, "print version and exit")
	checkConfig := flag.Bool("check-config", false, "load and validate the config, then exit")
	flag.Parse()

	// -version is a pure CLI introspection; print before any other init so
	// it works inside scratch containers where logger setup might fail.
	if *showVersion {
		fmt.Println(version.String())
		return
	}

	setupLogger()
	info := version.Short()
	mainLog := slog.With("pkg", "main")
	mainLog.Info("starting s-hole",
		"version", info.Version,
		"commit", info.Commit,
		"built", info.BuildDate,
	)

	// Service management commands exit immediately after completing.
	switch *svcAction {
	case "install":
		absConfig, err := filepath.Abs(*cfgPath)
		if err != nil {
			mainLog.Error("config path", "err", err)
			os.Exit(1)
		}
		if err := service.Install(absConfig); err != nil {
			mainLog.Error("install", "err", err)
			os.Exit(1)
		}
		return
	case "uninstall":
		if err := service.Uninstall(); err != nil {
			mainLog.Error("uninstall", "err", err)
			os.Exit(1)
		}
		return
	case "start":
		if err := service.Start(); err != nil {
			mainLog.Error("start", "err", err)
			os.Exit(1)
		}
		return
	case "stop":
		if err := service.Stop(); err != nil {
			mainLog.Error("stop", "err", err)
			os.Exit(1)
		}
		return
	case "":
		// continue to normal startup
	default:
		mainLog.Error("unknown -service action", "action", *svcAction, "valid", "install|uninstall|start|stop")
		os.Exit(1)
	}

	// -check-config is a dry run: it loads and validates the config exactly the
	// way startup does (config.LoadAndValidate is the same call), then exits. It
	// lets the installer reject a bad config before `systemctl restart`, so a
	// config error surfaces on screen instead of as a failed start (ROADMAP #27).
	if *checkConfig {
		if _, _, _, _, err := config.LoadAndValidate(*cfgPath); err != nil {
			mainLog.Error("config", "err", err)
			os.Exit(1)
		}
		mainLog.Info("config OK", "path", *cfgPath)
		return
	}

	cfg, refreshInterval, statsInterval, dbFlushInterval, err := config.LoadAndValidate(*cfgPath)
	if err != nil {
		mainLog.Error("config", "err", err)
		os.Exit(1)
	}

	store := blocklist.NewStore()
	store.SetWhitelist(cfg.Whitelist)

	if err := blocklist.Update(store, cfg.Blocklists, cfg.CacheDir); err != nil {
		mainLog.Warn("initial blocklist update", "err", err)
	}

	counter := stats.New()

	fileLog := querylog.NewFileLogger(cfg.LogFile, cfg.LogQueries)

	var db *querylog.DBLogger
	if cfg.QueryDB != "" {
		db, err = querylog.NewDBLogger(cfg.QueryDB, cfg.LogQueries, dbFlushInterval, cfg.QueryDBRetentionDays)
		if err != nil {
			mainLog.Warn("SQLite logger disabled", "err", err)
		} else {
			mainLog.Info("query log database opened", "path", cfg.QueryDB)
		}
	}

	var dnsCache *cache.Cache
	if cfg.CacheSize > 0 {
		dnsCache = cache.New(cfg.CacheSize)
		mainLog.Info("DNS response cache enabled", "max_entries", cfg.CacheSize)
	}

	logger := buildMultiLogger(fileLog, db)
	handler := dnsserver.NewHandler(store, counter, cfg.Upstreams, logger, cfg.BlockMode, cfg.BlockTTL, dnsCache, cfg.LocalPTR)
	dnsServer := dnsserver.NewServer(cfg.Listen, handler)

	// reloadMu single-flights blocklist refreshes across both the periodic
	// timer and POST /api/reload. Two concurrent goroutines downloading to
	// the same cache files would race on file writes.
	//
	// reloadFn returns synchronously: true means the refresh started, false
	// means a prior refresh is still running. The actual download work runs
	// in a background goroutine so callers (including the HTTP handler)
	// return quickly.
	//
	// reloadWG lets doStop wait for any in-flight refresh to complete (or
	// be cancelled by deadline) before the process exits; otherwise the
	// goroutine could be killed mid-rename and leave a half-written
	// cache .tmp file behind.
	var reloadMu sync.Mutex
	var reloadWG sync.WaitGroup
	reloadFn := newReloadFn(&reloadMu, &reloadWG, func() {
		mainLog.Info("refreshing blocklists")
		if err := blocklist.Update(store, cfg.Blocklists, cfg.CacheDir); err != nil {
			mainLog.Warn("blocklist refresh failed", "err", err)
		}
	})

	apiServer := api.New(counter, db, store, dnsCache, reloadFn)
	if cfg.EnablePprof {
		apiServer.EnablePprof(true)
		mainLog.Warn("pprof endpoints enabled; bind api_listen to localhost only",
			"api_listen", cfg.APIListen)
	}
	// Bind the admin listener synchronously so a bad api_listen or a port
	// conflict is caught here, in order, before the banner. DNS is the critical
	// service, so a failed admin bind is a WARN and continue (fail-open), not
	// fatal: killing DNS because the optional dashboard could not bind would
	// invert the priority. The banner then reports the admin UI as unavailable
	// instead of advertising a URL that refuses connections (b/052).
	apiUp := false
	if apiLn, err := net.Listen("tcp", cfg.APIListen); err != nil {
		mainLog.Warn("admin UI failed to bind; continuing without it (DNS still serving)",
			"api_listen", cfg.APIListen, "err", err,
			"hint", "check for a port conflict or fix api_listen")
	} else {
		apiUp = true
		go func() {
			if err := apiServer.Serve(apiLn); err != nil {
				mainLog.Error("api server", "err", err)
			}
		}()
	}

	_, dnsPort, _ := net.SplitHostPort(cfg.Listen)
	apiHost, apiPort, _ := net.SplitHostPort(cfg.APIListen)
	printNetworkHint(dnsPort, apiHost, apiPort, apiUp)

	// runCtx is the application-wide lifecycle context. doStop cancels
	// it before tearing down subsystems so the background tickers exit
	// promptly instead of running until os.Exit.
	runCtx, runCancel := context.WithCancel(context.Background())
	go runTicker(runCtx, statsInterval, counter.Print)
	go runTicker(runCtx, refreshInterval, func() {
		mainLog.Info("blocklist reload requested via timer")
		reloadFn()
	})

	// done is closed by doStop after the ordered teardown finishes. The
	// interactive path blocks on it, so the process exits only once shutdown()
	// has run to completion. This makes doStop the sole exit authority and
	// removes the race where dnsServer.Start() returning (unblocked by stopDNS)
	// let main() return before the later teardown steps ran (b/043).
	done := make(chan struct{})

	// doStop is the single shutdown path used by both the signal handler
	// (interactive) and the Windows SCM stop event (service mode). It wires the
	// running subsystems into shutdown(); shutdown() owns the teardown order.
	// stopOnce guards against a second stop request re-running teardown. The
	// old os.Exit(0) made re-entry impossible; without it, guard explicitly.
	var stopOnce sync.Once
	doStop := func() {
		stopOnce.Do(func() {
			shutdown(mainLog, 5*time.Second, shutdownDeps{
				cancelTickers: runCancel,
				printStats:    counter.Print,
				stopDNS:       dnsServer.Shutdown,
				drainHTTP:     apiServer.Shutdown,
				waitForReload: func(ctx context.Context) {
					waitWithDeadline(ctx, &reloadWG, mainLog, "blocklist refresh")
				},
				closeCache: func() {
					if dnsCache != nil {
						dnsCache.Close()
					}
				},
				closeFileLog: fileLog.Close,
				closeDB: func() error {
					if db != nil {
						return db.Close()
					}
					return nil
				},
			})
			close(done)
		})
	}

	// Signal handler for interactive (non-service) use.
	//
	// SIGINT/SIGTERM trigger a clean shutdown; SIGHUP (Unix only) triggers
	// a blocklist refresh, the conventional "reload config" gesture for
	// long-running daemons. Operators expect `kill -HUP $(pidof s-hole)`
	// to work without needing the admin API enabled.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, append([]os.Signal{syscall.SIGINT, syscall.SIGTERM}, reloadSignals()...)...)
	go func() {
		for sig := range sigs {
			if isReloadSignal(sig) {
				mainLog.Info("reload signal received", "signal", sig.String())
				reloadFn()
				continue
			}
			fmt.Println()
			doStop()
			return
		}
	}()

	// When launched by the Windows SCM, enter the service event loop instead
	// of blocking directly on the DNS server. The SCM stop control calls doStop,
	// which runs the same ordered teardown as the interactive path.
	if service.IsWindowsService() {
		if err := service.Run(func() {
			if err := dnsServer.Start(); err != nil {
				mainLog.Warn("dns server stopped", "err", err)
			}
		}, doStop); err != nil {
			mainLog.Error("service", "err", err)
			os.Exit(1)
		}
		return
	}

	// Interactive mode: run the DNS server in the background so doStop, not a
	// returning Start(), owns the exit.
	if code := blockUntilStopped(dnsServer.Start, done); code != 0 {
		os.Exit(code)
	}
}

// blockUntilStopped runs start (the DNS server) in a goroutine and blocks until
// doStop closes done. It returns the process exit code: 1 on a startup serve
// error, 0 on a clean stop. The serve goroutine reports only a non-nil error,
// which in practice is a startup bind failure; a clean Shutdown makes start()
// return nil, which is dropped so it cannot race the done signal. Extracted from
// main so the guarantee "the process exits only after shutdown() has fully run"
// is unit-testable (b/043).
func blockUntilStopped(start func() error, done <-chan struct{}) int {
	serveErr := make(chan error, 1)
	go func() {
		if err := start(); err != nil {
			serveErr <- err
		}
	}()
	select {
	case err := <-serveErr:
		slog.With("pkg", "main").Error("dns server", "err", err)
		return 1
	case <-done:
		return 0
	}
}

// printNetworkHint prints the machine's LAN-facing IPv4 addresses so the
// user knows what to enter in the router's DHCP DNS field. The banner is
// drawn with Unicode box-drawing by default; ASCII fallback kicks in when
// JSON logs are selected or S_HOLE_ASCII_BANNER=1 is set, so terminals
// without a UTF-8 codepage (notably the legacy Windows console) and log
// collectors that don't expect prose are not littered with mojibake.
//
// The Admin UI line honors where the API server is actually bound: with
// the localhost-only default, advertising http://<lan-ip>:8080 would be
// a lie (every other device gets connection-refused), so the banner
// points at 127.0.0.1 and says so (T4). When apiUp is false the admin
// listener failed to bind, so the banner says the UI is unavailable rather
// than advertising a URL that refuses connections (b/052).
func printNetworkHint(dnsPort, apiHost, apiPort string, apiUp bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}

	var lanIPs []string
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		lanIPs = append(lanIPs, ip.String())
	}

	if len(lanIPs) == 0 {
		return
	}

	adminHosts := lanIPs
	adminNote := ""
	if isLoopbackHost(apiHost) {
		adminHosts = []string{"127.0.0.1"}
		adminNote = " (this machine only)"
	}

	if useASCIIBanner() {
		fmt.Println("[main] +-- Router setup ---------------------------------------")
		for _, ip := range lanIPs {
			fmt.Printf("[main] |   DNS server -> %s:%s\n", ip, dnsPort)
		}
		if apiUp {
			for _, h := range adminHosts {
				fmt.Printf("[main] |   Admin UI   -> http://%s:%s%s\n", h, apiPort, adminNote)
			}
		} else {
			fmt.Println("[main] |   Admin UI   -> unavailable (api_listen bind failed)")
		}
		fmt.Println("[main] +------------------------------------------------------")
		return
	}

	fmt.Println("[main] ┌─ Router setup ───────────────────────────────────────")
	for _, ip := range lanIPs {
		fmt.Printf("[main] │  DNS server → %s:%s\n", ip, dnsPort)
	}
	if apiUp {
		for _, h := range adminHosts {
			fmt.Printf("[main] │  Admin UI   → http://%s:%s%s\n", h, apiPort, adminNote)
		}
	} else {
		fmt.Println("[main] │  Admin UI   → unavailable (api_listen bind failed)")
	}
	fmt.Println("[main] └──────────────────────────────────────────────────────")
}

// isLoopbackHost reports whether host names a loopback address. An empty
// host (api_listen ":8080") binds every interface and is therefore not
// loopback.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func useASCIIBanner() bool {
	if os.Getenv("S_HOLE_LOG_FORMAT") == "json" {
		return true
	}
	if v := os.Getenv("S_HOLE_ASCII_BANNER"); v != "" && v != "0" && v != "false" {
		return true
	}
	return false
}

// buildMultiLogger fans out to the file logger and optionally the DB logger.
func buildMultiLogger(fl *querylog.FileLogger, db *querylog.DBLogger) dnsserver.Logger {
	if db == nil {
		return fl
	}
	return querylog.NewMulti(fl, db)
}

// runTicker invokes fn on a fixed interval until ctx is cancelled. Used
// for the stats printer and the periodic blocklist refresh. doStop
// cancels the application-wide context before tearing down dependent
// subsystems so these tickers exit cleanly. Without that, the goroutines
// would have to be reclaimed implicitly by os.Exit, which is fragile if
// this code is ever embedded in a larger binary.
//
// A panic inside fn is recovered and logged so a transient failure (e.g.,
// a malformed blocklist line that triggers an out-of-bounds read) does
// not silently kill the ticker and freeze updates until restart.
func runTicker(ctx context.Context, d time.Duration, fn func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			runTickerOnce(fn)
		}
	}
}

func runTickerOnce(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			// Include the full stack so a panic that fires in the field
			// is diagnosable from the log stream alone. Without one,
			// recover() swallows the only signal.
			slog.Error("ticker fn panic recovered",
				"panic", r,
				"stack", string(debug.Stack()))
		}
	}()
	fn()
}

// waitWithDeadline blocks until wg drains or ctx is done. Used during
// shutdown to give background work a bounded window to finish cleanly.
func waitWithDeadline(ctx context.Context, wg *sync.WaitGroup, log *slog.Logger, what string) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		log.Warn("shutdown deadline exceeded waiting for "+what, "err", ctx.Err())
	}
}

// newReloadFn builds the single-flight blocklist-refresh closure shared by the
// periodic timer, POST /api/reload, and SIGHUP. It returns true if it acquired
// the lock and started work (asynchronously, so callers return at once), or
// false if a refresh is already running. The shared mutex stops the three
// callers from launching concurrent downloads that would race on the cache
// files. Keeping the lock in this one closure, not in api.Server, is what
// prevents the periodic timer from bypassing the gate (b/022).
//
// wg lets doStop wait for an in-flight refresh to finish its os.Rename before
// the process exits, so a refresh is never killed mid-write.
func newReloadFn(mu *sync.Mutex, wg *sync.WaitGroup, work func()) func() bool {
	return func() bool {
		if !mu.TryLock() {
			return false
		}
		wg.Add(1)
		go func() {
			// Explicit, ordered cleanup: release the lock first so a
			// subsequent caller is not gated on us, then signal Done so
			// doStop's wg.Wait() returns only after the mutex is already
			// free. Two separate defers would fire in LIFO order, which
			// puts Done before Unlock and confuses readers who expect
			// "release resources in reverse acquisition order."
			defer func() {
				mu.Unlock()
				wg.Done()
			}()
			work()
		}()
		return true
	}
}

// shutdownDeps holds the teardown actions so the order in shutdown() can be
// tested. main wires the real subsystems; a test injects recorders to assert
// the sequence.
type shutdownDeps struct {
	cancelTickers func()                      // stop scheduling new refresh/stats work
	printStats    func()                      // final stats line
	stopDNS       func()                      // after this, no query touches the cache or loggers
	drainHTTP     func(context.Context) error // drain in-flight admin requests
	waitForReload func(context.Context)       // let an in-flight refresh finish its rename
	closeCache    func()
	closeFileLog  func() error
	closeDB       func() error
}

// shutdown runs teardown in the required order and returns; the caller adds the
// process exit. The order is not arbitrary: cancel the tickers so they stop
// scheduling; stop the DNS server so no query touches the cache or loggers
// after this; drain in-flight HTTP; wait for an in-flight blocklist refresh to
// finish its os.Rename; only then close the cache and loggers. Closing a logger
// or the cache while the DNS server or a refresh is still live risks a
// write-to-closed-DB or a half-written cache file. TestShutdown_TeardownOrder
// pins the sequence. A drainHTTP or closeDB error is logged, not fatal, so the
// remaining steps still run. drainHTTP and waitForReload each run under their
// own timeout so a slow drain does not starve the reload wait.
func shutdown(log *slog.Logger, timeout time.Duration, d shutdownDeps) {
	log.Info("shutting down")
	d.cancelTickers()
	d.printStats()
	d.stopDNS()
	// Separate timeout budgets. A shared context let a slow HTTP drain eat into
	// the reload wait; the reload wait protects an in-flight refresh from being
	// killed mid os.Rename (R53), so it must get its full budget regardless of
	// how long the drain took.
	hctx, hcancel := context.WithTimeout(context.Background(), timeout)
	if err := d.drainHTTP(hctx); err != nil {
		log.Warn("api shutdown", "err", err)
	}
	hcancel()
	rctx, rcancel := context.WithTimeout(context.Background(), timeout)
	d.waitForReload(rctx)
	rcancel()
	d.closeCache()
	if err := d.closeFileLog(); err != nil {
		log.Warn("file log close", "err", err)
	}
	if err := d.closeDB(); err != nil {
		log.Warn("db close", "err", err)
	}
}
