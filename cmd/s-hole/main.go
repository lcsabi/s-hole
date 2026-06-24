// Command s-hole is the network-level DNS sinkhole entry point.
//
// Lifecycle:
//   - install the default slog handler (text on a TTY, JSON when
//     S_HOLE_LOG_FORMAT=json)
//   - parse flags; if -service is set, perform the SCM action and exit
//   - load and validate config (YAML + S_HOLE_* env-var overrides); bail
//     on any duration/enum failure
//   - construct the blocklist store, stats counter, query loggers, DNS
//     response cache, DNS handler, and DNS server
//   - construct the single-flight reload closure and the admin API server
//     (which exposes /healthz and /metrics alongside the REST API)
//   - launch background tickers for stats printing and blocklist refresh,
//     both panic-recovered
//   - either enter the Windows SCM event loop (service mode) or block on
//     the DNS server (interactive mode)
//
// Signals: SIGINT and SIGTERM trigger a clean shutdown. On non-Windows
// builds, SIGHUP triggers a blocklist refresh through the same
// single-flight closure used by the periodic timer and POST /api/reload —
// see signals_unix.go.
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
	"sync"
	"syscall"
	"time"

	"github.com/laszlo/s-hole/internal/api"
	"github.com/laszlo/s-hole/internal/blocklist"
	"github.com/laszlo/s-hole/internal/cache"
	"github.com/laszlo/s-hole/internal/config"
	"github.com/laszlo/s-hole/internal/dnsserver"
	"github.com/laszlo/s-hole/internal/querylog"
	"github.com/laszlo/s-hole/internal/service"
	"github.com/laszlo/s-hole/internal/stats"
	"github.com/laszlo/s-hole/internal/version"
)

// setupLogger installs the default slog handler. Format is text on a TTY
// for human readability; switch to JSON via S_HOLE_LOG_FORMAT=json for
// production / container deployments.
func setupLogger() {
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
	flag.Parse()

	// -version is a pure CLI introspection; print before any other init so
	// it works inside scratch containers where logger setup might fail.
	if *showVersion {
		fmt.Println(version.String())
		return
	}

	setupLogger()
	mainLog := slog.With("pkg", "main")
	mainLog.Info("starting s-hole",
		"version", version.Version,
		"commit", version.Commit,
		"built", version.BuildDate,
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

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		mainLog.Error("load config", "err", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		mainLog.Error("validate config", "err", err)
		os.Exit(1)
	}
	refreshInterval, err := cfg.ParsedRefreshInterval()
	if err != nil {
		mainLog.Error("parse refresh_interval", "err", err)
		os.Exit(1)
	}
	statsInterval, err := cfg.ParsedStatsInterval()
	if err != nil {
		mainLog.Error("parse stats_interval", "err", err)
		os.Exit(1)
	}
	dbFlushInterval, err := cfg.ParsedDBFlushInterval()
	if err != nil {
		mainLog.Error("parse db_flush_interval", "err", err)
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
	handler := dnsserver.NewHandler(store, counter, cfg.Upstreams, logger, cfg.BlockMode, cfg.BlockTTL, dnsCache)
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
	reloadFn := func() bool {
		if !reloadMu.TryLock() {
			return false
		}
		reloadWG.Add(1)
		go func() {
			defer reloadMu.Unlock()
			defer reloadWG.Done()
			mainLog.Info("refreshing blocklists")
			if err := blocklist.Update(store, cfg.Blocklists, cfg.CacheDir); err != nil {
				mainLog.Warn("blocklist refresh failed", "err", err)
			}
		}()
		return true
	}

	apiServer := api.New(counter, db, store, dnsCache, reloadFn)
	go func() {
		if err := apiServer.ListenAndServe(cfg.APIListen); err != nil {
			mainLog.Error("api server", "err", err)
		}
	}()

	_, dnsPort, _ := net.SplitHostPort(cfg.Listen)
	_, apiPort, _ := net.SplitHostPort(cfg.APIListen)
	printNetworkHint(dnsPort, apiPort)

	go runTicker(statsInterval, counter.Print)
	go runTicker(refreshInterval, func() { reloadFn() })

	// doStop is the single shutdown path used by both the signal handler
	// (interactive) and the Windows SCM stop event (service mode).
	doStop := func() {
		mainLog.Info("shutting down")
		counter.Print()
		dnsServer.Shutdown()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := apiServer.Shutdown(ctx); err != nil {
			mainLog.Warn("api shutdown", "err", err)
		}
		// Wait for any in-flight blocklist refresh to finish so it can
		// complete its os.Rename before we exit. Bounded by the same 5s
		// deadline as the API shutdown.
		waitWithDeadline(ctx, &reloadWG, mainLog, "blocklist refresh")
		if dnsCache != nil {
			dnsCache.Close()
		}
		if err := fileLog.Close(); err != nil {
			mainLog.Warn("file log close", "err", err)
		}
		if db != nil {
			if err := db.Close(); err != nil {
				mainLog.Warn("db close", "err", err)
			}
		}
		os.Exit(0)
	}

	// Signal handler for interactive (non-service) use.
	//
	// SIGINT/SIGTERM trigger a clean shutdown; SIGHUP (Unix only) triggers
	// a blocklist refresh — the conventional "reload config" gesture for
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
	// of blocking directly on the DNS server.
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

	// Interactive mode: block until the DNS server exits.
	if err := dnsServer.Start(); err != nil {
		mainLog.Error("dns server", "err", err)
		os.Exit(1)
	}
}

// printNetworkHint prints the machine's LAN-facing IPv4 addresses so the
// user knows what to enter in the router's DHCP DNS field. The banner is
// drawn with Unicode box-drawing by default; ASCII fallback kicks in when
// JSON logs are selected or S_HOLE_ASCII_BANNER=1 is set, so terminals
// without a UTF-8 codepage (notably the legacy Windows console) and log
// collectors that don't expect prose are not littered with mojibake.
func printNetworkHint(dnsPort, apiPort string) {
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

	if useASCIIBanner() {
		fmt.Println("[main] +-- Router setup ---------------------------------------")
		for _, ip := range lanIPs {
			fmt.Printf("[main] |   DNS server -> %s:%s\n", ip, dnsPort)
			fmt.Printf("[main] |   Admin UI   -> http://%s:%s\n", ip, apiPort)
		}
		fmt.Println("[main] +------------------------------------------------------")
		return
	}

	fmt.Println("[main] ┌─ Router setup ───────────────────────────────────────")
	for _, ip := range lanIPs {
		fmt.Printf("[main] │  DNS server → %s:%s\n", ip, dnsPort)
		fmt.Printf("[main] │  Admin UI   → http://%s:%s\n", ip, apiPort)
	}
	fmt.Println("[main] └──────────────────────────────────────────────────────")
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

// runTicker invokes fn on a fixed interval until the process exits. Used
// for the stats printer and the periodic blocklist refresh. There is no
// stop channel: the goroutine outlives the rest of the runtime by design
// and is reclaimed when os.Exit fires in doStop.
//
// A panic inside fn is recovered and logged so a transient failure (e.g.,
// a malformed blocklist line that triggers an out-of-bounds read) does
// not silently kill the ticker and freeze updates until restart.
func runTicker(d time.Duration, fn func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for range t.C {
		runTickerOnce(fn)
	}
}

func runTickerOnce(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("ticker fn panic recovered", "panic", r)
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
