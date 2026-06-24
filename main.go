// Command s-hole is the network-level DNS sinkhole entry point.
//
// Lifecycle:
//   - parse flags; if -service is set, perform the SCM action and exit
//   - load and validate config; bail on any duration/enum failure
//   - construct the blocklist store, stats counter, query loggers, DNS
//     response cache, DNS handler, and DNS server
//   - construct the single-flight reload closure and the admin API server
//   - launch background tickers for stats printing and blocklist refresh
//   - either enter the Windows SCM event loop (service mode) or block on
//     the DNS server (interactive mode)
//
// Shutdown is funnelled through a single doStop closure used by both the
// Ctrl+C path (SIGINT/SIGTERM) and the Windows SCM stop control; this
// keeps the cleanup order consistent across the two entry points.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
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
	dnsserver "github.com/laszlo/s-hole/internal/dns"
	"github.com/laszlo/s-hole/internal/querylog"
	"github.com/laszlo/s-hole/internal/service"
	"github.com/laszlo/s-hole/internal/stats"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	svcAction := flag.String("service", "", "manage the system service: install|uninstall|start|stop")
	flag.Parse()

	// Service management commands exit immediately after completing.
	switch *svcAction {
	case "install":
		absConfig, err := filepath.Abs(*cfgPath)
		if err != nil {
			log.Fatalf("config path: %v", err)
		}
		if err := service.Install(absConfig); err != nil {
			log.Fatalf("install: %v", err)
		}
		return
	case "uninstall":
		if err := service.Uninstall(); err != nil {
			log.Fatalf("uninstall: %v", err)
		}
		return
	case "start":
		if err := service.Start(); err != nil {
			log.Fatalf("start: %v", err)
		}
		return
	case "stop":
		if err := service.Stop(); err != nil {
			log.Fatalf("stop: %v", err)
		}
		return
	case "":
		// continue to normal startup
	default:
		log.Fatalf("unknown -service action %q; valid: install, uninstall, start, stop", *svcAction)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("config: %v", err)
	}
	refreshInterval, err := cfg.ParsedRefreshInterval()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	statsInterval, err := cfg.ParsedStatsInterval()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	dbFlushInterval, err := cfg.ParsedDBFlushInterval()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	store := blocklist.NewStore()
	store.SetWhitelist(cfg.Whitelist)

	if err := blocklist.Update(store, cfg.Blocklists, cfg.CacheDir); err != nil {
		log.Printf("blocklist update warning: %v", err)
	}

	counter := stats.New()

	fileLog := querylog.NewFileLogger(cfg.LogFile, cfg.LogQueries)

	var db *querylog.DBLogger
	if cfg.QueryDB != "" {
		db, err = querylog.NewDBLogger(cfg.QueryDB, cfg.LogQueries, dbFlushInterval)
		if err != nil {
			log.Printf("[main] SQLite logger disabled: %v", err)
		} else {
			fmt.Printf("[main] query log database: %s\n", cfg.QueryDB)
		}
	}

	var dnsCache *cache.Cache
	if cfg.CacheSize > 0 {
		dnsCache = cache.New(cfg.CacheSize)
		fmt.Printf("[main] DNS response cache: %d entries max\n", cfg.CacheSize)
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
	var reloadMu sync.Mutex
	reloadFn := func() bool {
		if !reloadMu.TryLock() {
			return false
		}
		go func() {
			defer reloadMu.Unlock()
			fmt.Println("[main] refreshing blocklists...")
			blocklist.Update(store, cfg.Blocklists, cfg.CacheDir)
		}()
		return true
	}

	apiServer := api.New(counter, db, store, reloadFn)
	go func() {
		if err := apiServer.ListenAndServe(cfg.APIListen); err != nil {
			log.Printf("[api] server error: %v", err)
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
		fmt.Println("[main] shutting down...")
		counter.Print()
		dnsServer.Shutdown()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		apiServer.Shutdown(ctx)
		if dnsCache != nil {
			dnsCache.Close()
		}
		fileLog.Close()
		if db != nil {
			db.Close()
		}
		os.Exit(0)
	}

	// Signal handler for interactive (non-service) use.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-quit; fmt.Println(); doStop() }()

	// When launched by the Windows SCM, enter the service event loop instead
	// of blocking directly on the DNS server.
	if service.IsWindowsService() {
		if err := service.Run(func() {
			if err := dnsServer.Start(); err != nil {
				log.Printf("[dns] server stopped: %v", err)
			}
		}, doStop); err != nil {
			log.Fatalf("service error: %v", err)
		}
		return
	}

	// Interactive mode: block until the DNS server exits.
	if err := dnsServer.Start(); err != nil {
		log.Fatalf("dns server error: %v", err)
	}
}

// printNetworkHint prints the machine's LAN-facing IPv4 addresses so the user
// knows what to enter in the router's DHCP DNS field.
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

	fmt.Println("[main] ┌─ Router setup ───────────────────────────────────────")
	for _, ip := range lanIPs {
		fmt.Printf("[main] │  DNS server → %s:%s\n", ip, dnsPort)
		fmt.Printf("[main] │  Admin UI   → http://%s:%s\n", ip, apiPort)
	}
	fmt.Println("[main] └──────────────────────────────────────────────────────")
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
func runTicker(d time.Duration, fn func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for range t.C {
		fn()
	}
}
