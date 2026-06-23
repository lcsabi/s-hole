package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/laszlo/s-hole/api"
	"github.com/laszlo/s-hole/blocklist"
	"github.com/laszlo/s-hole/cache"
	"github.com/laszlo/s-hole/config"
	dnsserver "github.com/laszlo/s-hole/dns"
	"github.com/laszlo/s-hole/querylog"
	"github.com/laszlo/s-hole/service"
	"github.com/laszlo/s-hole/stats"
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

	reloadFn := func() {
		fmt.Println("[main] refreshing blocklists...")
		blocklist.Update(store, cfg.Blocklists, cfg.CacheDir)
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
	go runTicker(refreshInterval, reloadFn)

	// doStop is the single shutdown path used by both the signal handler
	// (interactive) and the Windows SCM stop event (service mode).
	doStop := func() {
		fmt.Println("[main] shutting down...")
		counter.Print()
		dnsServer.Shutdown()
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

func runTicker(d time.Duration, fn func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for range t.C {
		fn()
	}
}
