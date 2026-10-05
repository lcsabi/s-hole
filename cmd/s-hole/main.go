// Command s-hole is the network-level DNS sinkhole entry point.
//
// Lifecycle:
//   - install the default slog handler (text by default, JSON when
//     S_HOLE_LOG_FORMAT=json, or the Windows Event Log when launched by the
//     SCM, where stdout is discarded)
//   - parse flags; if -service is set, perform the SCM action and exit
//   - when launched by the Windows SCM, change to the config file's
//     directory, so relative paths resolve next to config.yaml (b/066)
//   - load and validate config (YAML + S_HOLE_* env-var overrides); bail
//     on any duration/enum failure
//   - bind the plain DNS UDP and TCP sockets (dnsserver.Listen); a failure
//     here is fatal, and Shutdown can always close them (b/063)
//   - if dot_listen is set, load the DoT certificate and bind the
//     DNS-over-TLS listener; a failure here is fatal
//   - construct the blocklist store, stats counter, query loggers, DNS
//     response cache, DNS handler, and the DNS server on the bound sockets
//   - construct the single-flight reload closure and the admin API server
//     (which exposes /healthz, /readyz, /metrics, and, opt-in via
//     enable_pprof, /debug/pprof/* alongside the REST API)
//   - launch background tickers for the stats line and the blocklist reload,
//     both panic-recovered
//   - either enter the Windows SCM event loop (service mode) or run the DNS
//     server in the background and block until doStop completes the ordered
//     teardown (interactive mode)
//
// Signals: SIGINT and SIGTERM trigger a clean shutdown. On non-Windows
// builds, SIGHUP triggers a reload (the DoT certificate when DoT is on, then
// the blocklists) through the same single-flight closure used by the
// periodic timer and POST /api/reload. See signals_unix.go.
//
// Shutdown is funnelled through a single doStop closure. Four paths call it:
// the signal handler, the Windows SCM stop control, blockUntilStopped when
// the DNS server fails while s-hole runs (b/064), and the Windows service
// loop when the DNS server returns first (b/065). This keeps the cleanup
// order the same on every path. After a DNS server failure, the process exits
// non-zero once the teardown is done, so the service manager restarts it. An
// in-flight blocklist refresh is waited on (with a 5 s deadline) so the
// atomic rename can complete before the process exits; no new reload pass
// starts once shutdown has begun (b/070).
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lcsabi/s-hole/internal/api"
	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/config"
	"github.com/lcsabi/s-hole/internal/dnsserver"
	"github.com/lcsabi/s-hole/internal/logging"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/service"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/lcsabi/s-hole/internal/version"
)

// setupLogger installs the default slog handler. Format is text by default;
// switch to JSON via S_HOLE_LOG_FORMAT=json for container and log-aggregation
// deployments. Under systemd, stdout is the journal, so each line carries its
// syslog priority and text lines drop the time field (see
// logging.NewStdoutHandler).
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
	json := os.Getenv("S_HOLE_LOG_FORMAT") == "json"
	slog.SetDefault(slog.New(logging.NewStdoutHandler(os.Stdout, json, logging.StdoutIsJournal())))
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
			mainLog.Error("config path cannot be resolved", "err", err)
			os.Exit(1)
		}
		if err := service.Install(absConfig); err != nil {
			mainLog.Error("service install failed", "err", err)
			os.Exit(1)
		}
		return
	case "uninstall":
		if err := service.Uninstall(); err != nil {
			mainLog.Error("service uninstall failed", "err", err)
			os.Exit(1)
		}
		return
	case "start":
		if err := service.Start(); err != nil {
			mainLog.Error("service start failed", "err", err)
			os.Exit(1)
		}
		return
	case "stop":
		if err := service.Stop(); err != nil {
			mainLog.Error("service stop failed", "err", err)
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
		if code := runCheckConfig(mainLog, *cfgPath); code != 0 {
			os.Exit(code)
		}
		return
	}

	// Under the Windows SCM the working directory is C:\Windows\System32, so
	// the sample config's relative query_db and cache_dir, and any relative
	// log_file, put s-hole's files in the system folder (b/066). Change to the config file's
	// directory first, so relative paths resolve next to config.yaml, as they
	// resolve in /var/lib/s-hole under systemd and in /app in Docker.
	// The config is then loaded through its absolute path: a relative -config
	// path such as conf\config.yaml, read again from inside conf, would name
	// conf\conf\config.yaml (b/069).
	if service.IsWindowsService() {
		absCfg, err := chdirToConfigDir(*cfgPath, os.Chdir)
		if err != nil {
			mainLog.Error("working directory change failed", "config", *cfgPath, "err", err)
			os.Exit(1)
		}
		*cfgPath = absCfg
		mainLog.Info("working directory set to the config directory", "dir", filepath.Dir(absCfg))
	}

	cfg, refreshInterval, statsInterval, dbFlushInterval, err := config.LoadAndValidate(*cfgPath)
	if err != nil {
		mainLog.Error("config load failed", "err", err)
		os.Exit(1)
	}

	// Bind the DNS listeners before anything else opens, so a port conflict
	// or a bad listen address exits here with nothing half-built. Binding
	// here, not inside Start, also lets Shutdown always close the sockets
	// (b/063). The failure is fatal, unlike the fail-open admin UI: a resolver
	// that is not listening serves no one, and an enabled DoT listener that
	// did not come up would silently cut off the clients that need it
	// (Android's strict Private DNS mode does not fall back to plain DNS).
	dnsPC, dnsLn, err := dnsserver.Listen(cfg.Listen)
	if err != nil {
		mainLog.Error("dns listen failed", "listen", cfg.Listen, "err", err,
			"hint", "check for another program on the port (often the systemd-resolved stub on port 53), or fix listen")
		os.Exit(1)
	}
	var dotCerts *dnsserver.CertReloader
	var dotLn net.Listener
	if cfg.DoTListen != "" {
		dotCerts, err = dnsserver.NewCertReloader(cfg.TLSCert, cfg.TLSKey)
		if err == nil {
			dotLn, err = dnsserver.ListenDoT(cfg.DoTListen, dotCerts)
		}
		if err != nil {
			mainLog.Error("DoT listener failed", "dot_listen", cfg.DoTListen, "err", err,
				"hint", "check for a port conflict, or fix dot_listen, tls_cert, and tls_key")
			os.Exit(1)
		}
		mainLog.Info("DoT certificate loaded", "cert", cfg.TLSCert, "expires", dotCerts.NotAfter().Format(time.RFC3339))
		warnCertExpiry(mainLog, dotCerts)
	}

	store := blocklist.NewStore()
	store.SetWhitelist(cfg.Whitelist)

	if err := blocklist.Update(store, cfg.Blocklists, cfg.CacheDir, blocklist.CacheFirst); err != nil {
		mainLog.Warn("initial blocklist load failed", "err", err)
	}

	counter := stats.New()

	fileLog := querylog.NewFileLogger(cfg.LogFile, cfg.LogQueries)

	var db *querylog.DBLogger
	if cfg.QueryDB != "" {
		db, err = querylog.NewDBLogger(cfg.QueryDB, cfg.LogQueries, dbFlushInterval, cfg.QueryDBRetentionDays)
		if err != nil {
			mainLog.Warn("query log database open failed", "err", err,
				"hint", "the dashboard history and recent queries stay empty. Check query_db")
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
	handler := dnsserver.NewHandler(store, counter, cfg.Upstreams, logger, cfg.BlockMode, cfg.BlockTTL, dnsCache, cfg.LocalPTR, cfg.QueryPrivacy)
	dnsServer := dnsserver.NewServer(dnsPC, dnsLn, handler)
	if dotLn != nil {
		dnsServer.EnableDoT(dotLn)
	}

	// runCtx is the application-wide lifecycle context. doStop cancels
	// it before tearing down subsystems so the background tickers exit
	// promptly instead of running until os.Exit, and so a queued reload
	// does not start a new pass during shutdown.
	runCtx, runCancel := context.WithCancel(context.Background())

	// reloadFn single-flights reloads across the periodic timer, POST
	// /api/reload, and SIGHUP. A reload re-reads the DoT certificate (when DoT
	// is on) and then refreshes the blocklists. Two concurrent goroutines
	// downloading to the same cache files would race on file writes.
	//
	// reloadFn returns synchronously: true means the reload started, false
	// means a reload is already running and this request is queued behind it
	// (b/061), or that shutdown has started and the request is refused
	// (b/070). The actual download work runs in a background goroutine so
	// callers (including the HTTP handler) return quickly.
	//
	// reloadWG lets doStop wait for any in-flight refresh to complete (or
	// be cancelled by deadline) before the process exits; otherwise the
	// goroutine could be killed mid-rename and leave a half-written
	// cache .tmp file behind.
	var reloadWG sync.WaitGroup
	var certs certReloader
	if dotCerts != nil {
		certs = dotCerts
	}
	reloadFn, stopReloads := newReloadFn(runCtx, mainLog, &reloadWG, reloadWork(mainLog, certs, func() {
		mainLog.Info("refreshing blocklists")
		if err := blocklist.Update(store, cfg.Blocklists, cfg.CacheDir, blocklist.DownloadFirst); err != nil {
			mainLog.Warn("blocklist refresh failed", "err", err)
		}
	}))

	apiServer := api.New(counter, db, store, dnsCache, reloadFn)
	apiServer.SetQueryPrivacy(cfg.QueryPrivacy)
	apiServer.SetClientNames(cfg.ClientNames)
	// Bridge the dnsserver per-upstream transport-failure tracker to /metrics;
	// api does not import dnsserver, so main wires the two.
	apiServer.SetUpstreamTransportFailures(dnsserver.UpstreamTransportFailures)
	if dotCerts != nil {
		apiServer.SetDoTStatus(func() api.DoTStatus {
			st := dotCerts.Status(time.Now())
			return api.DoTStatus{
				Listen:          cfg.DoTListen,
				Names:           st.Names,
				NotAfter:        st.NotAfter,
				State:           st.State,
				LastReload:      st.LastReload,
				LastReloadError: st.LastReloadError,
				ReloadFailures:  st.ReloadFailures,
			}
		})
	}
	if cfg.EnablePprof {
		apiServer.EnablePprof(true)
		mainLog.Warn("pprof endpoints enabled", "api_listen", cfg.APIListen,
			"hint", "the pprof endpoints have no authentication. Set api_listen to a localhost address, or set enable_pprof to false")
	}
	// Bind the admin listener synchronously so a bad api_listen or a port
	// conflict is caught here, in order, before the banner. DNS is the critical
	// service, so a failed admin bind is a WARN and continue (fail-open), not
	// fatal: killing DNS because the optional dashboard could not bind would
	// invert the priority. The banner then reports the admin UI as unavailable
	// instead of advertising a URL that refuses connections (b/052).
	apiUp := false
	if apiLn, err := net.Listen("tcp", cfg.APIListen); err != nil {
		mainLog.Warn("admin UI failed to bind; DNS still serving",
			"api_listen", cfg.APIListen, "err", err,
			"hint", "check for a port conflict or fix api_listen")
	} else {
		apiUp = true
		go func() {
			if err := apiServer.Serve(apiLn); err != nil {
				mainLog.Error("admin UI server failed", "err", err)
			}
		}()
	}

	_, dnsPort, _ := net.SplitHostPort(cfg.Listen)
	var dotPort string
	if dotLn != nil {
		_, dotPort, _ = net.SplitHostPort(cfg.DoTListen)
	}
	apiHost, apiPort, _ := net.SplitHostPort(cfg.APIListen)
	printNetworkHint(dnsPort, dotPort, apiHost, apiPort, apiUp)

	go runTicker(runCtx, statsInterval, counter.Log)
	go runTicker(runCtx, refreshInterval, func() {
		mainLog.Info("reload requested via timer")
		reloadFn()
	})

	// done is closed by doStop after the ordered teardown finishes. The
	// interactive path blocks on it, so the process exits only once shutdown()
	// has run to completion. This makes doStop the sole exit authority and
	// removes the race where dnsServer.Start() returning (unblocked by stopDNS)
	// let main() return before the later teardown steps ran (b/043).
	done := make(chan struct{})

	// doStop is the single shutdown path. The signal handler, the Windows SCM
	// stop control, and a DNS server failure (blockUntilStopped, or Execute
	// under the SCM) all call it. It wires the running subsystems into
	// shutdown(); shutdown() owns the teardown order.
	// stopOnce guards against a second stop request re-running teardown. The
	// old os.Exit(0) made re-entry impossible; without it, guard explicitly.
	var stopOnce sync.Once
	doStop := func() {
		stopOnce.Do(func() {
			shutdown(mainLog, 5*time.Second, shutdownDeps{
				cancelTickers: runCancel,
				logStats:      counter.Log,
				stopDNS:       dnsServer.Shutdown,
				drainHTTP:     apiServer.Shutdown,
				waitForReload: func(ctx context.Context) {
					stopReloads()
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
	// a reload (the DoT certificate when DoT is on, then the blocklists), the
	// conventional "reload config" gesture for long-running daemons.
	// Operators expect `kill -HUP $(pidof s-hole)` to work without needing
	// the admin API enabled.
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
	// which runs the same ordered teardown as the interactive path. If the DNS
	// server fails first, Execute also calls doStop and reports a failure exit
	// code, so the SCM recovery actions restart the service (b/065).
	if service.IsWindowsService() {
		if err := service.Run(func() error {
			err := dnsServer.Start()
			if err != nil {
				mainLog.Error("dns server failed", "err", err)
			}
			return err
		}, doStop); err != nil {
			mainLog.Error("windows service failed", "err", err)
			os.Exit(1)
		}
		return
	}

	// Interactive mode: run the DNS server in the background so doStop, not a
	// returning Start(), owns the exit.
	if code := blockUntilStopped(dnsServer.Start, doStop, done); code != 0 {
		os.Exit(code)
	}
}

// blockUntilStopped runs start (the DNS server) in a goroutine and blocks until
// doStop closes done. It returns the process exit code: 0 on a clean stop, 1
// when a listener failed. The sockets are bound before start runs, so a serve
// error is a runtime failure, not a bind failure. On a serve error it calls
// stop (doStop) and waits for done, so the ordered teardown runs (the query
// log is flushed, an in-flight reload finishes) before the process exits
// non-zero, and systemd's Restart=on-failure restarts it (b/064). A clean
// Shutdown makes start() return nil, which is dropped so it cannot race the
// done signal. Extracted from main so the guarantee "the process exits only
// after shutdown() has fully run" is unit-testable (b/043).
func blockUntilStopped(start func() error, stop func(), done <-chan struct{}) int {
	serveErr := make(chan error, 1)
	go func() {
		if err := start(); err != nil {
			serveErr <- err
		}
	}()
	select {
	case err := <-serveErr:
		slog.With("pkg", "main").Error("dns server failed", "err", err,
			"hint", "s-hole stops and exits 1, so the service manager restarts it. If the error comes back after each restart, see 's-hole stopped while it ran' in docs/TROUBLESHOOTING.md")
		stop()
		<-done
		return 1
	case <-done:
		return 0
	}
}

// printNetworkHint prints the machine's LAN-facing IPv4 addresses so the
// user knows what to enter in the router's DHCP DNS field. Container, VM, and
// VPN interfaces are left out, because a router cannot reach them (see
// lanIPv4s, b/059). The banner is drawn with Unicode box-drawing by default;
// ASCII fallback kicks in when JSON logs are selected or
// S_HOLE_ASCII_BANNER=1 is set, so terminals without a UTF-8 codepage
// (notably the legacy Windows console) and log collectors that don't expect
// prose are not littered with mojibake.
//
// The Admin UI line honors where the API server is actually bound: with
// the localhost-only default, advertising http://<lan-ip>:8080 would be
// a lie (every other device gets connection-refused), so the banner
// points at 127.0.0.1 and says so (T4). When apiUp is false the admin
// listener failed to bind, so the banner says the UI is unavailable rather
// than advertising a URL that refuses connections (b/052). A non-empty
// dotPort adds a DoT line; it names the port and not an address, because a
// DoT client connects by the hostname in the certificate, not by IP.
func printNetworkHint(dnsPort, dotPort, apiHost, apiPort string, apiUp bool) {
	lanIPs := lanIPv4s(systemInterfaces())
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
		if dotPort != "" {
			fmt.Printf("[main] |   DoT        -> port %s (clients connect by the certificate's hostname)\n", dotPort)
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
	if dotPort != "" {
		fmt.Printf("[main] │  DoT        → port %s (clients connect by the certificate's hostname)\n", dotPort)
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

// ifaceAddrs is one network interface as the banner sees it: its name, its
// flags, and its addresses. It is a plain struct so lanIPv4s can be tested
// with fake interfaces.
type ifaceAddrs struct {
	name  string
	flags net.Flags
	addrs []net.Addr
}

// systemInterfaces lists the machine's network interfaces with their
// addresses. An interface whose addresses cannot be read is skipped.
func systemInterfaces() []ifaceAddrs {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]ifaceAddrs, 0, len(ifaces))
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		out = append(out, ifaceAddrs{name: ifc.Name, flags: ifc.Flags, addrs: addrs})
	}
	return out
}

// virtualIfacePrefixes names interfaces that a router cannot reach: container
// and VM bridges (Docker, libvirt, VirtualBox and VMware host-only networks,
// LXC/LXD/Incus, Podman, Kubernetes network plugins) and VPN tunnels. Their
// addresses are often private (Docker's docker0 is 172.17.0.1), so an
// address-range check cannot tell them from a real LAN interface, but the name
// can (b/059). "br-" keeps its hyphen: it matches Docker's br-<id> networks,
// not a real LAN bridge such as br0. Keep this list in step with lan_ipv4s in
// deploy/install-linux.sh, which filters the installer's banner the same way.
var virtualIfacePrefixes = []string{
	"docker", "br-", "veth", "virbr", "vboxnet", "vmnet", "lxcbr", "lxdbr",
	"incusbr", "podman", "cni", "flannel", "cali", "vxlan", "tailscale", "wg",
	"zt", "tun", "tap",
}

func isVirtualIface(name string) bool {
	name = strings.ToLower(name)
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// lanIPv4s returns the IPv4 addresses the banner offers as the router's DNS
// server: addresses on interfaces that are up and are not loopback, not
// link-local, and not a container, VM, or VPN interface. It only chooses what
// the banner prints; s-hole still listens on every address its listen
// setting covers.
func lanIPv4s(ifaces []ifaceAddrs) []string {
	var ips []string
	for _, ifc := range ifaces {
		if ifc.flags&net.FlagUp == 0 || ifc.flags&net.FlagLoopback != 0 || isVirtualIface(ifc.name) {
			continue
		}
		for _, a := range ifc.addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ips = append(ips, ip.String())
		}
	}
	return ips
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
// for the stats log line and the periodic reload. doStop
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
			slog.With("pkg", "main").Error("ticker fn panic recovered",
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

// chdirToConfigDir changes the working directory to the directory that holds
// cfgPath and returns the absolute config path. The caller loads the config
// through that path, because a relative cfgPath no longer names the file once
// the working directory has changed (b/069). main passes os.Chdir; a test
// passes a fake, so the Windows-service path is testable on any platform.
func chdirToConfigDir(cfgPath string, chdir func(string) error) (string, error) {
	abs, err := filepath.Abs(cfgPath)
	if err != nil {
		return "", err
	}
	if err := chdir(filepath.Dir(abs)); err != nil {
		return "", err
	}
	return abs, nil
}

// runCheckConfig is the -check-config dry run: it loads and validates the
// config the way startup does and returns the process exit code. Validate has
// already proved that a DoT certificate loads, but an expired certificate
// still loads, so the dry run also prints the same expiry WARN as startup.
// That is a warning, not a failure: startup would run with the certificate
// too, and the dry run mirrors startup.
func runCheckConfig(log *slog.Logger, path string) int {
	cfg, _, _, _, err := config.LoadAndValidate(path)
	if err != nil {
		log.Error("config load failed", "err", err)
		return 1
	}
	if cfg.DoTListen != "" {
		if certs, err := dnsserver.NewCertReloader(cfg.TLSCert, cfg.TLSKey); err == nil {
			warnCertExpiry(log, certs)
		}
	}
	log.Info("config OK", "path", path)
	return 0
}

// certReloader is the part of *dnsserver.CertReloader the reload path uses.
// It is an interface so tests can inject a reloader that fails.
type certReloader interface {
	Reload() error
	NotAfter() time.Time
	ExpiryWarning(now time.Time) (msg, hint string)
}

// reloadWork returns the body of one reload: re-read the DoT certificate
// when certs is non-nil (DoT is on), then run refresh (the blocklist
// download). The certificate goes first because it is fast and local. A
// failed certificate reload keeps the current certificate and does not skip
// the blocklist refresh.
func reloadWork(log *slog.Logger, certs certReloader, refresh func()) func() {
	return func() {
		if certs != nil {
			if err := certs.Reload(); err != nil {
				log.Warn("DoT certificate reload failed; keeping the current certificate", "err", err)
			} else {
				log.Info("DoT certificate reloaded", "expires", certs.NotAfter().Format(time.RFC3339))
				warnCertExpiry(log, certs)
			}
		}
		refresh()
	}
}

// warnCertExpiry logs a WARN when the DoT certificate has expired or expires
// soon, so a failed renewal shows up in the log before clients reject it.
func warnCertExpiry(log *slog.Logger, certs certReloader) {
	if msg, hint := certs.ExpiryWarning(time.Now()); msg != "" {
		log.Warn(msg, "expires", certs.NotAfter().Format(time.RFC3339), "hint", hint)
	}
}

// newReloadFn builds the single-flight reload closure shared by the
// periodic timer, POST /api/reload, and SIGHUP. It returns true if no reload
// was running and it started one (asynchronously, so callers return at once).
// It returns false if a reload is already running; the request is then queued,
// and the running reload does one more pass when it finishes. Any number of
// requests during one pass queue a single follow-up pass.
//
// Only one pass runs at a time, so the three callers never launch concurrent
// downloads that would race on the cache files. Keeping this state in one
// closure, not in api.Server, is what prevents the periodic timer from
// bypassing the gate (b/022). The queue exists because a request that arrives
// mid-pass may need work that the pass already did: a certbot deploy hook
// that runs `systemctl reload` during a blocklist download installed the new
// certificate after the pass read the old one. A dropped request left the old
// certificate served until the next timer reload (b/061).
//
// Once ctx is cancelled (shutdown has started) or stop has run, a queued pass
// is dropped and a new request starts no pass, so the bounded reload wait in shutdown covers at
// most the pass in flight (b/070). A new request then returns false.
//
// wg lets doStop wait for an in-flight refresh to finish its os.Rename before
// the process exits, so a refresh is never killed mid-write. The returned stop
// function closes the gate under the same mutex that guards wg.Add. shutdown
// calls it before wg.Wait, so every wg.Add happens before that Wait, and no
// request after it starts a pass. The ctx check alone does not give that
// order, because cancel does not take the mutex.
func newReloadFn(ctx context.Context, log *slog.Logger, wg *sync.WaitGroup, work func()) (reload func() bool, stop func()) {
	var mu sync.Mutex // guards running, queued, and closed
	var running, queued, closed bool
	stop = func() {
		mu.Lock()
		closed = true
		mu.Unlock()
	}
	reload = func() bool {
		mu.Lock()
		defer mu.Unlock()
		if closed || ctx.Err() != nil {
			log.Info("reload refused during shutdown")
			return false
		}
		if running {
			if !queued {
				log.Info("reload queued until the running reload ends")
			}
			queued = true
			return false
		}
		running = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				work()
				// Check and clear the queue under the same lock that callers
				// take, so a request that arrives after this check sees
				// running == false and starts its own pass: none is lost.
				mu.Lock()
				again := queued && !closed && ctx.Err() == nil
				queued = false
				if !again {
					running = false
				}
				mu.Unlock()
				if !again {
					return
				}
				log.Info("queued reload started")
			}
		}()
		return true
	}
	return reload, stop
}

// shutdownDeps holds the teardown actions so the order in shutdown() can be
// tested. main wires the real subsystems; a test injects recorders to assert
// the sequence.
type shutdownDeps struct {
	cancelTickers func()                      // stop scheduling new refresh/stats work
	logStats      func()                      // final stats line
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
	d.logStats()
	d.stopDNS()
	// Separate timeout budgets. A shared context let a slow HTTP drain eat into
	// the reload wait; the reload wait protects an in-flight refresh from being
	// killed mid os.Rename (R53), so it must get its full budget regardless of
	// how long the drain took.
	hctx, hcancel := context.WithTimeout(context.Background(), timeout)
	if err := d.drainHTTP(hctx); err != nil {
		log.Warn("admin UI shutdown failed", "err", err)
	}
	hcancel()
	rctx, rcancel := context.WithTimeout(context.Background(), timeout)
	d.waitForReload(rctx)
	rcancel()
	d.closeCache()
	if err := d.closeFileLog(); err != nil {
		log.Warn("query file log close failed", "err", err)
	}
	if err := d.closeDB(); err != nil {
		log.Warn("query log database close failed", "err", err)
	}
}
