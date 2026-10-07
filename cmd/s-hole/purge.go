package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/lcsabi/s-hole/internal/api"
	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/config"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
)

// purgeTargets are the stores a purge reaches in a running s-hole. db,
// fileLog, and dnsCache are nil when that store is off; resetGraph empties
// the per-minute graph (stats.Counter.ResetTimeline).
type purgeTargets struct {
	cfg        *config.Config
	db         *querylog.DBLogger
	fileLog    *querylog.FileLogger
	counter    *stats.Counter
	dnsCache   *cache.Cache
	resetGraph func()
}

// purge deletes everything a running s-hole has written: the query database
// rows, the query log file, the downloaded blocklists, the Top Domains and
// Top Clients lists, the per-minute graph, and the DNS response cache. It
// keeps the allowlist, which is configuration, not history, and the
// since-start counters (see stats.Counter.ResetTallies). It reports each
// step; a failed step does not stop the others.
func (t purgeTargets) purge(ctx context.Context) api.PurgeReport {
	var rep api.PurgeReport
	add := func(what, result string, failed bool) {
		rep.Steps = append(rep.Steps, api.PurgeStep{What: what, Result: result, Failed: failed})
	}

	if t.db == nil {
		add("query database", "off, nothing stored", false)
	} else if err := t.db.Purge(ctx); err != nil {
		add("query database", "delete failed: "+err.Error(), true)
	} else {
		add("query database", "every row deleted and the file rewritten", false)
	}

	if t.fileLog == nil {
		add("query log file", "off, nothing stored", false)
	} else {
		err := t.fileLog.Purge(ctx)
		switch {
		case errors.Is(err, querylog.ErrStdoutNotPurgeable):
			add("query log output", journalNote, false)
		case err != nil:
			add("query log file", "empty failed: "+err.Error(), true)
		default:
			add("query log file", "emptied", false)
		}
	}

	n, err := blocklist.PurgeCache(t.cfg.Blocking.CacheDir)
	if err != nil {
		add("downloaded blocklists", fmt.Sprintf("%d files deleted, then: %v", n, err), true)
	} else {
		add("downloaded blocklists", strconv.Itoa(n)+" files deleted; the next reload downloads them again", false)
	}

	t.counter.ResetTallies()
	add("Top Domains and Top Clients", "emptied", false)
	if t.resetGraph != nil {
		t.resetGraph()
		add("per-minute graph", "emptied", false)
	}
	if t.dnsCache != nil {
		t.dnsCache.Flush()
		add("DNS response cache", "emptied", false)
	}
	if t.cfg.QueryLog.Mode == config.ModeAll {
		add("system log", "s-hole cannot delete its own log lines. With query_log.mode \"all\", a warning line can name a domain", false)
	}
	return rep
}

// journalNote says what s-hole cannot delete when query lines went to
// standard output.
const journalNote = "query lines went to standard output (the system journal or the container log), which s-hole cannot change. " +
	"To delete them, clear the journal (journalctl --rotate && journalctl --vacuum-time=1s, which deletes the logs of every service) " +
	"or recreate the container"

// errNotRunning means no s-hole answered on the admin address.
var errNotRunning = errors.New("s-hole is not running")

// runPurge is `s-hole -purge`: it deletes the query history and everything
// else s-hole wrote. When s-hole is running, it asks that process to purge
// through the admin API, so the data in memory goes too. When s-hole is not
// running, it deletes the files itself. It prints a summary and returns the
// exit code.
func runPurge(log *slog.Logger, path string) int {
	cfg, problems, err := config.Load(path)
	logConfigProblems(log, problems)
	if err != nil {
		log.Error("config load failed", "err", err)
		return 1
	}
	rep, err := purgeViaAPI(cfg.Admin.Listen)
	switch {
	case err == nil:
		fmt.Println("The running s-hole deleted its stored data:")
	case errors.Is(err, errNotRunning):
		var notFound bool
		rep, notFound = purgeOffline(cfg)
		fmt.Println("s-hole is not running. Deleted the files it stores:")
		defer func() {
			if notFound {
				fmt.Println("A file was not found. Relative paths in the config start in the current directory.")
				fmt.Println("If s-hole keeps its files in another directory, run the purge again from there")
				fmt.Println("(/var/lib/s-hole after the Linux installer).")
			}
		}()
	default:
		log.Error("purge failed", "err", err)
		return 1
	}
	for _, s := range rep.Steps {
		mark := "ok"
		if s.Failed {
			mark = "FAILED"
		}
		fmt.Printf("  %-28s %-6s %s\n", s.What, mark, s.Result)
	}
	if rep.Failed() {
		return 1
	}
	return 0
}

// purgeViaAPI posts the purge request to a running s-hole. It returns
// errNotRunning when nothing listens on the admin address.
func purgeViaAPI(adminListen string) (api.PurgeReport, error) {
	addr, err := localAdminAddr(adminListen)
	if err != nil {
		return api.PurgeReport{}, err
	}
	url := "http://" + addr + "/api/purge"
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader([]byte(`{"confirm": true}`)))
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return api.PurgeReport{}, errNotRunning
		}
		return api.PurgeReport{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var rep api.PurgeReport
	if err := json.Unmarshal(body, &rep); err != nil || len(rep.Steps) == 0 {
		return api.PurgeReport{}, fmt.Errorf("the running s-hole refused the purge: %s %s", resp.Status, bytes.TrimSpace(body))
	}
	return rep, nil
}

// purgeOffline deletes the stored files of an s-hole that is not running:
// the query database with its -wal and -shm files, the query log file, and
// the downloaded blocklists. A configured file that does not exist is
// reported as "not found" with its absolute path, and notFound is true: a
// relative path resolves against the current directory, so a purge run from
// the wrong directory must not claim that it deleted the history (b/091).
func purgeOffline(cfg *config.Config) (rep api.PurgeReport, notFound bool) {
	add := func(what, result string, failed bool) {
		rep.Steps = append(rep.Steps, api.PurgeStep{What: what, Result: result, Failed: failed})
	}
	// remove deletes paths and reports whether any of them existed.
	remove := func(paths ...string) (bool, error) {
		found := false
		for _, p := range paths {
			err := os.Remove(p)
			switch {
			case err == nil:
				found = true
			case !errors.Is(err, fs.ErrNotExist):
				return found, err
			}
		}
		return found, nil
	}
	missing := func(what, path string) {
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		add(what, "not found at "+path, false)
		notFound = true
	}

	if db := cfg.QueryLog.Database; db == "" {
		add("query database", "off, nothing stored", false)
	} else if found, err := remove(db, db+"-wal", db+"-shm"); err != nil {
		add("query database", "delete failed: "+err.Error(), true)
	} else if !found {
		missing("query database", db)
	} else {
		add("query database", "files deleted", false)
	}

	switch f := cfg.QueryLog.File; f {
	case "":
		add("query log file", "off, nothing stored", false)
	case config.FileStdout:
		add("query log output", journalNote, false)
	default:
		if found, err := remove(f); err != nil {
			add("query log file", "delete failed: "+err.Error(), true)
		} else if !found {
			missing("query log file", f)
		} else {
			add("query log file", "deleted", false)
		}
	}

	n, err := blocklist.PurgeCache(cfg.Blocking.CacheDir)
	switch {
	case err != nil:
		add("downloaded blocklists", fmt.Sprintf("%d files deleted, then: %v", n, err), true)
	case n == 0 && len(cfg.Blocking.Lists) > 0:
		missing("downloaded blocklists", cfg.Blocking.CacheDir)
	default:
		add("downloaded blocklists", strconv.Itoa(n)+" files deleted", false)
	}
	return rep, notFound
}

// localAdminAddr is the address a command on the s-hole host uses to reach
// the admin server: admin.listen, with a wildcard host (":8080",
// "0.0.0.0:8080", "[::]:8080") replaced by 127.0.0.1.
func localAdminAddr(adminListen string) (string, error) {
	host, port, err := net.SplitHostPort(adminListen)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

// runHealthcheck is `s-hole -healthcheck`, the Docker HEALTHCHECK command: it
// asks the running s-hole for /readyz on the admin address and returns 0 when
// s-hole is ready (the block set is loaded), 1 otherwise. It prints one line
// and no log lines, because Docker keeps the output of each check.
func runHealthcheck(path string) int {
	cfg, _, err := config.Load(path)
	if err != nil {
		fmt.Println("unhealthy: config:", err)
		return 1
	}
	addr, err := localAdminAddr(cfg.Admin.Listen)
	if err != nil {
		fmt.Println("unhealthy: admin.listen:", err)
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/readyz")
	if err != nil {
		fmt.Println("unhealthy:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println("unhealthy: /readyz answered", resp.Status)
		return 1
	}
	fmt.Println("healthy")
	return 0
}
