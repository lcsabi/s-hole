package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/api"
	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/config"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// jsonLog is a slog.Logger that writes JSON lines to a buffer, with a parser
// for the lines.
type jsonLog struct{ buf bytes.Buffer }

func (j *jsonLog) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(&j.buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func (j *jsonLog) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(j.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

func (j *jsonLog) count(t *testing.T, level, msg string) int {
	t.Helper()
	n := 0
	for _, r := range j.records(t) {
		if r["level"] == level && r["msg"] == msg {
			n++
		}
	}
	return n
}

// clearSholeEnv unsets every S_HOLE_* variable for the test, so config.Load
// sees only the file.
func clearSholeEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "S_HOLE_") {
			t.Setenv(name, "")
			os.Unsetenv(name)
		}
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunCheckConfig_ProblemsAndWarnings(t *testing.T) {
	// M1: each config problem is a WARN "config problem", then an ERROR
	// "config has problems", and the exit code is 1. A setting less private
	// than its default is a WARN "privacy warning" and does not fail.
	// Success logs "config OK" with admin_listen.
	clearSholeEnv(t)
	cases := []struct {
		name          string
		body          string
		code          int
		problems      int
		privacy       int
		ok            bool
		adminListen   string
		hasProblemErr bool
	}{
		{"defaults", "", 0, 0, 0, true, "127.0.0.1:8080", false},
		{"less private settings", "query_log:\n  mode: all\n  clients: full\nadmin:\n  listen: \"0.0.0.0:8080\"\n", 0, 0, 3, true, "0.0.0.0:8080", false},
		{"problems", "bogus: 1\nblocking:\n  reply: zero\n", 1, 2, 0, false, "", true},
		{"problems and warnings", "log_queries: all\nquery_log:\n  mode: blocked\n", 1, 1, 1, false, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var j jsonLog
			code := runCheckConfig(j.logger(), writeConfig(t, tc.body))
			if code != tc.code {
				t.Errorf("exit code = %d, want %d\n%s", code, tc.code, j.buf.String())
			}
			if n := j.count(t, "WARN", "config problem"); n != tc.problems {
				t.Errorf("config problem lines = %d, want %d", n, tc.problems)
			}
			if n := j.count(t, "WARN", "privacy warning"); n != tc.privacy {
				t.Errorf("privacy warning lines = %d, want %d\n%s", n, tc.privacy, j.buf.String())
			}
			if n := j.count(t, "ERROR", "config has problems"); (n == 1) != tc.hasProblemErr || n > 1 {
				t.Errorf("config has problems lines = %d, want %v", n, tc.hasProblemErr)
			}
			okLines := 0
			for _, r := range j.records(t) {
				if r["msg"] == "config OK" {
					okLines++
					if r["admin_listen"] != tc.adminListen {
						t.Errorf("config OK admin_listen = %v, want %s", r["admin_listen"], tc.adminListen)
					}
				}
			}
			if (okLines == 1) != tc.ok {
				t.Errorf("config OK lines = %d, want ok=%v", okLines, tc.ok)
			}
		})
	}
	var j jsonLog
	if code := runCheckConfig(j.logger(), writeConfig(t, "dns: [\n")); code != 1 || j.count(t, "ERROR", "config load failed") != 1 {
		t.Errorf("invalid YAML: exit %d\n%s", code, j.buf.String())
	}
}

func TestFileKind(t *testing.T) {
	// M6: query_log.file as the dashboard shows it.
	for in, want := range map[string]string{"": "off", "stdout": "stdout", "q.log": "file", "/var/log/s-hole/queries.log": "file"} {
		if got := fileKind(in); got != want {
			t.Errorf("fileKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildMultiLogger_NeitherOutputRecordsNothing(t *testing.T) {
	// M6: with no file and no database the logger records nothing, and
	// calling it is safe.
	l := buildMultiLogger(nil, nil)
	if l == nil {
		t.Fatal("buildMultiLogger(nil, nil) = nil, want a logger that records nothing")
	}
	out := captureStdout(t, func() {
		l.Log(querylog.Record{ClientIP: "192.168.1.5", Domain: "example.com.", Blocked: true})
	})
	if out != "" {
		t.Errorf("the empty logger wrote %q", out)
	}
	if m, ok := l.(*querylog.Multi); !ok || m == nil {
		t.Errorf("buildMultiLogger(nil, nil) = %T, want an empty *querylog.Multi", l)
	}
	db, err := querylog.NewDBLogger(filepath.Join(t.TempDir(), "q.db"), "all", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := buildMultiLogger(nil, db); got != querylog.Logger(db) {
		t.Errorf("buildMultiLogger(nil, db) = %T, want the database logger", got)
	}
}

func TestNewFileLogger_OffAndOpenFailure(t *testing.T) {
	// Q2 and b/079 at startup: query_log.file off gives no logger, and a file
	// that cannot be opened gives no logger and a WARN, never standard output.
	var j jsonLog
	if fl := newFileLogger(j.logger(), config.QueryLog{File: "", Mode: "all"}); fl != nil {
		fl.Close()
		t.Error("newFileLogger with the file off returned a logger")
	}
	var fl *querylog.FileLogger
	out := captureStdout(t, func() {
		fl = newFileLogger(j.logger(), config.QueryLog{File: filepath.Join(t.TempDir(), "missing", "q.log"), Mode: "all"})
	})
	if fl != nil {
		fl.Close()
		t.Error("newFileLogger with a missing directory returned a logger")
	}
	if out != "" {
		t.Errorf("standard output got %q", out)
	}
	if j.count(t, "WARN", "query log file open failed; query lines are not written") != 1 {
		t.Errorf("no WARN for the open failure:\n%s", j.buf.String())
	}
}

// purgeFixture is a running s-hole's stores with data in each.
type purgeFixture struct {
	targets  purgeTargets
	dbPath   string
	logPath  string
	cacheDir string
	q        dns.Question
	graph    *atomic.Int64
	closeDB  func() // closes the database once; the cleanup calls it too
}

func newPurgeFixture(t *testing.T, mode string) *purgeFixture {
	t.Helper()
	dir := t.TempDir()
	f := &purgeFixture{
		dbPath:   filepath.Join(dir, "q.db"),
		logPath:  filepath.Join(dir, "q.log"),
		cacheDir: filepath.Join(dir, "cache"),
		q:        dns.Question{Name: "cached.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		graph:    new(atomic.Int64),
	}
	if err := os.Mkdir(f.cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"blocklist_a.txt", "blocklist_b.txt.tmp", "keep.txt"} {
		if err := os.WriteFile(filepath.Join(f.cacheDir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	db, err := querylog.NewDBLogger(f.dbPath, "all", 10*time.Millisecond, 0)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	f.closeDB = func() { once.Do(func() { db.Close() }) }
	t.Cleanup(f.closeDB)
	db.Log(querylog.Record{ClientIP: "192.168.1.5", Domain: "visited.example."})
	deadline := time.Now().Add(2 * time.Second)
	for {
		rows, _ := db.Recent(context.Background(), 5)
		if len(rows) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the database row was not written")
		}
		time.Sleep(5 * time.Millisecond)
	}
	fl, err := querylog.NewFileLogger(f.logPath, "all")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fl.Close() })
	fl.Log(querylog.Record{ClientIP: "192.168.1.5", Domain: "visited.example."})
	counter := stats.New()
	counter.RecordQuery("192.168.1.5", "ads.example.", true)
	c := cache.New(10)
	t.Cleanup(c.Close)
	resp := new(dns.Msg)
	resp.Question = []dns.Question{f.q}
	resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: f.q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(1, 2, 3, 4)}}
	c.Set(cacheQuery(f.q), resp)

	cfg := &config.Config{}
	cfg.Blocking.CacheDir = f.cacheDir
	cfg.QueryLog.Mode = mode
	f.targets = purgeTargets{cfg: cfg, db: db, fileLog: fl, counter: counter, dnsCache: c, resetGraph: func() { f.graph.Add(1) }}
	return f
}

func stepByWhat(rep api.PurgeReport) map[string]api.PurgeStep {
	m := map[string]api.PurgeStep{}
	for _, s := range rep.Steps {
		m[s.What] = s
	}
	return m
}

func TestPurgeTargets_PurgesEveryStore(t *testing.T) {
	// M2: the purge reports a step for each store and empties each one: the
	// database, the log file, the downloaded blocklists, the Top lists, the
	// graph, and the DNS cache. Under mode "all" it adds a system-log note.
	f := newPurgeFixture(t, "all")
	rep := f.targets.purge(context.Background())
	if rep.Failed() {
		t.Fatalf("purge failed: %+v", rep)
	}
	steps := stepByWhat(rep)
	for _, what := range []string{"query database", "query log file", "downloaded blocklists", "Top Domains and Top Clients", "per-minute graph", "DNS response cache", "system log"} {
		if _, ok := steps[what]; !ok {
			t.Errorf("no %q step in %+v", what, rep.Steps)
		}
	}
	if !strings.Contains(steps["downloaded blocklists"].Result, "2 files") {
		t.Errorf("blocklist step = %q, want 2 files", steps["downloaded blocklists"].Result)
	}
	if rows, _ := f.targets.db.Recent(context.Background(), 5); len(rows) != 0 {
		t.Errorf("database rows after purge = %d, want 0", len(rows))
	}
	if b, _ := os.ReadFile(f.logPath); len(b) != 0 {
		t.Errorf("log file after purge = %q, want empty", b)
	}
	if _, err := os.Stat(filepath.Join(f.cacheDir, "keep.txt")); err != nil {
		t.Errorf("the purge deleted a file that is not a blocklist: %v", err)
	}
	for _, name := range []string{"blocklist_a.txt", "blocklist_b.txt.tmp"} {
		if _, err := os.Stat(filepath.Join(f.cacheDir, name)); !os.IsNotExist(err) {
			t.Errorf("%s still exists", name)
		}
	}
	if s := f.targets.counter.Snapshot(10); len(s.TopClients) != 0 || len(s.TopDomains) != 0 || s.TotalQueries != 1 {
		t.Errorf("stats after purge = %+v, want empty Top lists and the counters kept", s)
	}
	if f.graph.Load() != 1 {
		t.Errorf("graph reset %d times, want 1", f.graph.Load())
	}
	if _, ok := f.targets.dnsCache.Get(cacheQuery(f.q)); ok {
		t.Error("the DNS cache still answers after the purge")
	}
}

func TestPurgeTargets_SystemLogNoteOnlyUnderModeAll(t *testing.T) {
	// M2: the system-log note appears only under mode "all".
	for _, mode := range []string{"none", "blocked"} {
		f := newPurgeFixture(t, mode)
		if _, ok := stepByWhat(f.targets.purge(context.Background()))["system log"]; ok {
			t.Errorf("mode %q: purge has a system log note", mode)
		}
	}
}

func TestPurgeTargets_FailedStepDoesNotStopTheRest(t *testing.T) {
	// M2: a failed step is marked failed, and the steps after it still run.
	f := newPurgeFixture(t, "blocked")
	f.closeDB() // the database purge now fails
	rep := f.targets.purge(context.Background())
	if !rep.Failed() || !stepByWhat(rep)["query database"].Failed {
		t.Fatalf("report = %+v, want the database step failed", rep)
	}
	for _, what := range []string{"query log file", "downloaded blocklists", "Top Domains and Top Clients", "per-minute graph", "DNS response cache"} {
		if s, ok := stepByWhat(rep)[what]; !ok || s.Failed {
			t.Errorf("step %q = %+v (present %v), want it done", what, s, ok)
		}
	}
	if _, err := os.Stat(filepath.Join(f.cacheDir, "blocklist_a.txt")); !os.IsNotExist(err) {
		t.Error("the blocklist files were not deleted after the failed step")
	}
	if _, ok := f.targets.dnsCache.Get(cacheQuery(f.q)); ok {
		t.Error("the DNS cache was not emptied after the failed step")
	}
}

func TestPurgeTargets_StoresOffAndStdout(t *testing.T) {
	// M2: a store that is off is reported as such, not as a failure, and
	// lines on standard output get a note that s-hole cannot delete them.
	cfg := &config.Config{}
	cfg.Blocking.CacheDir = t.TempDir()
	cfg.QueryLog.Mode = "none"
	rep := purgeTargets{cfg: cfg, counter: stats.New()}.purge(context.Background())
	steps := stepByWhat(rep)
	if rep.Failed() || !strings.Contains(steps["query database"].Result, "off") || !strings.Contains(steps["query log file"].Result, "off") {
		t.Errorf("report = %+v, want the database and the file reported off", rep)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	fl, err := querylog.NewFileLogger("stdout", "all")
	os.Stdout = orig
	if err != nil {
		t.Fatal(err)
	}
	rep = purgeTargets{cfg: cfg, counter: stats.New(), fileLog: fl}.purge(context.Background())
	fl.Close()
	w.Close()
	r.Close()
	s, ok := stepByWhat(rep)["query log output"]
	if !ok || s.Failed || !strings.Contains(s.Result, "standard output") {
		t.Errorf("stdout step = %+v (present %v), want a note that is not a failure", s, ok)
	}
}

func TestLocalAdminAddr(t *testing.T) {
	// M2: a wildcard admin host is reached at 127.0.0.1.
	cases := map[string]string{
		":8080":            "127.0.0.1:8080",
		"0.0.0.0:8080":     "127.0.0.1:8080",
		"[::]:8080":        "127.0.0.1:8080",
		"127.0.0.1:9090":   "127.0.0.1:9090",
		"192.168.1.2:8080": "192.168.1.2:8080",
		"[::1]:8080":       "[::1]:8080",
		"localhost:8080":   "localhost:8080",
	}
	for in, want := range cases {
		if got, err := localAdminAddr(in); err != nil || got != want {
			t.Errorf("localAdminAddr(%q) = (%q, %v), want %q", in, got, err, want)
		}
	}
	if _, err := localAdminAddr("8080"); err == nil {
		t.Error("localAdminAddr(\"8080\") = nil error")
	}
}

// adminServer runs a real admin server on a loopback port and returns its
// address.
func adminServer(t *testing.T, store *blocklist.Store, purge func(context.Context) api.PurgeReport) string {
	t.Helper()
	s := api.New(stats.New(), nil, store, nil, func() bool { return true })
	if purge != nil {
		s.SetPurge(purge)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		s.Serve(ln)
		close(done)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.Shutdown(ctx)
		<-done
	})
	return ln.Addr().String()
}

// closedAddr returns a loopback address that nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// storedFiles creates a query database with its -wal and -shm files, a log
// file, and a downloaded blocklist, and returns a config that names them.
func storedFiles(t *testing.T, adminListen, file string) (cfgPath string, paths []string, cacheDir string) {
	t.Helper()
	dir := t.TempDir()
	cacheDir = filepath.Join(dir, "cache")
	if err := os.Mkdir(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "q.db")
	paths = []string{db, db + "-wal", db + "-shm", filepath.Join(cacheDir, "blocklist_a.txt")}
	if file != "stdout" {
		file = filepath.Join(dir, "q.log")
		paths = append(paths, file)
	}
	for _, p := range paths {
		if err := os.WriteFile(p, []byte("visited.example"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	body := "query_log:\n  mode: all\n  database: \"" + db + "\"\n  file: \"" + file + "\"\n" +
		"blocking:\n  cache_dir: \"" + cacheDir + "\"\nadmin:\n  listen: \"" + adminListen + "\"\n"
	return writeConfig(t, body), paths, cacheDir
}

func TestRunPurge_ThroughTheRunningSHole(t *testing.T) {
	// M2: when an s-hole answers on the admin address, runPurge asks it to
	// purge through the API, and it does not touch the files itself.
	clearSholeEnv(t)
	var calls atomic.Int64
	addr := adminServer(t, blocklist.NewStore(), func(context.Context) api.PurgeReport {
		calls.Add(1)
		return api.PurgeReport{Steps: []api.PurgeStep{{What: "query database", Result: "every row deleted"}}}
	})
	cfgPath, paths, _ := storedFiles(t, addr, "q.log")
	var j jsonLog
	var code int
	out := captureStdout(t, func() { code = runPurge(j.logger(), cfgPath) })
	if code != 0 || calls.Load() != 1 {
		t.Fatalf("exit %d, API purges %d; want 0 and 1\n%s\n%s", code, calls.Load(), out, j.buf.String())
	}
	if !strings.Contains(out, "running s-hole") || !strings.Contains(out, "every row deleted") {
		t.Errorf("output = %q, want the running s-hole's report", out)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("runPurge deleted %s itself although s-hole runs", filepath.Base(p))
		}
	}
}

func TestRunPurge_RunningSHoleReportsFailure(t *testing.T) {
	// M2: a failed step in the running s-hole's report gives exit code 1.
	clearSholeEnv(t)
	addr := adminServer(t, blocklist.NewStore(), func(context.Context) api.PurgeReport {
		return api.PurgeReport{Steps: []api.PurgeStep{{What: "query database", Result: "delete failed", Failed: true}}}
	})
	cfgPath, _, _ := storedFiles(t, addr, "q.log")
	var j jsonLog
	var code int
	out := captureStdout(t, func() { code = runPurge(j.logger(), cfgPath) })
	if code != 1 || !strings.Contains(out, "FAILED") {
		t.Errorf("exit %d, output %q; want 1 and a FAILED step", code, out)
	}
}

func TestRunPurge_RunningSHoleRefuses(t *testing.T) {
	// M2: when the running s-hole answers but refuses, runPurge fails and
	// does not delete the files behind the running process.
	clearSholeEnv(t)
	addr := adminServer(t, blocklist.NewStore(), nil) // no purge function: 503
	cfgPath, paths, _ := storedFiles(t, addr, "q.log")
	var j jsonLog
	var code int
	captureStdout(t, func() { code = runPurge(j.logger(), cfgPath) })
	if code != 1 || j.count(t, "ERROR", "purge failed") != 1 {
		t.Errorf("exit %d; want 1 with a purge failed ERROR\n%s", code, j.buf.String())
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("runPurge deleted %s although s-hole answered", filepath.Base(p))
		}
	}
}

func TestRunPurge_NotRunningDeletesFiles(t *testing.T) {
	// M2: when the connection is refused, runPurge deletes the database with
	// its -wal and -shm files, the log file, and the downloaded blocklists.
	clearSholeEnv(t)
	cfgPath, paths, _ := storedFiles(t, closedAddr(t), "q.log")
	var j jsonLog
	var code int
	out := captureStdout(t, func() { code = runPurge(j.logger(), cfgPath) })
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s\n%s", code, out, j.buf.String())
	}
	if !strings.Contains(out, "not running") {
		t.Errorf("output = %q, want it to say s-hole is not running", out)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists", filepath.Base(p))
		}
	}
}

func TestRunPurge_NotRunningStdoutNote(t *testing.T) {
	// M2: with query lines on standard output, the offline purge says those
	// lines cannot be deleted, and it still deletes the rest.
	clearSholeEnv(t)
	cfgPath, paths, _ := storedFiles(t, closedAddr(t), "stdout")
	var j jsonLog
	var code int
	out := captureStdout(t, func() { code = runPurge(j.logger(), cfgPath) })
	if code != 0 || !strings.Contains(out, "standard output") || !strings.Contains(out, "cannot") {
		t.Errorf("exit %d, output %q; want 0 and a note about standard output", code, out)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists", filepath.Base(p))
		}
	}
}

func TestRunPurge_NotRunningReportsFailure(t *testing.T) {
	// M2: an offline step that fails is shown as FAILED and gives exit 1.
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix directory permissions and a user other than root")
	}
	clearSholeEnv(t)
	cfgPath, _, cacheDir := storedFiles(t, closedAddr(t), "q.log")
	if err := os.Chmod(cacheDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cacheDir, 0o700) })
	var j jsonLog
	var code int
	out := captureStdout(t, func() { code = runPurge(j.logger(), cfgPath) })
	if code != 1 || !strings.Contains(out, "FAILED") {
		t.Errorf("exit %d, output %q; want 1 and a FAILED step", code, out)
	}
}

func TestRunHealthcheck(t *testing.T) {
	// M3: 0 when /readyz answers 200 on the admin address, 1 otherwise; one
	// line of output either way.
	clearSholeEnv(t)
	ready := blocklist.NewStore()
	ready.Replace([]string{"ads.example.com"})
	cases := []struct {
		name, body string
		code       int
	}{
		{"ready", "admin:\n  listen: \"" + adminServer(t, ready, nil) + "\"\n", 0},
		{"blocklist empty", "admin:\n  listen: \"" + adminServer(t, blocklist.NewStore(), nil) + "\"\n", 1},
		{"not running", "admin:\n  listen: \"" + closedAddr(t) + "\"\n", 1},
		{"bad config", "dns: [\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var code int
			out := captureStdout(t, func() { code = runHealthcheck(writeConfig(t, tc.body)) })
			if code != tc.code {
				t.Errorf("exit = %d, want %d (output %q)", code, tc.code, out)
			}
			if lines := strings.Split(strings.TrimRight(out, "\n"), "\n"); len(lines) != 1 || lines[0] == "" {
				t.Errorf("output = %q, want one line", out)
			}
		})
	}
}

func TestRunHealthcheck_WildcardAdminAddress(t *testing.T) {
	// M3 with M2's localAdminAddr: a wildcard admin.listen is checked at
	// 127.0.0.1.
	clearSholeEnv(t)
	ready := blocklist.NewStore()
	ready.Replace([]string{"ads.example.com"})
	_, port, _ := net.SplitHostPort(adminServer(t, ready, nil))
	var code int
	out := captureStdout(t, func() { code = runHealthcheck(writeConfig(t, "admin:\n  listen: \"0.0.0.0:"+port+"\"\n")) })
	if code != 0 {
		t.Errorf("exit = %d, want 0 (output %q)", code, out)
	}
}

func TestHostUsesShole(t *testing.T) {
	// M4: true when a resolver is loopback (except systemd-resolved's
	// 127.0.0.53 and 127.0.0.54 and Docker's 127.0.0.11) or one of the host's
	// addresses, s-hole listens on port 53, and its listen host is a wildcard
	// or that address.
	addrs := func(ss ...string) []netip.Addr {
		var out []netip.Addr
		for _, s := range ss {
			out = append(out, netip.MustParseAddr(s))
		}
		return out
	}
	own := map[netip.Addr]bool{netip.MustParseAddr("192.168.1.2"): true, netip.MustParseAddr("2001:db8::2"): true}
	cases := []struct {
		name    string
		servers []netip.Addr
		listen  string
		want    bool
		which   string
	}{
		{"loopback, wildcard", addrs("127.0.0.1"), ":53", true, "127.0.0.1"},
		{"loopback ::1", addrs("::1"), "[::]:53", true, "::1"},
		{"loopback, bound to it", addrs("127.0.0.1"), "127.0.0.1:53", true, "127.0.0.1"},
		{"mapped loopback", addrs("::ffff:127.0.0.1"), "0.0.0.0:53", true, "127.0.0.1"},
		{"systemd stub", addrs("127.0.0.53"), ":53", false, ""},
		{"systemd stub 54", addrs("127.0.0.54"), ":53", false, ""},
		{"docker resolver", addrs("127.0.0.11"), ":53", false, ""},
		{"own address, wildcard", addrs("192.168.1.2"), "0.0.0.0:53", true, "192.168.1.2"},
		{"own IPv6 address", addrs("2001:db8::2"), ":53", true, "2001:db8::2"},
		{"own address, bound to it", addrs("192.168.1.2"), "192.168.1.2:53", true, "192.168.1.2"},
		{"own address, bound elsewhere", addrs("192.168.1.2"), "192.168.1.3:53", false, ""},
		{"loopback, bound to the LAN", addrs("127.0.0.1"), "192.168.1.2:53", false, ""},
		{"other port", addrs("127.0.0.1"), ":5353", false, ""},
		{"other port, own address", addrs("192.168.1.2"), "192.168.1.2:5353", false, ""},
		{"router", addrs("192.168.1.1"), ":53", false, ""},
		{"public resolver", addrs("9.9.9.9", "1.1.1.1"), ":53", false, ""},
		{"stub, then own address", addrs("127.0.0.53", "192.168.1.2"), ":53", true, "192.168.1.2"},
		{"no resolvers", nil, ":53", false, ""},
		{"bad listen", addrs("127.0.0.1"), "53", false, ""},
	}
	for _, tc := range cases {
		got, ok := hostUsesShole(tc.servers, own, tc.listen)
		if ok != tc.want {
			t.Errorf("%s: hostUsesShole = %v, want %v", tc.name, ok, tc.want)
			continue
		}
		if ok && got.String() != tc.which {
			t.Errorf("%s: resolver = %s, want %s", tc.name, got, tc.which)
		}
	}
}

func TestNameservers(t *testing.T) {
	// The resolver files are read for their nameserver lines; a missing file
	// is skipped and a zone is dropped.
	dir := t.TempDir()
	a := filepath.Join(dir, "resolv.conf")
	b := filepath.Join(dir, "resolved.conf")
	os.WriteFile(a, []byte("# comment\nsearch lan\nnameserver 127.0.0.53\noptions edns0\nnameserver\nnameserver not-an-ip\n"), 0o600)
	os.WriteFile(b, []byte("nameserver 192.168.1.2\nnameserver fe80::1%eth0\n"), 0o600)
	got := nameservers([]string{a, filepath.Join(dir, "missing"), b})
	want := []string{"127.0.0.53", "192.168.1.2", "fe80::1"}
	if len(got) != len(want) {
		t.Fatalf("nameservers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("nameservers[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestStaleWarning(t *testing.T) {
	// M5: "1 row" or "N rows", and with retention 0 a note that retention does
	// not remove them.
	one := staleWarning(querylog.StaleReport{Rows: 1})
	if !strings.Contains(one, "1 row ") || strings.Contains(one, "1 rows") {
		t.Errorf("staleWarning(1) = %q, want \"1 row\"", one)
	}
	if !strings.Contains(one, "retention does not remove") {
		t.Errorf("staleWarning without expiry = %q, want a note that retention does not remove them", one)
	}
	many := staleWarning(querylog.StaleReport{Rows: 42, Expires: time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)})
	if !strings.Contains(many, "42 rows") || !strings.Contains(many, "2026-10-13") || strings.Contains(many, "does not remove") {
		t.Errorf("staleWarning(42, expiry) = %q, want 42 rows and the expiry date", many)
	}
}

func TestPrivacyReport_LogPeriodic(t *testing.T) {
	// M5: logPeriodic logs one WARN that lists the settings, the stale rows,
	// and the plaintext fallbacks and refused queries since the last call. It
	// logs nothing when there is nothing to list.
	var plain, refused atomic.Uint64
	p := &privacyReport{
		settings:  []config.Warning{{Key: "query_log.mode", Detail: "every query is recorded"}},
		plaintext: plain.Load,
		refused:   refused.Load,
	}
	p.stale = querylog.StaleReport{Rows: 3}
	warnings := func(j *jsonLog) []map[string]any {
		var out []map[string]any
		for _, r := range j.records(t) {
			if r["msg"] == "privacy and security warnings in effect" {
				out = append(out, r)
			}
		}
		return out
	}

	plain.Store(5)
	refused.Store(2)
	var j1 jsonLog
	p.logPeriodic(j1.logger())
	w := warnings(&j1)
	if len(w) != 1 || w[0]["level"] != "WARN" || w[0]["count"] != float64(4) {
		t.Fatalf("first call = %v, want one WARN with 4 items", w)
	}
	text, _ := w[0]["warnings"].(string)
	for _, want := range []string{"query_log.mode: every query is recorded", "3 rows", "5 queries were sent unencrypted since the last stats line", "2 queries from outside the LAN were refused since the last stats line"} {
		if !strings.Contains(text, want) {
			t.Errorf("warnings %q lack %q", text, want)
		}
	}

	var j2 jsonLog
	p.logPeriodic(j2.logger())
	w = warnings(&j2)
	if len(w) != 1 || w[0]["count"] != float64(2) {
		t.Fatalf("second call with no new events = %v, want 2 items (settings and stale rows)", w)
	}
	if text, _ := w[0]["warnings"].(string); strings.Contains(text, "unencrypted") || strings.Contains(text, "refused") {
		t.Errorf("second call repeats old events: %q", text)
	}

	plain.Store(7)
	var j3 jsonLog
	p.logPeriodic(j3.logger())
	if text, _ := warnings(&j3)[0]["warnings"].(string); !strings.Contains(text, "2 queries were sent unencrypted") {
		t.Errorf("third call = %q, want the 2 new fallbacks", text)
	}

	empty := &privacyReport{plaintext: plain.Load, refused: refused.Load}
	empty.lastPlaintext, empty.lastRefused = plain.Load(), refused.Load()
	var j4 jsonLog
	empty.logPeriodic(j4.logger())
	if j4.buf.Len() != 0 {
		t.Errorf("nothing to report, but logged: %s", j4.buf.String())
	}
	var j5 jsonLog
	(&privacyReport{}).logPeriodic(j5.logger())
	if j5.buf.Len() != 0 {
		t.Errorf("empty report logged: %s", j5.buf.String())
	}
}

func TestPrivacyReport_Current(t *testing.T) {
	// M5: current lists the same items for the dashboard, with the counts
	// since startup.
	var plain, refused atomic.Uint64
	p := &privacyReport{
		settings:  []config.Warning{{Key: "admin.pprof", Detail: "the profiler is on"}},
		plaintext: plain.Load,
		refused:   refused.Load,
	}
	if got := p.current(); len(got) != 1 || got[0] != "admin.pprof: the profiler is on" {
		t.Errorf("current = %q, want only the setting", got)
	}
	plain.Store(9)
	refused.Store(4)
	p.stale = querylog.StaleReport{Rows: 1}
	var j jsonLog
	p.logPeriodic(j.logger()) // a stats line does not change the since-startup counts
	got := strings.Join(p.current(), "\n")
	for _, want := range []string{"admin.pprof: the profiler is on", "1 row ", "9 queries were sent unencrypted since startup", "4 queries from outside the LAN were refused since startup"} {
		if !strings.Contains(got, want) {
			t.Errorf("current = %q, lacks %q", got, want)
		}
	}
	if len((&privacyReport{}).current()) != 0 {
		t.Error("an empty report has current items")
	}
}

func TestPrivacyReport_CheckStale(t *testing.T) {
	// M5: the stored-history check records the stale rows for the report,
	// and logs a privacy warning only when asked to announce them.
	db, err := querylog.NewDBLogger(filepath.Join(t.TempDir(), "q.db"), "all", 10*time.Millisecond, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Log(querylog.Record{ClientIP: "192.168.1.5", Domain: "visited.example."})
	deadline := time.Now().Add(2 * time.Second)
	for rows, _ := db.Recent(context.Background(), 5); len(rows) == 0; rows, _ = db.Recent(context.Background(), 5) {
		if time.Now().After(deadline) {
			t.Fatal("row not written")
		}
		time.Sleep(5 * time.Millisecond)
	}
	p := &privacyReport{}
	var quiet jsonLog
	p.checkStale(context.Background(), quiet.logger(), db, "drop", false)
	if quiet.buf.Len() != 0 {
		t.Errorf("announce=false logged: %s", quiet.buf.String())
	}
	if items := p.current(); len(items) != 1 || !strings.Contains(items[0], "1 row ") {
		t.Errorf("current after the check = %q, want the stale row", items)
	}
	var loud jsonLog
	p.checkStale(context.Background(), loud.logger(), db, "drop", true)
	if loud.count(t, "WARN", "privacy warning") != 1 {
		t.Errorf("announce=true: %s, want one privacy warning", loud.buf.String())
	}
	var none jsonLog
	p.checkStale(context.Background(), none.logger(), db, "full", true)
	if none.buf.Len() != 0 || len(p.current()) != 0 {
		t.Errorf("no stale rows under clients full, but: log %s, current %q", none.buf.String(), p.current())
	}
}

// cacheQuery returns a client query for q, the form the DNS cache keys by.
func cacheQuery(q dns.Question) *dns.Msg {
	return &dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: true}, Question: []dns.Question{q}}
}
