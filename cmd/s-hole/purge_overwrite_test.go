package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/api"
	"github.com/lcsabi/s-hole/internal/config"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
)

// wipeMarker is the test domain that the PRIV-08 offline purge tests store.
const wipeMarker = "offlinewipe-c41e.example."

// writeQueryDB writes a query database at path the way s-hole does
// (NewDBLogger, Log, Close), with n rows for domain.
func writeQueryDB(t *testing.T, path, domain string, n int) {
	t.Helper()
	db := openQueryDB(t, path)
	waitQueryRows(t, db, domain, n)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// openQueryDB opens a DBLogger on path that writes its rows soon.
func openQueryDB(t *testing.T, path string) *querylog.DBLogger {
	t.Helper()
	db, err := querylog.NewDBLogger(path, "all", 20*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	return db
}

// waitQueryRows logs n rows for domain and waits until they are written.
func waitQueryRows(t *testing.T, db *querylog.DBLogger, domain string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		db.Log(querylog.Record{ClientIP: "192.168.1.77", Domain: domain})
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rows, err := db.Recent(context.Background(), n+10); err == nil && len(rows) >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d rows", n)
}

// queryRows opens the query database at path and returns its row count.
func queryRows(t *testing.T, path string) int {
	t.Helper()
	db, err := querylog.NewDBLogger(path, "all", time.Hour, 0)
	if err != nil {
		t.Fatalf("NewDBLogger(%s): %v", path, err)
	}
	defer db.Close()
	rows, err := db.Recent(context.Background(), 1_000_000)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	return len(rows)
}

// writeQueryLog writes a query log file at path the way s-hole does
// (NewFileLogger, Log, Close), with n lines for domain.
func writeQueryLog(t *testing.T, path, domain string, n int) {
	t.Helper()
	l, err := querylog.NewFileLogger(path, "all")
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	for i := 0; i < n; i++ {
		l.Log(querylog.Record{ClientIP: "192.168.1.77", Domain: domain})
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Contains(readFile(t, path), []byte(domain)) {
		t.Fatal("the test domain is not in the query log file; the test proves nothing")
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// assertSingleLine checks that every step result is one line, so that
// runPurge prints one line for each step (PRIV-08).
func assertSingleLine(t *testing.T, rep api.PurgeReport) {
	t.Helper()
	for _, s := range rep.Steps {
		if strings.ContainsAny(s.Result, "\r\n") {
			t.Errorf("step %q result is more than one line: %q", s.What, s.Result)
		}
	}
}

// assertDeleteFailed checks that the step what failed with a result that
// starts with "delete failed: ".
func assertDeleteFailed(t *testing.T, rep api.PurgeReport, what string) {
	t.Helper()
	s, ok := stepByWhat(rep)[what]
	if !ok || !s.Failed || !strings.HasPrefix(s.Result, "delete failed: ") {
		t.Errorf("step %q = %+v (present %v), want failed with \"delete failed: ...\"", what, s, ok)
	}
}

func TestPurgeOffline_SymlinkedDatabaseIsNotTouched(t *testing.T) {
	// PRIV-08: the offline purge can run as root in the data directory,
	// which the s-hole user owns. A symbolic link at the database path is
	// not followed: the database it points to keeps its rows and bytes, the
	// link is not deleted, and the step fails. The query log step still
	// runs.
	wd := offlineWorkDir(t)
	target := filepath.Join(t.TempDir(), "other.db")
	writeQueryDB(t, target, wipeMarker, 30)
	before := readFile(t, target)
	link := filepath.Join(wd, "q.db")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot make a symbolic link here: %v", err)
	}
	writeQueryLog(t, filepath.Join(wd, "q.log"), wipeMarker, 5)

	cfg, _ := loadOffline(t, "query_log:\n  database: \"q.db\"\n  file: \"q.log\"\n")
	rep, _ := purgeOffline(cfg)
	steps := stepByWhat(rep)
	assertDeleteFailed(t, rep, "query database")
	assertSingleLine(t, rep)
	want := "delete failed: " + cfg.QueryLog.Database + ": not a regular file; not overwritten"
	if s := steps["query database"]; s.Result != want {
		t.Errorf("result = %q, want %q (the refusal once, on one line)", s.Result, want)
	}
	if s := steps["query log file"]; s.Failed || s.Result != "deleted" {
		t.Errorf("query log file step = %+v, want \"deleted\" after the failed database step", s)
	}
	assertGone(t, filepath.Join(wd, "q.log"))
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the symbolic link was changed or deleted: %v, %v", fi, err)
	}
	if after := readFile(t, target); !bytes.Equal(after, before) {
		t.Errorf("the link target changed (%d bytes before, %d after)", len(before), len(after))
	}
	if n := queryRows(t, target); n != 30 {
		t.Errorf("the link target has %d rows, want 30", n)
	}
}

func TestPurgeOffline_SymlinkedLogFileIsNotTouched(t *testing.T) {
	// PRIV-08: a symbolic link at the query log path is not followed: the
	// file it points to keeps its content, the link stays, and the step
	// fails. The database step still runs.
	wd := offlineWorkDir(t)
	target := filepath.Join(t.TempDir(), "other.txt")
	content := []byte("not s-hole data " + wipeMarker + "\n")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(wd, "q.log")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot make a symbolic link here: %v", err)
	}
	writeQueryDB(t, filepath.Join(wd, "q.db"), wipeMarker, 10)

	cfg, _ := loadOffline(t, "query_log:\n  database: \"q.db\"\n  file: \"q.log\"\n")
	rep, _ := purgeOffline(cfg)
	steps := stepByWhat(rep)
	assertDeleteFailed(t, rep, "query log file")
	assertSingleLine(t, rep)
	want := "delete failed: " + cfg.QueryLog.File + ": not a regular file; not overwritten"
	if s := steps["query log file"]; s.Result != want {
		t.Errorf("result = %q, want %q", s.Result, want)
	}
	if s := steps["query database"]; s.Failed || s.Result != "files deleted" {
		t.Errorf("query database step = %+v, want \"files deleted\"", s)
	}
	assertGone(t, filepath.Join(wd, "q.db"), filepath.Join(wd, "q.db-wal"), filepath.Join(wd, "q.db-shm"))
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the symbolic link was changed or deleted: %v, %v", fi, err)
	}
	if got := readFile(t, target); !bytes.Equal(got, content) {
		t.Errorf("the link target changed: %q", got)
	}
}

func TestPurgeOffline_NotADatabaseIsDeleted(t *testing.T) {
	// PRIV-08: a file at the database path that is not a SQLite database is
	// deleted, and the step does not fail.
	// TestPurgeOffline_NotADatabaseIsZeroedBeforeDelete checks the zeros.
	wd := offlineWorkDir(t)
	touch(t, filepath.Join(wd, "q.db"))
	cfg, _ := loadOffline(t, "query_log:\n  database: \"q.db\"\n")
	rep, notFound := purgeOffline(cfg)
	if s := stepByWhat(rep)["query database"]; notFound || s.Failed || s.Result != "files deleted" {
		t.Errorf("step = %+v, notFound %v; want \"files deleted\", not failed", s, notFound)
	}
	assertGone(t, filepath.Join(wd, "q.db"), filepath.Join(wd, "q.db-wal"), filepath.Join(wd, "q.db-shm"))
}

func TestPurgeTargets_LogNotOverwrittenIsReported(t *testing.T) {
	// PRIV-08: in a running s-hole, when another file took the query log
	// path, Purge empties the open file but cannot overwrite it with zeros.
	// The step fails, and its result is the error text, which starts with
	// "emptied, but not overwritten with zeros" (not "empty failed: ").
	// The new file at the path keeps its content.
	dir := t.TempDir()
	path := filepath.Join(dir, "q.log")
	if err := os.WriteFile(path, []byte("old "+wipeMarker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fl, err := querylog.NewFileLogger(path, "all")
	if err != nil {
		t.Fatal(err)
	}
	defer fl.Close()
	moved := filepath.Join(dir, "q.log.1")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	other := []byte("another file\n")
	if err := os.WriteFile(path, other, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Blocking.CacheDir = t.TempDir()
	rep := purgeTargets{cfg: cfg, counter: stats.New(), fileLog: fl}.purge(context.Background())
	s, ok := stepByWhat(rep)["query log file"]
	if !ok || !s.Failed || !strings.HasPrefix(s.Result, "emptied, but not overwritten with zeros") {
		t.Errorf("step = %+v (present %v), want failed with \"emptied, but not overwritten with zeros...\"", s, ok)
	}
	assertSingleLine(t, rep)
	if got := readFile(t, moved); len(got) != 0 {
		t.Errorf("the open log file holds %d bytes after the purge, want 0", len(got))
	}
	if got := readFile(t, path); !bytes.Equal(got, other) {
		t.Errorf("the new file at the path changed: %q", got)
	}
}

// linkedDB is a query database in a temporary current directory where some
// of q.db, q.db-wal, and q.db-shm are links to files under other names.
type linkedDB struct {
	db      string            // the configured path, "q.db"
	other   map[string]string // suffix -> the other name of a linked file
	saved   map[string][]byte // suffix -> the content of the other name
	plain   []string          // the paths of the files that are not linked
	refused []string          // the configured paths of the linked files
}

// setupLinkedDB makes q.db, q.db-wal, and q.db-shm in a fresh current
// directory. The files in linked get their content under another name, and
// link makes the q.db path name that file (a symbolic link or a hard link).
// The other files are plain files. Every file holds wipeMarker. q.db is a
// real query database written by NewDBLogger.
func setupLinkedDB(t *testing.T, linked []string, link func(other, path string) error) linkedDB {
	t.Helper()
	wd := offlineWorkDir(t)
	elsewhere := t.TempDir()
	l := linkedDB{db: "q.db", other: map[string]string{}, saved: map[string][]byte{}}
	isLinked := map[string]bool{}
	for _, s := range linked {
		isLinked[s] = true
	}
	// q.db first: NewDBLogger must not write to a -wal or -shm link.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := filepath.Join(wd, "q.db"+suffix)
		target := path
		if isLinked[suffix] {
			target = filepath.Join(elsewhere, "other.db"+suffix)
		}
		if suffix == "" {
			writeQueryDB(t, target, wipeMarker, 30)
		} else if err := os.WriteFile(target, bytes.Repeat([]byte(wipeMarker), 3000), 0o600); err != nil {
			t.Fatal(err)
		}
		if !isLinked[suffix] {
			l.plain = append(l.plain, path)
			continue
		}
		if err := link(target, path); err != nil {
			t.Skipf("cannot make a link here: %v", err)
		}
		l.other[suffix], l.saved[suffix] = target, readFile(t, target)
		l.refused = append(l.refused, "q.db"+suffix)
	}
	return l
}

// check verifies the result of an offline purge of l: the step fails with
// one line that names each refused path once, with reason; the links stay;
// their other names keep their exact content; the plain files are deleted.
func (l linkedDB) check(t *testing.T, rep api.PurgeReport, reason string) {
	t.Helper()
	assertDeleteFailed(t, rep, "query database")
	assertSingleLine(t, rep)
	res := stepByWhat(rep)["query database"].Result
	for _, p := range l.refused {
		if n := strings.Count(res, p+": "+reason); n != 1 {
			t.Errorf("result names %q %d times, want once: %q", p+": "+reason, n, res)
		}
	}
	if len(l.refused) == 1 {
		if want := "delete failed: " + l.refused[0] + ": " + reason; res != want {
			t.Errorf("result = %q, want %q", res, want)
		}
	}
	for suffix, other := range l.other {
		if _, err := os.Lstat("q.db" + suffix); err != nil {
			t.Errorf("the link q.db%s was deleted: %v", suffix, err)
		}
		if got := readFile(t, other); !bytes.Equal(got, l.saved[suffix]) {
			t.Errorf("the other name of q.db%s changed (%d bytes, was %d)", suffix, len(got), len(l.saved[suffix]))
		}
	}
	assertGone(t, l.plain...)
}

// setName names a link set for a subtest, for example "q.db-wal+q.db-shm".
func setName(set []string) string {
	names := make([]string, len(set))
	for i, s := range set {
		names[i] = "q.db" + s
	}
	return strings.Join(names, "+")
}

// linkSets are the sets of database files that the link tests make links.
var linkSets = [][]string{{""}, {"-wal"}, {"-shm"}, {"-wal", "-shm"}, {"", "-wal", "-shm"}}

func TestPurgeOffline_SymlinkedDatabaseFilesAreNotFollowed(t *testing.T) {
	// PRIV-08: a symbolic link at q.db, q.db-wal, or q.db-shm is not
	// followed and not deleted, and the file it points to keeps its exact
	// content. The step fails with one line that names each refused path
	// once. The database files that are not links are still deleted.
	for _, set := range linkSets {
		t.Run(setName(set), func(t *testing.T) {
			l := setupLinkedDB(t, set, os.Symlink)
			cfg, _ := loadOffline(t, "query_log:\n  database: \""+l.db+"\"\n")
			rep, _ := purgeOffline(cfg)
			l.check(t, rep, "not a regular file; not overwritten")
		})
	}
}
