package querylog

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// walMarker and walClient are the test domain and client that the PRIV-16
// tests store. Neither may be in the WAL when s-hole frees it.
const (
	walMarker = "walwipe-3e8d.example."
	walClient = "192.168.1.77"
)

// walSnap is what the walFreeHook saw in the WAL at one point of freeing.
type walSnap struct {
	size   int
	zero   bool // every byte is zero
	marker bool // walMarker is in the bytes
	client bool // walClient is in the bytes
	err    string
}

// walRecorder records a walSnap each time s-hole is about to free the WAL.
type walRecorder struct {
	mu    sync.Mutex
	snaps []walSnap
}

// recordWALFrees sets walFreeHook to a recorder and resets the hook when the
// test ends. Call it before NewDBLogger. The hook runs in whichever
// goroutine wipes (the writer, the prune goroutine, or the caller of
// NewDBLogger, prune, and Close), so the recorder holds a mutex.
func recordWALFrees(t *testing.T) *walRecorder {
	t.Helper()
	r := &walRecorder{}
	walFreeHook = func(walPath string) {
		s := walSnap{}
		b, err := os.ReadFile(walPath)
		if err != nil && !os.IsNotExist(err) {
			s.err = err.Error()
		}
		s.size = len(b)
		s.zero = allZero(b)
		s.marker = bytes.Contains(b, []byte(walMarker))
		s.client = bytes.Contains(b, []byte(walClient))
		r.mu.Lock()
		r.snaps = append(r.snaps, s)
		r.mu.Unlock()
	}
	t.Cleanup(func() { walFreeHook = nil })
	return r
}

// take returns the snapshots recorded since the last take and clears them.
func (r *walRecorder) take() []walSnap {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.snaps
	r.snaps = nil
	return s
}

// checkZeroed fails the test when a snapshot shows query data in the WAL at
// the point where s-hole frees it.
func checkZeroed(t *testing.T, step string, snaps []walSnap) {
	t.Helper()
	for i, s := range snaps {
		if s.err != "" {
			t.Errorf("%s, free %d: the hook could not read the WAL: %s", step, i, s.err)
		}
		if s.marker {
			t.Errorf("%s, free %d: the test domain is in the WAL just before SQLite frees it", step, i)
		}
		if s.client {
			t.Errorf("%s, free %d: the test client is in the WAL just before SQLite frees it", step, i)
		}
		if !s.zero {
			t.Errorf("%s, free %d: the WAL (%d bytes) holds bytes other than zero just before SQLite frees it", step, i, s.size)
		}
	}
}

// integrityOK fails the test unless PRAGMA integrity_check returns "ok".
func integrityOK(t *testing.T, step string, db *sql.DB) {
	t.Helper()
	var res string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&res); err != nil {
		t.Fatalf("%s: integrity_check: %v", step, err)
	}
	if res != "ok" {
		t.Errorf("%s: integrity_check = %q, want ok", step, res)
	}
}

// countRows returns the number of rows whose domain matches the LIKE pattern.
func countRows(t *testing.T, db *sql.DB, like string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM queries WHERE domain LIKE ?", like).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", like, err)
	}
	return n
}

// insertRows writes n rows with walMarker and walClient, stamped ts, through
// the logger's one connection.
func insertRows(t *testing.T, d *DBLogger, n int, ts time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := d.db.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
			ts.UTC().Format(time.RFC3339), walClient, walMarker, 1); err != nil {
			t.Fatal(err)
		}
	}
}

// walHas reports whether the WAL file at path+"-wal" holds walMarker.
func walHas(t *testing.T, path string) bool {
	t.Helper()
	return bytes.Contains(fileBytes(t, path+"-wal"), []byte(walMarker))
}

// liveLogger calls d.Log in a loop with domains "live-N.example." until the
// returned stop is called. stop returns the number of Log calls.
func liveLogger(d *DBLogger) (stop func() int64) {
	var sent atomic.Int64
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-quit:
				return
			default:
			}
			d.Log(Record{ClientIP: "10.9.8.7", Domain: fmt.Sprintf("live-%d.example.", i)})
			sent.Add(1)
			time.Sleep(100 * time.Microsecond)
		}
	}()
	return func() int64 {
		close(quit)
		<-done
		return sent.Load()
	}
}

// syncBuffer is a bytes.Buffer that the writer goroutines can share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureWALLogs sends every slog record to a buffer as JSON lines until the
// test ends. The package logger looks up slog.Default for each record.
func captureWALLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// wipeWarnings returns the "at" field of each "query log WAL overwrite
// failed" WARN in the captured log.
func wipeWarnings(t *testing.T, buf *syncBuffer) []string {
	t.Helper()
	var at []string
	dec := json.NewDecoder(strings.NewReader(buf.String()))
	for {
		var rec map[string]any
		if err := dec.Decode(&rec); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode log: %v", err)
		}
		if rec["msg"] == "query log WAL overwrite failed" {
			if rec["level"] != "WARN" {
				t.Errorf("WAL overwrite failure logged at %v, want WARN", rec["level"])
			}
			s, _ := rec["at"].(string)
			at = append(at, s)
		}
	}
	return at
}

// checkLogClean fails the test when the application log names the test
// domain or client (the log carries no query data).
func checkLogClean(t *testing.T, buf *syncBuffer) {
	t.Helper()
	out := buf.String()
	for _, s := range []string{walMarker, strings.TrimSuffix(walMarker, "."), walClient} {
		if strings.Contains(out, s) {
			t.Errorf("the application log holds %q:\n%s", s, out)
		}
	}
}

// reopen opens the database at path again with NewDBLogger, as a restart
// does, and closes it when the test ends.
func reopen(t *testing.T, path string) *DBLogger {
	t.Helper()
	d, err := NewDBLogger(path, "all", time.Hour, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestDBLogger_PruneZeroesWALBeforeItIsFreed(t *testing.T) {
	// PRIV-16: after a retention prune that deletes rows, the WAL holds only
	// zeros when SQLite truncates it, also while Log calls go on. The rows
	// that the prune keeps, and the rows logged during the prune, survive a
	// restart, and the database is intact after each step.
	rec := recordWALFrees(t)
	path := filepath.Join(t.TempDir(), "q.db")
	d, err := NewDBLogger(path, "all", 10*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	d.retentionDays = 1 // set here, so no startup prune runs in parallel with the test
	insertRows(t, d, 50, time.Now().Add(-72*time.Hour))
	if _, err := d.db.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
		time.Now().UTC().Format(time.RFC3339), "", "kept.example.", 0); err != nil {
		t.Fatal(err)
	}
	if !walHas(t, path) {
		t.Fatal("the test domain is not in the WAL before the prune; the test proves nothing")
	}
	rec.take()

	stop := liveLogger(d)
	time.Sleep(20 * time.Millisecond) // let some live rows reach the WAL first
	d.prune()
	sent := stop()

	snaps := rec.take()
	if len(snaps) != 1 {
		t.Fatalf("the prune freed the WAL through the wipe %d times, want 1", len(snaps))
	}
	checkZeroed(t, "prune", snaps)
	integrityOK(t, "after prune", d.db)
	if n := countRows(t, d.db, walMarker); n != 0 {
		t.Errorf("%d pruned rows are still in the table", n)
	}

	dropped := int64(d.Dropped())
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	checkZeroed(t, "close", rec.take())

	d2 := reopen(t, path)
	integrityOK(t, "after restart", d2.db)
	if n := countRows(t, d2.db, "kept.example."); n != 1 {
		t.Errorf("kept rows after restart = %d, want 1", n)
	}
	if n := int64(countRows(t, d2.db, "live-%")); n != sent-dropped {
		t.Errorf("live rows after restart = %d, want %d (%d logged, %d dropped)", n, sent-dropped, sent, dropped)
	}
}

func TestDBLogger_PurgeZeroesWALBeforeItIsFreed(t *testing.T) {
	// PRIV-16: an online purge overwrites the WAL with zeros after the row
	// deletes and again after the VACUUM, each time just before SQLite
	// truncates it, also while Log calls go on. Purge returns nil, the
	// database is intact, and a row logged after the purge survives a
	// restart.
	rec := recordWALFrees(t)
	path := filepath.Join(t.TempDir(), "q.db")
	d, err := NewDBLogger(path, "all", 10*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	for i := 0; i < 200; i++ {
		d.Log(Record{ClientIP: walClient, Domain: walMarker, Blocked: true})
	}
	waitRows(t, d, 200)
	if !walHas(t, path) {
		t.Fatal("the test domain is not in the WAL before the purge; the test proves nothing")
	}
	rec.take()

	stop := liveLogger(d)
	time.Sleep(20 * time.Millisecond)
	if err := d.Purge(context.Background()); err != nil {
		t.Fatalf("Purge = %v, want nil", err)
	}
	stop()

	snaps := rec.take()
	if len(snaps) != 2 {
		t.Fatalf("the purge freed the WAL through the wipe %d times, want 2 (after the deletes and after the VACUUM)", len(snaps))
	}
	checkZeroed(t, "purge", snaps)
	integrityOK(t, "after purge", d.db)

	d.Log(Record{Domain: "after.example."})
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	checkZeroed(t, "close", rec.take())
	if onDisk(t, path, walMarker) {
		t.Error("the test domain is on disk after the purge and Close")
	}

	d2 := reopen(t, path)
	integrityOK(t, "after restart", d2.db)
	if n := countRows(t, d2.db, walMarker); n != 0 {
		t.Errorf("purged rows after restart = %d, want 0", n)
	}
	if n := countRows(t, d2.db, "after.example."); n != 1 {
		t.Errorf("rows logged after the purge = %d after restart, want 1", n)
	}
}

func TestDBLogger_CloseZeroesWALBeforeItIsFreed(t *testing.T) {
	// PRIV-16: Close writes the queued entries, then overwrites the WAL with
	// zeros before SQLite deletes it, also while Log calls go on. Every row
	// logged before Close survives a restart, and the database is intact.
	rec := recordWALFrees(t)
	path := filepath.Join(t.TempDir(), "q.db")
	d, err := NewDBLogger(path, "all", time.Hour, 0) // only Close writes the queue
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	for i := 0; i < 30; i++ {
		d.Log(Record{ClientIP: walClient, Domain: walMarker, Blocked: true})
	}
	rec.take()

	stop := liveLogger(d)
	time.Sleep(10 * time.Millisecond)
	before := stop() // every one of these Log calls ended before Close starts
	stop2 := liveLogger(d)
	err = d.Close()
	stop2()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	dropped := int64(d.Dropped())

	snaps := rec.take()
	if len(snaps) != 1 {
		t.Fatalf("Close freed the WAL through the wipe %d times, want 1", len(snaps))
	}
	if snaps[0].size == 0 {
		t.Error("the WAL was empty when Close wiped it; the test proves nothing")
	}
	checkZeroed(t, "close", snaps)
	if wal := fileBytes(t, path+"-wal"); len(wal) != 0 {
		t.Errorf("the WAL holds %d bytes after Close, want none", len(wal))
	}

	d2 := reopen(t, path)
	integrityOK(t, "after restart", d2.db)
	if n := countRows(t, d2.db, walMarker); n != 30 {
		t.Errorf("rows queued before Close = %d after restart, want 30", n)
	}
	if n := int64(countRows(t, d2.db, "live-%")); n < before-dropped {
		t.Errorf("live rows after restart = %d, want at least %d (logged before Close)", n, before-dropped)
	}
}

func TestNewDBLogger_ZeroesLeftoverWALAtStart(t *testing.T) {
	// PRIV-16: a WAL that a crash left holds page images of committed rows.
	// NewDBLogger copies them into the database, then overwrites the WAL with
	// zeros before it is freed. No committed row is lost.
	crashed, dir := t.TempDir(), t.TempDir()
	src := filepath.Join(crashed, "q.db")
	old, err := sql.Open("sqlite", src)
	if err != nil {
		t.Fatal(err)
	}
	old.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=WAL", schema} {
		if _, err := old.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 40; i++ {
		if _, err := old.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
			time.Now().UTC().Format(time.RFC3339), walClient, walMarker, 1); err != nil {
			t.Fatal(err)
		}
	}
	// Copy the files while the connection is open: this is what a crash
	// leaves on the disk (the database and a WAL with every commit).
	path := filepath.Join(dir, "q.db")
	for _, sfx := range []string{"", "-wal"} {
		b, err := os.ReadFile(src + sfx)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+sfx, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old.Close()
	if !walHas(t, path) {
		t.Fatal("the test domain is not in the leftover WAL; the test proves nothing")
	}

	rec := recordWALFrees(t)
	d, err := NewDBLogger(path, "all", time.Hour, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	snaps := rec.take()
	if len(snaps) != 1 {
		t.Fatalf("NewDBLogger freed the WAL through the wipe %d times, want 1", len(snaps))
	}
	checkZeroed(t, "start", snaps)
	integrityOK(t, "after start", d.db)
	if n := countRows(t, d.db, walMarker); n != 40 {
		t.Errorf("committed rows from the leftover WAL = %d, want 40", n)
	}
}

func TestDBLogger_WALWipeRefusedWhileAnotherConnectionReads(t *testing.T) {
	// PRIV-16: while another connection holds a read transaction, the
	// checkpoint cannot finish, so s-hole neither zeroes nor truncates the
	// WAL: the WAL keeps its data. Purge returns an error; prune and Close
	// log a WARN without query data, and Close returns nil. After the reader
	// ends, the database is intact and a row logged before Close is there.
	logs := captureWALLogs(t)
	rec := recordWALFrees(t)
	path := filepath.Join(t.TempDir(), "q.db")
	d, err := NewDBLogger(path, "all", 10*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	// The checkpoint waits busy_timeout for the reader; 200 ms keeps the
	// test short. It does not change what the guard decides.
	if _, err := d.db.Exec("PRAGMA busy_timeout=200"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		d.Log(Record{ClientIP: walClient, Domain: walMarker, Blocked: true})
	}
	waitRows(t, d, 50)
	if !walHas(t, path) {
		t.Fatal("the test domain is not in the WAL; the test proves nothing")
	}
	rec.take()

	reader, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow("SELECT COUNT(*) FROM queries").Scan(&n); err != nil || n != 50 {
		t.Fatalf("reader count = %d, %v", n, err)
	}

	walKept := func(step string) {
		t.Helper()
		wal := fileBytes(t, path+"-wal")
		if len(wal) == 0 {
			t.Errorf("%s: the WAL is empty or gone; it must not be truncated while the guard fails", step)
		}
		if !bytes.Contains(wal, []byte(walMarker)) {
			t.Errorf("%s: the WAL lost its data; it must not be zeroed while the guard fails", step)
		}
	}

	if err := d.Purge(context.Background()); err == nil {
		t.Error("Purge = nil while another connection reads, want an error")
	}
	if snaps := rec.take(); len(snaps) != 0 {
		t.Errorf("Purge reached the WAL free point %d times while the guard failed, want 0", len(snaps))
	}
	walKept("purge")

	d.retentionDays = 1
	insertRows(t, d, 5, time.Now().Add(-72*time.Hour))
	d.prune()
	if snaps := rec.take(); len(snaps) != 0 {
		t.Errorf("prune reached the WAL free point %d times while the guard failed, want 0", len(snaps))
	}
	walKept("prune")

	d.Log(Record{Domain: "kept.example."})
	if err := d.Close(); err != nil {
		t.Errorf("Close = %v while another connection reads, want nil (only a WARN)", err)
	}
	if snaps := rec.take(); len(snaps) != 0 {
		t.Errorf("Close reached the WAL free point %d times while the guard failed, want 0", len(snaps))
	}
	walKept("close")

	if got := wipeWarnings(t, logs); strings.Join(got, ",") != "prune,stop" {
		t.Errorf("WAL overwrite WARNs at %v, want [prune stop]", got)
	}
	checkLogClean(t, logs)

	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	reader.Close()
	d2 := reopen(t, path)
	integrityOK(t, "after restart", d2.db)
	if n := countRows(t, d2.db, "kept.example."); n != 1 {
		t.Errorf("row logged before Close = %d after restart, want 1", n)
	}
}

func TestDBLogger_WALWipeRefusesHardLinkedWAL(t *testing.T) {
	// PRIV-16: when ZeroFile refuses the WAL (here a second hard link), s-hole
	// does not truncate it either, so the data stays in the file. Purge
	// returns an error and prune logs a WARN without query data. Once the
	// link is gone, Close wipes the WAL again.
	logs := captureWALLogs(t)
	rec := recordWALFrees(t)
	path := filepath.Join(t.TempDir(), "q.db")
	d, err := NewDBLogger(path, "all", 10*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	for i := 0; i < 50; i++ {
		d.Log(Record{ClientIP: walClient, Domain: walMarker, Blocked: true})
	}
	waitRows(t, d, 50)
	other := filepath.Join(t.TempDir(), "other")
	if err := os.Link(path+"-wal", other); err != nil {
		d.Close()
		t.Skipf("cannot make a hard link here: %v", err)
	}
	rec.take()

	walKept := func(step string) {
		t.Helper()
		for _, p := range []string{path + "-wal", other} {
			b := fileBytes(t, p)
			if len(b) == 0 {
				t.Errorf("%s: %s is empty or gone, want it not truncated", step, filepath.Base(p))
			}
			if !bytes.Contains(b, []byte(walMarker)) {
				t.Errorf("%s: %s lost its data, want it not overwritten", step, filepath.Base(p))
			}
		}
	}

	if err := d.Purge(context.Background()); err == nil {
		t.Error("Purge = nil with a hard-linked WAL, want an error")
	}
	if snaps := rec.take(); len(snaps) != 0 {
		t.Errorf("Purge reached the WAL free point %d times, want 0", len(snaps))
	}
	walKept("purge")

	d.retentionDays = 1
	insertRows(t, d, 5, time.Now().Add(-72*time.Hour))
	d.prune()
	if snaps := rec.take(); len(snaps) != 0 {
		t.Errorf("prune reached the WAL free point %d times, want 0", len(snaps))
	}
	walKept("prune")
	if got := wipeWarnings(t, logs); strings.Join(got, ",") != "prune" {
		t.Errorf("WAL overwrite WARNs at %v, want [prune]", got)
	}

	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	snaps := rec.take()
	if len(snaps) != 1 {
		t.Fatalf("Close freed the WAL through the wipe %d times after the link was removed, want 1", len(snaps))
	}
	checkZeroed(t, "close", snaps)
	checkLogClean(t, logs)

	d2 := reopen(t, path)
	integrityOK(t, "after restart", d2.db)
}

func TestDBLogger_WALIsNotShortenedAfterCommit(t *testing.T) {
	// PRIV-16: journal_size_limit is -1, so SQLite does not truncate the WAL
	// after a commit. Only the wipe makes the WAL shorter. A truncate after a
	// commit would free blocks that still hold page images.
	path := filepath.Join(t.TempDir(), "q.db")
	d, err := NewDBLogger(path, "all", time.Hour, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	defer d.Close()
	var limit int64
	if err := d.db.QueryRow("PRAGMA journal_size_limit").Scan(&limit); err != nil {
		t.Fatal(err)
	}
	if limit != -1 {
		t.Errorf("journal_size_limit = %d, want -1", limit)
	}

	tx, err := d.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for i := 0; i < 3000; i++ {
		if _, err := tx.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
			now, walClient, fmt.Sprintf("big-%d-%s", i, walMarker), 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	big := len(fileBytes(t, path+"-wal"))
	// A complete checkpoint makes the next commit start the WAL again from
	// its first frame: that is where SQLite applies journal_size_limit.
	if _, err := d.db.Exec("PRAGMA wal_checkpoint(PASSIVE)"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)", now, "", "small.example.", 0); err != nil {
		t.Fatal(err)
	}
	if got := len(fileBytes(t, path+"-wal")); got < big {
		t.Errorf("the WAL got shorter after a commit: %d bytes, was %d", got, big)
	}
}

func TestDBLogger_WALWipeKeepsRowsOfAnotherWriter(t *testing.T) {
	// PRIV-16: the wipe copies every WAL frame into the database before it
	// zeroes the WAL, so rows that another connection committed, still in the
	// WAL, are not lost. The other connection writes before and after each
	// wipe, and the database stays intact.
	rec := recordWALFrees(t)
	path := filepath.Join(t.TempDir(), "q.db")
	d, err := NewDBLogger(path, "all", 10*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	d.retentionDays = 1
	rec.take()
	ext, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ext.Close()
	ext.SetMaxOpenConns(1)

	const rounds, perRound = 5, 20
	for round := 0; round < rounds; round++ {
		tx, err := ext.Begin()
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < perRound; i++ {
			if _, err := tx.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
				time.Now().UTC().Format(time.RFC3339), "", fmt.Sprintf("ext-%d-%d.example.", round, i), 0); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(fileBytes(t, path+"-wal"), []byte(fmt.Sprintf("ext-%d-0.example.", round))) {
			t.Fatalf("round %d: the rows of the other connection are not in the WAL; the test proves nothing", round)
		}
		insertRows(t, d, 3, time.Now().Add(-72*time.Hour))
		d.prune()
		snaps := rec.take()
		if len(snaps) != 1 {
			t.Fatalf("round %d: the prune freed the WAL through the wipe %d times, want 1", round, len(snaps))
		}
		checkZeroed(t, fmt.Sprintf("round %d", round), snaps)
		if wal := fileBytes(t, path+"-wal"); len(wal) != 0 {
			t.Errorf("round %d: the WAL holds %d bytes after the wipe, want 0", round, len(wal))
		}
		integrityOK(t, fmt.Sprintf("round %d", round), d.db)
		if n := countRows(t, ext, "ext-%"); n != (round+1)*perRound {
			t.Fatalf("round %d: the other connection reads %d of its rows, want %d", round, n, (round+1)*perRound)
		}
	}

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ext.Close()
	d2 := reopen(t, path)
	integrityOK(t, "after restart", d2.db)
	if n := countRows(t, d2.db, "ext-%"); n != rounds*perRound {
		t.Errorf("rows of the other connection after restart = %d, want %d", n, rounds*perRound)
	}
	if n := countRows(t, d2.db, walMarker); n != 0 {
		t.Errorf("pruned rows after restart = %d, want 0", n)
	}
}

func TestDBLogger_WALWipeRefusedWhenAnotherConnectionWritesAfterCheckpoint(t *testing.T) {
	// PRIV-16: when another connection commits between the RESTART
	// checkpoint and BEGIN IMMEDIATE, its frames are in the WAL only, so
	// s-hole neither zeroes nor truncates the WAL. Purge returns an error;
	// prune and Close log a WARN without query data, and Close returns nil.
	// Every row of the other connection survives, also after a restart.
	logs := captureWALLogs(t)
	rec := recordWALFrees(t)
	path := filepath.Join(t.TempDir(), "q.db")
	ext, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ext.Close()
	ext.SetMaxOpenConns(1)

	// The hook commits one row from the other connection each time the test
	// arms it, so a later wipe that is not armed can succeed.
	var armed atomic.Bool
	var writes atomic.Int64
	var hookMu sync.Mutex
	var hookErr error
	walCheckpointHook = func() {
		if !armed.CompareAndSwap(true, false) {
			return
		}
		n := writes.Load()
		_, err := ext.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
			time.Now().UTC().Format(time.RFC3339), "", fmt.Sprintf("ext%d-%s", n, walMarker), 0)
		if err != nil {
			hookMu.Lock()
			hookErr = err
			hookMu.Unlock()
			return
		}
		writes.Add(1)
	}
	t.Cleanup(func() { walCheckpointHook = nil })

	d, err := NewDBLogger(path, "all", 10*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	d.retentionDays = 1
	rec.take()

	// step runs one wipe point with the hook armed, then checks that the WAL
	// was not freed and still holds the row that the other connection wrote.
	step := func(name string, run func()) {
		t.Helper()
		want := writes.Load() + 1
		armed.Store(true)
		run()
		hookMu.Lock()
		err := hookErr
		hookMu.Unlock()
		if err != nil {
			t.Fatalf("%s: the other connection could not write: %v", name, err)
		}
		if got := writes.Load(); got != want {
			t.Fatalf("%s: the other connection wrote %d rows, want %d; the hook did not run", name, got, want)
		}
		if snaps := rec.take(); len(snaps) != 0 {
			t.Errorf("%s: reached the WAL free point %d times after another connection wrote, want 0", name, len(snaps))
		}
		wal := fileBytes(t, path+"-wal")
		if len(wal) == 0 {
			t.Errorf("%s: the WAL is empty or gone; it must not be truncated after another connection wrote", name)
		}
		if !bytes.Contains(wal, []byte(fmt.Sprintf("ext%d-%s", want-1, walMarker))) {
			t.Errorf("%s: the WAL lost the frames of the other connection; it must not be zeroed", name)
		}
	}

	insertRows(t, d, 5, time.Now().Add(-72*time.Hour))
	step("prune", d.prune)
	integrityOK(t, "after prune", d.db)
	if n := countRows(t, d.db, "ext%"); n != 1 {
		t.Errorf("after prune: rows of the other connection = %d, want 1", n)
	}

	step("purge", func() {
		if err := d.Purge(context.Background()); err == nil {
			t.Error("Purge = nil after another connection wrote during the wipe, want an error")
		}
	})
	integrityOK(t, "after purge", d.db)
	if n := countRows(t, d.db, "ext%"); n != 1 {
		t.Errorf("after purge: rows of the other connection = %d, want 1 (the one written after the deletes)", n)
	}

	step("close", func() {
		if err := d.Close(); err != nil {
			t.Errorf("Close = %v after another connection wrote during the wipe, want nil (only a WARN)", err)
		}
	})

	if got := wipeWarnings(t, logs); strings.Join(got, ",") != "prune,stop" {
		t.Errorf("WAL overwrite WARNs at %v, want [prune stop]", got)
	}
	checkLogClean(t, logs)

	if n := countRows(t, ext, "ext%"); n != 2 {
		t.Errorf("the other connection reads %d of its rows after Close, want 2", n)
	}
	ext.Close()
	d2 := reopen(t, path)
	integrityOK(t, "after restart", d2.db)
	if n := countRows(t, d2.db, "ext%"); n != 2 {
		t.Errorf("rows of the other connection after restart = %d, want 2", n)
	}
}
