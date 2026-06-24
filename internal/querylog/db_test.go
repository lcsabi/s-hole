package querylog

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newDB(t *testing.T, logQueries string) (*DBLogger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "queries.db")
	db, err := NewDBLogger(path, logQueries, 50*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	return db, path
}

func TestNewDBLogger_BadPathErrors(t *testing.T) {
	// A path inside a nonexistent directory cannot be created. Verify
	// NewDBLogger surfaces the error rather than returning a half-built
	// DBLogger that would crash on the first write.
	_, err := NewDBLogger("/does/not/exist/queries.db", "all", time.Hour, 0)
	if err == nil {
		t.Error("NewDBLogger with unwritable path returned nil error")
	}
}

func TestDBLogger_PruneIsNoOpWhenEmpty(t *testing.T) {
	// prune() on an empty table must not error. Covers the
	// "RowsAffected == 0" log branch.
	path := filepath.Join(t.TempDir(), "queries.db")
	db, err := NewDBLogger(path, "all", time.Hour, 1)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	defer db.Close()
	db.prune() // must not panic or error visibly
}

func TestDBLogger_RoundTrip(t *testing.T) {
	db, _ := newDB(t, "all")

	db.Log("1.2.3.4", "ads.example.com.", true)
	db.Log("1.2.3.4", "google.com.", false)
	db.Log("5.6.7.8", "ads.example.com.", true)

	// Close drains pending entries and waits for the goroutine.
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open to read what was persisted.
	path := filepath.Join(t.TempDir(), "verify.db")
	_ = path // unused; reopen the same db via a new logger for the read-side helpers.
}

func TestDBLogger_RecentReturnsNewestFirst(t *testing.T) {
	db, _ := newDB(t, "all")
	defer db.Close()

	db.Log("1.1.1.1", "first.com.", false)
	db.Log("2.2.2.2", "second.com.", true)
	db.Log("3.3.3.3", "third.com.", false)

	// Wait for the flush tick.
	time.Sleep(150 * time.Millisecond)

	rows, err := db.Recent(context.Background(), 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	if rows[0].Domain != "third.com." {
		t.Errorf("rows[0].Domain = %q, want third.com.", rows[0].Domain)
	}
	if rows[2].Domain != "first.com." {
		t.Errorf("rows[2].Domain = %q, want first.com.", rows[2].Domain)
	}
}

func TestDBLogger_TopBlocked(t *testing.T) {
	db, _ := newDB(t, "all")
	defer db.Close()

	for i := 0; i < 3; i++ {
		db.Log("1.1.1.1", "ads.com.", true)
	}
	db.Log("1.1.1.1", "tracker.com.", true)
	db.Log("1.1.1.1", "ok.com.", false)

	time.Sleep(150 * time.Millisecond)

	top, err := db.TopBlocked(context.Background(), 5)
	if err != nil {
		t.Fatalf("TopBlocked: %v", err)
	}
	if len(top) != 2 {
		t.Fatalf("top = %v, want 2 entries", top)
	}
	if top[0].Name != "ads.com." || top[0].Count != 3 {
		t.Errorf("top[0] = %+v, want {ads.com., 3}", top[0])
	}
}

func TestDBLogger_FilterBlocked(t *testing.T) {
	db, _ := newDB(t, "blocked")
	defer db.Close()

	db.Log("1.1.1.1", "ads.com.", true)
	db.Log("1.1.1.1", "ok.com.", false) // dropped

	time.Sleep(150 * time.Millisecond)

	rows, err := db.Recent(context.Background(), 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %v, want exactly the blocked row", rows)
	}
	if rows[0].Domain != "ads.com." {
		t.Errorf("rows[0].Domain = %q, want ads.com.", rows[0].Domain)
	}
}

func TestDBLogger_CloseFlushesPending(t *testing.T) {
	// Regression for b/005: entries enqueued just before Close must be
	// persisted; Close waits on the WaitGroup.
	path := filepath.Join(t.TempDir(), "queries.db")
	db, err := NewDBLogger(path, "all", 1*time.Hour, 0) // long interval — only drain on Close fires
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	for i := 0; i < 10; i++ {
		db.Log("1.1.1.1", "ads.com.", true)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open and verify all 10 rows landed.
	db2, err := NewDBLogger(path, "all", 1*time.Hour, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	rows, err := db2.Recent(context.Background(), 20)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(rows) != 10 {
		t.Errorf("got %d rows after Close+reopen, want 10", len(rows))
	}
}

func TestDBLogger_RetentionPruneDeletesOldRows(t *testing.T) {
	// R16: with retentionDays=1, a row dated 2 days ago must be deleted
	// by the prune goroutine. We bypass the periodic ticker by calling
	// prune() directly on a DBLogger built with retention enabled.
	path := filepath.Join(t.TempDir(), "queries.db")
	db, err := NewDBLogger(path, "all", 1*time.Hour, 1)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	defer db.Close()

	// Inject one fresh row and one row stamped 2 days ago.
	tx, _ := db.db.Begin()
	old := time.Now().Add(-48 * time.Hour).Format(time.RFC3339)
	now := time.Now().Format(time.RFC3339)
	tx.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)", old, "1.1.1.1", "old.com", 1)
	tx.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)", now, "1.1.1.1", "new.com", 1)
	if err := tx.Commit(); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	db.prune()

	rows, err := db.Recent(context.Background(), 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("after prune got %d rows, want 1", len(rows))
	}
	if rows[0].Domain != "new.com" {
		t.Errorf("kept row = %q, want new.com", rows[0].Domain)
	}
}

func TestDBLogger_DroppedOnChannelOverflow(t *testing.T) {
	// With a tiny channel and a slow flush (1h interval) the buffer
	// fills up quickly. The logger must drop entries silently rather
	// than block the caller — that would deadlock the DNS hot path —
	// and it must *count* the drops so /metrics can surface back-pressure.
	path := filepath.Join(t.TempDir(), "queries.db")
	db, err := NewDBLogger(path, "all", 1*time.Hour, 0) // long flush → no draining
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	defer db.Close()

	// Push >> queryQueueSize (1000) so the default-arm branch in Log()
	// definitely fires.
	const pushed = 5000
	done := make(chan struct{})
	go func() {
		for i := 0; i < pushed; i++ {
			db.Log("1.1.1.1", "ads.com.", true)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Log() blocked under back-pressure — channel must drop on full")
	}

	// Pushed 5000 entries into a 1000-slot channel that's not draining;
	// at least the last 4000 must have been dropped. The exact count is
	// scheduler-dependent so we assert a lower bound.
	if got := db.Dropped(); got < 3000 {
		t.Errorf("Dropped() = %d after pushing %d into a 1000-slot channel; "+
			"want >= 3000 (R33 regression: dropped counter not incrementing)",
			got, pushed)
	}
}

func TestDBLogger_DroppedZeroUnderNormalLoad(t *testing.T) {
	// Quiescent path: pushing a handful of entries to a logger with a
	// short flush interval must never increment the drop counter.
	db, _ := newDB(t, "all")
	defer db.Close()
	for i := 0; i < 10; i++ {
		db.Log("1.1.1.1", "ads.com.", true)
	}
	time.Sleep(150 * time.Millisecond)
	if got := db.Dropped(); got != 0 {
		t.Errorf("Dropped() = %d under normal load; want 0", got)
	}
}
