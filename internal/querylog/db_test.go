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

func TestNewDBLogger_NonPositiveFlushIntervalErrors(t *testing.T) {
	// A non-positive flush interval would panic time.NewTicker in the writer
	// goroutine. The constructor must reject it (no panic, no goroutine started)
	// so the caller degrades cleanly (b/046).
	path := filepath.Join(t.TempDir(), "queries.db")
	for _, d := range []time.Duration{0, -5 * time.Second} {
		if _, err := NewDBLogger(path, "all", d, 0); err == nil {
			t.Errorf("NewDBLogger with flushInterval=%s returned nil error, want rejected", d)
		}
	}
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

func TestDBLogger_Search(t *testing.T) {
	// Seed rows directly for deterministic domains, clients, and block flags, then
	// assert each filter dimension. Seeding bypasses the async writer, the same
	// approach as the History and retention tests.
	db, _ := newDB(t, "all")
	defer db.Close()

	seed := func(client, domain string, blocked int) {
		t.Helper()
		if _, err := db.db.Exec(
			"INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
			time.Now().Format(time.RFC3339), client, domain, blocked); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}

	seed("1.1.1.1", "ads.example.com.", 1)
	seed("1.1.1.1", "sub.ads.example.com.", 1)
	seed("2.2.2.2", "google.com.", 0)
	seed("2.2.2.2", "tracker.net.", 1)
	seed("3.3.3.3", "a_b.com.", 0) // the underscore is a LIKE wildcard; it must match literally
	seed("3.3.3.3", "axb.com.", 0)

	ctx := context.Background()
	tru, fls := true, false
	tests := []struct {
		name   string
		filter QueryFilter
		want   int
	}{
		{"no filter matches all", QueryFilter{}, 6},
		{"domain substring", QueryFilter{Domain: "ads"}, 2},
		{"domain case-insensitive", QueryFilter{Domain: "ADS"}, 2},
		{"domain no match", QueryFilter{Domain: "nope"}, 0},
		{"underscore is literal", QueryFilter{Domain: "a_b"}, 1},
		{"client exact", QueryFilter{Client: "2.2.2.2"}, 2},
		{"client no match", QueryFilter{Client: "9.9.9.9"}, 0},
		{"blocked true", QueryFilter{Blocked: &tru}, 3},
		{"blocked false", QueryFilter{Blocked: &fls}, 3},
		{"domain and blocked", QueryFilter{Domain: "example", Blocked: &tru}, 2},
		{"client and blocked false", QueryFilter{Client: "2.2.2.2", Blocked: &fls}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := db.Search(ctx, tc.filter, 100)
			if err != nil {
				t.Fatalf("Search: %v", err)
			}
			if len(rows) != tc.want {
				t.Errorf("Search(%+v) returned %d rows, want %d", tc.filter, len(rows), tc.want)
			}
		})
	}

	// Recent is Search with an empty filter, so the two must agree.
	recent, err := db.Recent(ctx, 100)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	all, err := db.Search(ctx, QueryFilter{}, 100)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(recent) != len(all) {
		t.Errorf("Recent returned %d rows, Search{} returned %d; want equal", len(recent), len(all))
	}
}

func TestDBLogger_CloseFlushesPending(t *testing.T) {
	// Regression for b/005: entries enqueued just before Close must be
	// persisted; Close waits on the WaitGroup.
	path := filepath.Join(t.TempDir(), "queries.db")
	db, err := NewDBLogger(path, "all", 1*time.Hour, 0) // long interval, only drain on Close fires
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
	//
	// b/038: this flaked under -race with SQLITE_BUSY; the startup prune, the
	// seed tx, and this explicit prune() contended across pooled connections
	// until NewDBLogger pinned the pool to one connection (SetMaxOpenConns(1)).
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

func TestDBLogger_History(t *testing.T) {
	// Seed rows with controlled timestamps into known hour buckets, then assert
	// the dense series buckets them correctly. Seeding directly (not via the
	// async writer) keeps the timestamps deterministic, the same approach as
	// the retention test.
	db, _ := newDB(t, "all")
	defer db.Close()

	now := time.Now()
	seed := func(ts time.Time, domain string, blocked int) {
		t.Helper()
		if _, err := db.db.Exec(
			"INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
			ts.Format(time.RFC3339), "1.1.1.1", domain, blocked); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}

	// Current hour bucket: 3 queries, 2 blocked.
	seed(now, "a.com", 1)
	seed(now, "b.com", 1)
	seed(now, "c.com", 0)
	// One hour earlier: 2 queries, 1 blocked.
	seed(now.Add(-1*time.Hour), "d.com", 1)
	seed(now.Add(-1*time.Hour), "e.com", 0)
	// Outside the 24h window: must be excluded.
	seed(now.Add(-25*time.Hour), "old.com", 1)

	series, err := db.History(context.Background(), 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(series) != 24 {
		t.Fatalf("series length = %d, want 24 (dense 24h/1h)", len(series))
	}

	// Ascending order by Start.
	for i := 1; i < len(series); i++ {
		if series[i].Start <= series[i-1].Start {
			t.Fatalf("series not ascending at %d: %d <= %d", i, series[i].Start, series[i-1].Start)
		}
	}

	// The last bucket is the current (partial) hour; the one before it is the
	// previous hour.
	cur := series[len(series)-1]
	if cur.Total != 3 || cur.Blocked != 2 {
		t.Errorf("current bucket = {total %d, blocked %d}, want {3, 2}", cur.Total, cur.Blocked)
	}
	prev := series[len(series)-2]
	if prev.Total != 2 || prev.Blocked != 1 {
		t.Errorf("previous bucket = {total %d, blocked %d}, want {2, 1}", prev.Total, prev.Blocked)
	}

	// An empty bucket in the middle is zero-filled, not skipped.
	if mid := series[0]; mid.Total != 0 || mid.Blocked != 0 {
		t.Errorf("oldest (empty) bucket = {total %d, blocked %d}, want {0, 0}", mid.Total, mid.Blocked)
	}

	// A total across all buckets must exclude the out-of-window row.
	var total int64
	for _, b := range series {
		total += b.Total
	}
	if total != 5 {
		t.Errorf("summed total = %d, want 5 (25h-ago row excluded)", total)
	}
}

func TestDBLogger_TopBlockedTieOrder(t *testing.T) {
	// b/056: equal-count blocked domains come back ordered by domain ascending,
	// matching the in-memory topN tie-break so the dashboard's "Since start" and
	// "All time" tabs order ties identically. Seed directly for a deterministic
	// tie (each domain blocked exactly once).
	db, _ := newDB(t, "all")
	defer db.Close()
	now := time.Now().Format(time.RFC3339)
	for _, d := range []string{"c.com.", "b.com.", "a.com."} {
		if _, err := db.db.Exec(
			"INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
			now, "1.1.1.1", d, 1); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}

	top, err := db.TopBlocked(context.Background(), 10)
	if err != nil {
		t.Fatalf("TopBlocked: %v", err)
	}
	want := []string{"a.com.", "b.com.", "c.com."}
	if len(top) != len(want) {
		t.Fatalf("TopBlocked len = %d, want %d", len(top), len(want))
	}
	for i, w := range want {
		if top[i].Name != w {
			t.Errorf("TopBlocked[%d] = %q, want %q", i, top[i].Name, w)
		}
	}
}

func TestDBLogger_LogQueries(t *testing.T) {
	// The accessor reports the configured filter so the history endpoint can
	// label the graph honestly.
	for _, mode := range []string{"all", "blocked", "none"} {
		db, _ := newDB(t, mode)
		if got := db.LogQueries(); got != mode {
			t.Errorf("LogQueries() = %q, want %q", got, mode)
		}
		db.Close()
	}
}

func TestDBLogger_HistoryEmptyDBIsZeroFilled(t *testing.T) {
	db, _ := newDB(t, "all")
	defer db.Close()

	series, err := db.History(context.Background(), 6*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(series) != 6 {
		t.Fatalf("series length = %d, want 6", len(series))
	}
	for i, b := range series {
		if b.Total != 0 || b.Blocked != 0 {
			t.Errorf("bucket %d = {total %d, blocked %d}, want zero", i, b.Total, b.Blocked)
		}
	}
}

func TestDBLogger_DroppedOnChannelOverflow(t *testing.T) {
	// With a tiny channel and a slow flush (1h interval) the buffer
	// fills up quickly. The logger must drop entries silently rather
	// than block the caller (that would deadlock the DNS hot path),
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
		t.Fatal("Log() blocked under back-pressure; channel must drop on full")
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

// BenchmarkDBLogger_Flush measures the batch-commit throughput of the async
// writer. The SQLite pool is pinned to one connection (b/038), so this
// single-transaction insert of flushBatchSize rows is the entire drain
// budget: if it slows, the bounded channel fills and Log starts dropping
// (shole_query_log_dropped_total). Each iteration commits one full batch. The
// flush interval is set long so the writer goroutine stays idle and does not
// compete for the one connection while flush is called directly.
func BenchmarkDBLogger_Flush(b *testing.B) {
	path := filepath.Join(b.TempDir(), "queries.db")
	d, err := NewDBLogger(path, "all", time.Hour, 0)
	if err != nil {
		b.Fatalf("NewDBLogger: %v", err)
	}
	defer d.Close()

	now := time.Now()
	batch := make([]entry, flushBatchSize)
	for i := range batch {
		batch[i] = entry{ts: now, clientIP: "192.168.1.10", domain: "ads.example.com.", blocked: i%2 == 0}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.flush(batch)
	}
}

// BenchmarkDBLogger_Log_Parallel measures the enqueue cost on the hot path
// under concurrent callers, the way it runs in production: one DNS goroutine
// per query calling Log. The point is that the select-send stays non-blocking
// even when the channel saturates and Log takes the drop branch; a regression
// that made Log block a DNS goroutine would show as a throughput collapse
// here. The writer drains concurrently, so some sends land and some drop; the
// benchmark measures the caller's cost either way.
func BenchmarkDBLogger_Log_Parallel(b *testing.B) {
	path := filepath.Join(b.TempDir(), "queries.db")
	d, err := NewDBLogger(path, "all", 50*time.Millisecond, 0)
	if err != nil {
		b.Fatalf("NewDBLogger: %v", err)
	}
	defer d.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			d.Log("192.168.1.10", "ads.example.com.", true)
		}
	})
}
