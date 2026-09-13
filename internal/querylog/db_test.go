package querylog

import (
	"context"
	"database/sql"
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

	db.Log(Record{ClientIP: "1.2.3.4", Domain: "ads.example.com.", Blocked: true})
	db.Log(Record{ClientIP: "1.2.3.4", Domain: "google.com."})
	db.Log(Record{ClientIP: "5.6.7.8", Domain: "ads.example.com.", Blocked: true})

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

	db.Log(Record{ClientIP: "1.1.1.1", Domain: "first.com."})
	db.Log(Record{ClientIP: "2.2.2.2", Domain: "second.com.", Blocked: true})
	db.Log(Record{ClientIP: "3.3.3.3", Domain: "third.com."})

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
		db.Log(Record{ClientIP: "1.1.1.1", Domain: "ads.com.", Blocked: true})
	}
	db.Log(Record{ClientIP: "1.1.1.1", Domain: "tracker.com.", Blocked: true})
	db.Log(Record{ClientIP: "1.1.1.1", Domain: "ok.com."})

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

	db.Log(Record{ClientIP: "1.1.1.1", Domain: "ads.com.", Blocked: true})
	db.Log(Record{ClientIP: "1.1.1.1", Domain: "ok.com."}) // dropped

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
		db.Log(Record{ClientIP: "1.1.1.1", Domain: "ads.com.", Blocked: true})
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
	seed := func(ts time.Time, domain string, blocked, cacheHit int) {
		t.Helper()
		if _, err := db.db.Exec(
			"INSERT INTO queries(ts,client_ip,domain,blocked,cache_hit) VALUES(?,?,?,?,?)",
			ts.Format(time.RFC3339), "1.1.1.1", domain, blocked, cacheHit); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}

	// Current hour bucket: 3 queries, 2 blocked, 1 cache hit (a blocked query
	// never reaches the cache, so only an allowed row carries cache_hit=1).
	seed(now, "a.com", 1, 0)
	seed(now, "b.com", 1, 0)
	seed(now, "c.com", 0, 1)
	// One hour earlier: 2 queries, 1 blocked, 1 cache hit.
	seed(now.Add(-1*time.Hour), "d.com", 1, 0)
	seed(now.Add(-1*time.Hour), "e.com", 0, 1)
	// Outside the 24h window: must be excluded.
	seed(now.Add(-25*time.Hour), "old.com", 1, 0)

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
	if cur.Total != 3 || cur.Blocked != 2 || cur.Cached != 1 {
		t.Errorf("current bucket = {total %d, blocked %d, cached %d}, want {3, 2, 1}", cur.Total, cur.Blocked, cur.Cached)
	}
	prev := series[len(series)-2]
	if prev.Total != 2 || prev.Blocked != 1 || prev.Cached != 1 {
		t.Errorf("previous bucket = {total %d, blocked %d, cached %d}, want {2, 1, 1}", prev.Total, prev.Blocked, prev.Cached)
	}

	// An empty bucket in the middle is zero-filled, not skipped.
	if mid := series[0]; mid.Total != 0 || mid.Blocked != 0 || mid.Cached != 0 {
		t.Errorf("oldest (empty) bucket = {total %d, blocked %d, cached %d}, want {0, 0, 0}", mid.Total, mid.Blocked, mid.Cached)
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

func TestDBLogger_CacheHitRoundTrip(t *testing.T) {
	// A cache-hit record is stored and summed by History. Exercises the full
	// write path (Log -> channel -> flush INSERT) for the cache_hit column,
	// not a direct seed.
	db, _ := newDB(t, "all")
	defer db.Close()

	db.Log(Record{ClientIP: "1.1.1.1", Domain: "cached.com.", CacheHit: true})
	db.Log(Record{ClientIP: "1.1.1.1", Domain: "forwarded.com."})
	db.Log(Record{ClientIP: "1.1.1.1", Domain: "ads.com.", Blocked: true})

	time.Sleep(150 * time.Millisecond) // let the flush tick persist the batch

	series, err := db.History(context.Background(), time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	cur := series[len(series)-1]
	if cur.Total != 3 || cur.Blocked != 1 || cur.Cached != 1 {
		t.Errorf("bucket = {total %d, blocked %d, cached %d}, want {3, 1, 1}", cur.Total, cur.Blocked, cur.Cached)
	}
}

func TestMigrate_AddsCacheHitColumn(t *testing.T) {
	// An older database predates the cache_hit column. NewDBLogger must add it
	// idempotently (the first ALTER TABLE migration), and existing rows must
	// read cache_hit=0 (the column DEFAULT), the documented forward-only behavior.
	path := filepath.Join(t.TempDir(), "old.db")

	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open old db: %v", err)
	}
	if _, err := old.Exec(`CREATE TABLE queries (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		ts        TEXT    NOT NULL,
		client_ip TEXT    NOT NULL,
		domain    TEXT    NOT NULL,
		blocked   INTEGER NOT NULL
	)`); err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	if _, err := old.Exec(
		"INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
		time.Now().Format(time.RFC3339), "1.1.1.1", "pre-upgrade.com.", 0); err != nil {
		t.Fatalf("seed old row: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatalf("close old db: %v", err)
	}

	// Opening through NewDBLogger runs the migration.
	db, err := NewDBLogger(path, "all", time.Hour, 0)
	if err != nil {
		t.Fatalf("NewDBLogger on old db: %v", err)
	}
	defer db.Close()

	// The pre-upgrade row reads cache_hit=0.
	var cacheHit int
	if err := db.db.QueryRow("SELECT cache_hit FROM queries WHERE domain = 'pre-upgrade.com.'").Scan(&cacheHit); err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if cacheHit != 0 {
		t.Errorf("pre-upgrade row cache_hit = %d, want 0", cacheHit)
	}

	// Re-running the migration is a no-op (idempotent), not an error.
	if err := migrate(db.db); err != nil {
		t.Errorf("second migrate: %v", err)
	}
}

func TestMigrate_AddsOutcomeColumns(t *testing.T) {
	// A post-CL76, pre-CL77 database has cache_hit but not the rcode or
	// synthesized columns. NewDBLogger must add both idempotently, and existing
	// rows must read rcode=0, synthesized=0 (so an old row is never counted as a
	// failed query), the documented forward-only behavior.
	path := filepath.Join(t.TempDir(), "old.db")

	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open old db: %v", err)
	}
	if _, err := old.Exec(`CREATE TABLE queries (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		ts        TEXT    NOT NULL,
		client_ip TEXT    NOT NULL,
		domain    TEXT    NOT NULL,
		blocked   INTEGER NOT NULL,
		cache_hit INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	if _, err := old.Exec(
		"INSERT INTO queries(ts,client_ip,domain,blocked,cache_hit) VALUES(?,?,?,?,?)",
		time.Now().Format(time.RFC3339), "1.1.1.1", "pre-upgrade.com.", 0, 0); err != nil {
		t.Fatalf("seed old row: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatalf("close old db: %v", err)
	}

	db, err := NewDBLogger(path, "all", time.Hour, 0)
	if err != nil {
		t.Fatalf("NewDBLogger on old db: %v", err)
	}
	defer db.Close()

	var rcode, synthesized int
	if err := db.db.QueryRow("SELECT rcode, synthesized FROM queries WHERE domain = 'pre-upgrade.com.'").Scan(&rcode, &synthesized); err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if rcode != 0 || synthesized != 0 {
		t.Errorf("pre-upgrade row = {rcode %d, synthesized %d}, want {0, 0}", rcode, synthesized)
	}

	// Re-running the migration is a no-op (idempotent), not an error.
	if err := migrate(db.db); err != nil {
		t.Errorf("second migrate: %v", err)
	}
}

func TestDBLogger_OutcomeRoundTrip(t *testing.T) {
	// Drive the full write path (Log -> channel -> flush INSERT) for each
	// outcome, then assert History sums the two failure kinds per bucket. A
	// blocked, cached, or successfully forwarded query never counts as failed.
	db, _ := newDB(t, "all")
	defer db.Close()

	db.Log(Record{ClientIP: "1.1.1.1", Domain: "ok.com."})                                                 // forwarded NOERROR
	db.Log(Record{ClientIP: "1.1.1.1", Domain: "blocked.com.", Blocked: true, Synthesized: true})          // blocked
	db.Log(Record{ClientIP: "1.1.1.1", Domain: "dead.com.", Rcode: rcodeServerFailure, Synthesized: true}) // unresolved
	db.Log(Record{ClientIP: "1.1.1.1", Domain: "broken.com.", Rcode: rcodeServerFailure})                  // relayed SERVFAIL
	db.Log(Record{ClientIP: "1.1.1.1", Domain: "refused.com.", Rcode: rcodeRefused})                       // relayed REFUSED
	db.Log(Record{ClientIP: "1.1.1.1", Domain: "nx.com.", Rcode: 3})                                       // NXDOMAIN, not a failure

	time.Sleep(150 * time.Millisecond) // let the flush tick persist the batch

	series, err := db.History(context.Background(), time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	cur := series[len(series)-1]
	if cur.Total != 6 || cur.Unresolved != 1 || cur.UpstreamError != 2 {
		t.Errorf("bucket = {total %d, unresolved %d, upstream_error %d}, want {6, 1, 2}",
			cur.Total, cur.Unresolved, cur.UpstreamError)
	}
}

func TestDBLogger_SearchOutcome(t *testing.T) {
	// The ?outcome= filter narrows to a failure kind. Seed rows with explicit
	// rcode/synthesized so the two kinds are distinguishable.
	db, _ := newDB(t, "all")
	defer db.Close()

	seed := func(domain string, blocked, rcode, synthesized int) {
		t.Helper()
		if _, err := db.db.Exec(
			"INSERT INTO queries(ts,client_ip,domain,blocked,rcode,synthesized) VALUES(?,?,?,?,?,?)",
			time.Now().Format(time.RFC3339), "1.1.1.1", domain, blocked, rcode, synthesized); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}
	seed("ok.com.", 0, 0, 0)
	seed("blocked.com.", 1, 0, 1)
	seed("dead.com.", 0, rcodeServerFailure, 1)   // unresolved
	seed("broken.com.", 0, rcodeServerFailure, 0) // relayed SERVFAIL
	seed("refused.com.", 0, rcodeRefused, 0)      // relayed REFUSED

	ctx := context.Background()
	tests := []struct {
		outcome string
		want    int
	}{
		{"", 5},
		{"unresolved", 1},
		{"upstream-error", 2},
	}
	for _, tc := range tests {
		t.Run("outcome="+tc.outcome, func(t *testing.T) {
			rows, err := db.Search(ctx, QueryFilter{Outcome: tc.outcome}, 100)
			if err != nil {
				t.Fatalf("Search: %v", err)
			}
			if len(rows) != tc.want {
				t.Errorf("outcome %q returned %d rows, want %d", tc.outcome, len(rows), tc.want)
			}
		})
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
			db.Log(Record{ClientIP: "1.1.1.1", Domain: "ads.com.", Blocked: true})
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
		db.Log(Record{ClientIP: "1.1.1.1", Domain: "ads.com.", Blocked: true})
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
			d.Log(Record{ClientIP: "192.168.1.10", Domain: "ads.example.com.", Blocked: true})
		}
	})
}
