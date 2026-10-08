package querylog

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fileBytes returns the content of path, or nil when it does not exist.
func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// onDisk reports whether marker is in the database file or its WAL.
func onDisk(t *testing.T, path, marker string) bool {
	t.Helper()
	return bytes.Contains(fileBytes(t, path), []byte(marker)) || bytes.Contains(fileBytes(t, path+"-wal"), []byte(marker))
}

func TestNewDBLogger_NewDatabaseIsOwnerOnly(t *testing.T) {
	// Q3 (b/076): a new database file is created with mode 0600, and the -wal
	// and -shm files SQLite creates next to it follow.
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "q.db")
	db, err := NewDBLogger(path, "all", 20*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	defer db.Close()
	db.Log(Record{ClientIP: "10.0.0.1", Domain: "a.example."})
	waitRows(t, db, 1)
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s does not exist while the database is open: %v", filepath.Base(p), err)
		}
		assertMode(t, p, 0o600)
	}
}

func TestNewDBLogger_TightensExistingFiles(t *testing.T) {
	// Q3 (b/076): an existing database and its -wal and -shm files, written by
	// an older build with mode 0644, are set to 0600 when s-hole opens them.
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "q.db")
	// The older build is still connected, so its WAL and shared-memory files
	// exist when s-hole opens the database.
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	old.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=WAL", schema,
		"INSERT INTO queries(ts,client_ip,domain,blocked) VALUES('2026-01-01T00:00:00Z','192.168.1.77','old.example.',0)"} {
		if _, err := old.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatalf("chmod %s: %v", filepath.Base(p), err)
		}
	}
	db, err := NewDBLogger(path, "all", time.Hour, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	defer db.Close()
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		assertMode(t, p, 0o600)
	}
}

// waitRows polls until at least n rows are stored or fails after 2 s.
func waitRows(t *testing.T, db *DBLogger, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rows, err := db.Recent(context.Background(), n+10); err == nil && len(rows) >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d rows", n)
}

func TestDBLogger_PruneErasesDeletedRows(t *testing.T) {
	// Q3 (b/077): after a retention prune, the bytes of a deleted row are in
	// neither the database file nor the WAL, and the WAL is empty.
	path := filepath.Join(t.TempDir(), "q.db")
	db, err := NewDBLogger(path, "all", time.Hour, 1)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	defer db.Close()

	const marker = "prunemarker-7f3a9c.example."
	old := time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)
	now := time.Now().UTC().Format(time.RFC3339)
	for i := 0; i < 50; i++ {
		if _, err := db.db.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)", old, "192.168.1.77", marker, 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.db.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)", now, "", "kept.example.", 0); err != nil {
		t.Fatal(err)
	}
	if !onDisk(t, path, marker) {
		t.Fatal("the marker is not on disk before the prune; the test proves nothing")
	}

	db.prune()

	rows, err := db.Recent(context.Background(), 100)
	if err != nil || len(rows) != 1 || rows[0].Domain != "kept.example." {
		t.Fatalf("rows after prune = %+v (%v), want only kept.example.", rows, err)
	}
	if bytes.Contains(fileBytes(t, path), []byte(marker)) {
		t.Error("the database file still holds the bytes of a pruned row")
	}
	if wal := fileBytes(t, path+"-wal"); len(wal) != 0 {
		t.Errorf("the WAL holds %d bytes after the prune, want 0", len(wal))
	}
}

func TestDBLogger_StoresUTC(t *testing.T) {
	// Q3: a new row stores ts in UTC ("...Z"), whatever the zone of the time.
	db, _ := newDB(t, "all")
	defer db.Close()
	zone := time.FixedZone("TEST", 5*60*60)
	db.flush([]entry{{ts: time.Date(2026, 1, 2, 3, 4, 5, 0, zone), clientIP: "", domain: "zoned.example."}})
	db.Log(Record{Domain: "now.example."})
	waitRows(t, db, 2)

	var ts string
	if err := db.db.QueryRow("SELECT ts FROM queries WHERE domain = 'zoned.example.'").Scan(&ts); err != nil {
		t.Fatal(err)
	}
	if ts != "2026-01-01T22:04:05Z" {
		t.Errorf("stored ts = %q, want 2026-01-01T22:04:05Z", ts)
	}
	if err := db.db.QueryRow("SELECT ts FROM queries WHERE domain = 'now.example.'").Scan(&ts); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(ts, "Z") {
		t.Errorf("stored ts = %q, want UTC with Z", ts)
	}
}

func TestMigrate_RewritesOldRowsToUTCAndLowercase(t *testing.T) {
	// Q3 (b/082): on open, a row with an offset ts is rewritten to UTC and its
	// domain is lowercased. A row whose ts cannot be parsed keeps its ts, and
	// the open does not fail.
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(schema); err != nil {
		t.Fatal(err)
	}
	seed := []struct{ ts, domain string }{
		{"2026-01-02T05:04:05+02:00", "Ads.Example.COM."},
		{"2026-01-02T01:00:00-03:30", "west.example."},
		{"2026-01-02T03:00:00Z", "Already.UTC."},
		{"not a time", "bad.example."},
	}
	for _, s := range seed {
		if _, err := old.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)", s.ts, "", s.domain, 0); err != nil {
			t.Fatal(err)
		}
	}
	old.Close()

	db, err := NewDBLogger(path, "all", time.Hour, 0)
	if err != nil {
		t.Fatalf("NewDBLogger on an old database: %v", err)
	}
	defer db.Close()
	got := map[int]QueryRow{}
	rows, err := db.db.Query("SELECT id, ts, domain FROM queries")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int
		var r QueryRow
		if err := rows.Scan(&id, &r.TS, &r.Domain); err != nil {
			t.Fatal(err)
		}
		got[id] = r
	}
	rows.Close()
	want := map[int]QueryRow{
		1: {TS: "2026-01-02T03:04:05Z", Domain: "ads.example.com."},
		2: {TS: "2026-01-02T04:30:00Z", Domain: "west.example."},
		3: {TS: "2026-01-02T03:00:00Z", Domain: "already.utc."},
	}
	for id, w := range want {
		if got[id].TS != w.TS || got[id].Domain != w.Domain {
			t.Errorf("row %d = {%s %s}, want {%s %s}", id, got[id].TS, got[id].Domain, w.TS, w.Domain)
		}
	}
	if got[4].TS != "not a time" {
		t.Errorf("row with an unreadable ts = %q, want it unchanged", got[4].TS)
	}
}

func TestDBLogger_PurgeDeletesEverything(t *testing.T) {
	// Q4: Purge deletes every row, discards the queued entries, resets the
	// row id counter, and leaves no bytes of a deleted row in the file.
	path := filepath.Join(t.TempDir(), "q.db")
	db, err := NewDBLogger(path, "all", time.Hour, 0) // queued entries stay queued
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	const stored = "purgestored-51c2.example."
	const queued = "purgequeued-9be0.example."
	for i := 0; i < 200; i++ {
		db.Log(Record{ClientIP: "192.168.1.77", Domain: stored, Blocked: true})
	}
	waitRows(t, db, 200)
	for i := 0; i < 20; i++ {
		db.Log(Record{ClientIP: "192.168.1.77", Domain: queued})
	}
	if !onDisk(t, path, stored) {
		t.Fatal("the stored marker is not on disk before the purge; the test proves nothing")
	}

	if err := db.Purge(context.Background()); err != nil {
		t.Fatalf("Purge = %v", err)
	}
	if rows, err := db.Recent(context.Background(), 10); err != nil || len(rows) != 0 {
		t.Errorf("rows after Purge = %+v (%v), want none", rows, err)
	}
	for _, m := range []string{stored, queued} {
		if onDisk(t, path, m) {
			t.Errorf("%s is still on disk after Purge", m)
		}
	}

	db.Log(Record{Domain: "after.example."})
	if err := db.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if err := db.Purge(context.Background()); err == nil {
		t.Error("Purge after Close = nil, want an error")
	}

	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var ids []int
	var domains []string
	rows, err := check.Query("SELECT id, domain FROM queries ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int
		var d string
		if err := rows.Scan(&id, &d); err != nil {
			t.Fatal(err)
		}
		ids, domains = append(ids, id), append(domains, d)
	}
	rows.Close()
	if len(ids) != 1 || ids[0] != 1 || domains[0] != "after.example." {
		t.Errorf("rows after Purge and Close = ids %v domains %v, want only after.example. with id 1", ids, domains)
	}
	if onDisk(t, path, queued) {
		t.Error("an entry queued before Purge was written after it")
	}
}

func TestDBLogger_PurgeHonorsCanceledContext(t *testing.T) {
	db, _ := newDB(t, "all")
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The writer may take the request before it sees the cancel; either
	// result is valid, but a canceled purge must not hang.
	done := make(chan struct{})
	go func() {
		_ = db.Purge(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Purge with a canceled context did not return")
	}
}

// staleRow is one row the StaleRows test stores: its age before the test's
// base time (a whole second), its client value, and its blocked flag.
type staleRow struct {
	age     time.Duration
	client  string
	blocked int
}

var staleSeed = []staleRow{
	{3 * time.Hour, "", 1},                      // r1
	{2 * time.Hour, "192.168.1.0", 0},           // r2: subnet-masked
	{time.Hour, "192.168.1.77", 1},              // r3: full address
	{30 * time.Minute, "2001:db8:1:2::", 1},     // r4: subnet-masked
	{10 * time.Minute, "2001:db8:1:2::abcd", 0}, // r5: full address
	{5 * time.Minute, "", 0},                    // r6
}

func TestDBLogger_StaleRows(t *testing.T) {
	// Q5: StaleRows counts the rows that hold more than the current settings
	// would write, and reports the newest one and when retention removes it.
	path := filepath.Join(t.TempDir(), "q.db")
	base := time.Now().UTC().Truncate(time.Second)
	seed, err := NewDBLogger(path, "all", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	times := make([]time.Time, len(staleSeed))
	for i, r := range staleSeed {
		times[i] = base.Add(-r.age)
		if _, err := seed.db.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
			times[i].Format(time.RFC3339), r.client, "d.example.", r.blocked); err != nil {
			t.Fatal(err)
		}
	}
	seed.Close()

	cases := []struct {
		mode, clients string
		rows          int64
		newest        int // index into staleSeed; -1 for none
	}{
		{"none", "full", 6, 5},
		{"none", "drop", 6, 5},
		{"blocked", "full", 3, 5},   // r2, r5, r6
		{"all", "drop", 4, 4},       // r2, r3, r4, r5
		{"all", "", 4, 4},           // "" reads as drop
		{"all", "subnet", 2, 4},     // r3, r5
		{"all", "full", 0, -1},      // nothing
		{"blocked", "subnet", 4, 5}, // r2, r3, r5, r6
		{"blocked", "drop", 5, 5},   // r2, r3, r4, r5, r6
	}
	for _, retention := range []int{0, 3} {
		for _, tc := range cases {
			t.Run(tc.mode+"/"+tc.clients+"/retention "+strconv.Itoa(retention), func(t *testing.T) {
				db, err := NewDBLogger(path, tc.mode, time.Hour, 0)
				if err != nil {
					t.Fatal(err)
				}
				db.retentionDays = retention // no prune goroutine, so the seed rows stay
				defer db.Close()
				rep, err := db.StaleRows(context.Background(), tc.clients)
				if err != nil {
					t.Fatalf("StaleRows = %v", err)
				}
				if tc.newest < 0 {
					if rep != (StaleReport{}) {
						t.Errorf("report = %+v, want the zero report", rep)
					}
					return
				}
				newest := times[tc.newest]
				var expires time.Time
				if retention > 0 {
					expires = newest.Add(time.Duration(retention) * 24 * time.Hour)
				}
				if rep.Rows != tc.rows || !rep.Newest.Equal(newest) || !rep.Expires.Equal(expires) {
					t.Errorf("report = {rows %d, newest %s, expires %s}, want {rows %d, newest %s, expires %s}",
						rep.Rows, rep.Newest, rep.Expires, tc.rows, newest, expires)
				}
			})
		}
	}
}

func TestDBLogger_StaleRowsNone(t *testing.T) {
	// Q5: an empty database, and one whose rows are all masked, give the zero
	// report.
	db, path := newDB(t, "none")
	rep, err := db.StaleRows(context.Background(), "drop")
	db.Close()
	if err != nil || rep != (StaleReport{}) {
		t.Errorf("empty database: report = %+v (%v), want the zero report", rep, err)
	}

	seed, err := NewDBLogger(path, "all", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.db.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
		time.Now().UTC().Format(time.RFC3339), "192.168.1.0", "d.example.", 0); err != nil {
		t.Fatal(err)
	}
	rep, err = seed.StaleRows(context.Background(), "subnet")
	seed.Close()
	if err != nil || rep != (StaleReport{}) {
		t.Errorf("masked rows under subnet: report = %+v (%v), want the zero report", rep, err)
	}
}

func TestDBLogger_StaleRowsCountsUnreadableClients(t *testing.T) {
	// b/101 (CL 101): under clients "subnet", a stored client value that
	// subnet masking cannot read counts as a stale row, like a full address.
	// A masked value does not.
	path := filepath.Join(t.TempDir(), "q.db")
	seed, err := NewDBLogger(path, "all", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Second)
	rows := []struct {
		client string
		stale  bool
	}{
		{"192.168.1.0", false},
		{"fe80::", false},
		{"", false},
		{"fe80::1%eth0", true},
		{"garbage", true},
		{"unknown", true},
		{"192.168.1.77", true},
	}
	var want int64
	for i, r := range rows {
		ts := base.Add(-time.Duration(len(rows)-i) * time.Minute)
		if _, err := seed.db.Exec("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)",
			ts.Format(time.RFC3339), r.client, "d.example.", 0); err != nil {
			t.Fatal(err)
		}
		if r.stale {
			want++
		}
	}
	rep, err := seed.StaleRows(context.Background(), "subnet")
	seed.Close()
	if err != nil {
		t.Fatalf("StaleRows = %v", err)
	}
	if rep.Rows != want {
		t.Errorf("stale rows = %d, want %d", rep.Rows, want)
	}
	if newest := base.Add(-time.Minute); !rep.Newest.Equal(newest) {
		t.Errorf("newest = %s, want %s", rep.Newest, newest)
	}
}
