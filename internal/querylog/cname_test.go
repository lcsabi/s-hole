package querylog

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// CL 117: a blocked query records what matched it (BlockSource): the queried
// name, or a CNAME target in its answer. The target itself is never stored.

func TestBlockSource_String(t *testing.T) {
	// CL 117 req 7: "name", "cname", and "unknown" for any other value.
	cases := []struct {
		in   BlockSource
		want string
	}{
		{BlockedByName, "name"},
		{BlockedByCNAME, "cname"},
		{BlockSource(2), "unknown"},
		{BlockSource(-1), "unknown"},
		{BlockSource(99), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("BlockSource(%d).String() = %q, want %q", int(tc.in), got, tc.want)
		}
	}
	if (Record{}).BlockSource != BlockedByName {
		t.Error("the zero Record does not have BlockSource BlockedByName")
	}
}

// cnameRecords are one row of each kind, logged in this order. The allowed
// row carries BlockSource=cname on purpose: an allowed row must read no
// blocked_by whatever the field holds.
var cnameRecords = []Record{
	{ClientIP: "192.168.1.5", Domain: "ads.example.com.", Blocked: true, Synthesized: true, BlockSource: BlockedByName},
	{ClientIP: "192.168.1.5", Domain: "metrics.shop.example.", Blocked: true, Synthesized: true, BlockSource: BlockedByCNAME},
	{ClientIP: "192.168.1.5", Domain: "ok.example.com.", BlockSource: BlockedByCNAME},
	{ClientIP: "192.168.1.5", Domain: "nx.shop.example.", Blocked: true, Rcode: 3, Synthesized: true, BlockSource: BlockedByCNAME},
}

var cnameWantBlockedBy = map[string]string{
	"ads.example.com.":      "name",
	"metrics.shop.example.": "cname",
	"ok.example.com.":       "",
	"nx.shop.example.":      "cname",
}

// checkBlockedBy fails unless each row has the blocked_by of its domain.
func checkBlockedBy(t *testing.T, where string, rows []QueryRow, want int) {
	t.Helper()
	if len(rows) != want {
		t.Fatalf("%s returned %d rows, want %d", where, len(rows), want)
	}
	for _, r := range rows {
		w, ok := cnameWantBlockedBy[r.Domain]
		if !ok {
			t.Errorf("%s: unexpected row %+v", where, r)
			continue
		}
		if r.BlockedBy != w {
			t.Errorf("%s: %s blocked_by = %q, want %q", where, r.Domain, r.BlockedBy, w)
		}
	}
}

func TestDBLogger_BlockSourceRoundTrip(t *testing.T) {
	// CL 117 req 8: the full write path (Log, channel, INSERT) stores the block
	// source, and Recent, Search, and Export read it back as blocked_by.
	db, _ := newDB(t, "all")
	defer db.Close()
	for _, r := range cnameRecords {
		db.Log(r)
	}
	waitRows(t, db, len(cnameRecords))
	ctx := context.Background()

	recent, err := db.Recent(ctx, 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	checkBlockedBy(t, "Recent", recent, 4)

	all, err := db.Search(ctx, QueryFilter{}, 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	checkBlockedBy(t, "Search", all, 4)

	tru := true
	blocked, err := db.Search(ctx, QueryFilter{Blocked: &tru}, 10)
	if err != nil {
		t.Fatalf("Search(blocked): %v", err)
	}
	checkBlockedBy(t, "Search(blocked)", blocked, 3)

	var exported []QueryRow
	if err := db.Export(ctx, QueryFilter{}, 0, func(r QueryRow) error {
		exported = append(exported, r)
		return nil
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	checkBlockedBy(t, "Export", exported, 4)

	// The column holds 0 for a name block and 1 for a CNAME block.
	var src int
	if err := db.db.QueryRow("SELECT block_source FROM queries WHERE domain = 'metrics.shop.example.'").Scan(&src); err != nil {
		t.Fatalf("read block_source: %v", err)
	}
	if src != 1 {
		t.Errorf("block_source of the CNAME row = %d, want 1", src)
	}
	if err := db.db.QueryRow("SELECT block_source FROM queries WHERE domain = 'ads.example.com.'").Scan(&src); err != nil {
		t.Fatalf("read block_source: %v", err)
	}
	if src != 0 {
		t.Errorf("block_source of the name row = %d, want 0", src)
	}
}

func TestQueryRow_BlockedByJSON(t *testing.T) {
	// CL 117 req 8: blocked_by is in the JSON of a blocked row and omitted from
	// an allowed row.
	for _, tc := range []struct {
		row     QueryRow
		present bool
		want    string
	}{
		{QueryRow{Domain: "a.example.", Blocked: true, BlockedBy: "cname"}, true, "cname"},
		{QueryRow{Domain: "a.example.", Blocked: true, BlockedBy: "name"}, true, "name"},
		{QueryRow{Domain: "a.example."}, false, ""},
	} {
		b, err := json.Marshal(tc.row)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		v, ok := m["blocked_by"]
		if ok != tc.present || (ok && v != tc.want) {
			t.Errorf("JSON %s: blocked_by = %#v (present %v), want %q (present %v)", b, v, ok, tc.want, tc.present)
		}
	}
}

func TestNewDBLogger_BlockSourceColumn(t *testing.T) {
	// CL 117 req 8: a new database has block_source INTEGER NOT NULL DEFAULT 0.
	db, _ := newDB(t, "all")
	defer db.Close()
	checkBlockSourceColumn(t, db.db)
}

// checkBlockSourceColumn fails unless the queries table has the
// block_source column with its CL 117 type, NOT NULL, and DEFAULT 0.
func checkBlockSourceColumn(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(queries)")
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		if name != "block_source" {
			continue
		}
		if !strings.EqualFold(typ, "INTEGER") || notnull != 1 || dflt.String != "0" {
			t.Errorf("block_source = {type %q, notnull %d, default %q}, want {INTEGER, 1, 0}", typ, notnull, dflt.String)
		}
		return
	}
	t.Error("queries table has no block_source column")
}

func TestMigrate_AddsBlockSourceColumn(t *testing.T) {
	// CL 117 req 8: a database from an older build has no block_source column.
	// Opening it adds the column; an old blocked row reads blocked_by "name"
	// and an old allowed row reads none. New rows store their source.
	for _, tc := range []struct {
		name   string
		schema string
		insert string
	}{
		{"CL 77 schema", `CREATE TABLE queries (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			ts          TEXT    NOT NULL,
			client_ip   TEXT    NOT NULL,
			domain      TEXT    NOT NULL,
			blocked     INTEGER NOT NULL,
			cache_hit   INTEGER NOT NULL DEFAULT 0,
			rcode       INTEGER NOT NULL DEFAULT 0,
			synthesized INTEGER NOT NULL DEFAULT 0
		)`, "INSERT INTO queries(ts,client_ip,domain,blocked,synthesized) VALUES(?,?,?,?,?)"},
		{"first schema", `CREATE TABLE queries (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			ts        TEXT    NOT NULL,
			client_ip TEXT    NOT NULL,
			domain    TEXT    NOT NULL,
			blocked   INTEGER NOT NULL
		)`, "INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "old.db")
			old, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatalf("open old db: %v", err)
			}
			if _, err := old.Exec(tc.schema); err != nil {
				t.Fatalf("create old schema: %v", err)
			}
			ts := time.Now().UTC().Format(time.RFC3339)
			for _, r := range []struct {
				domain  string
				blocked int
			}{{"old-blocked.example.", 1}, {"old-allowed.example.", 0}} {
				args := []any{ts, "1.1.1.1", r.domain, r.blocked}
				if strings.Contains(tc.insert, "synthesized") {
					args = append(args, r.blocked)
				}
				if _, err := old.Exec(tc.insert, args...); err != nil {
					t.Fatalf("seed old row: %v", err)
				}
			}
			if err := old.Close(); err != nil {
				t.Fatalf("close old db: %v", err)
			}

			db, err := NewDBLogger(path, "all", 20*time.Millisecond, 0)
			if err != nil {
				t.Fatalf("NewDBLogger on old db: %v", err)
			}
			defer db.Close()
			checkBlockSourceColumn(t, db.db)

			db.Log(Record{ClientIP: "1.1.1.1", Domain: "new-cname.example.", Blocked: true, Synthesized: true, BlockSource: BlockedByCNAME})
			waitRows(t, db, 3)
			rows, err := db.Recent(context.Background(), 10)
			if err != nil {
				t.Fatalf("Recent: %v", err)
			}
			want := map[string]string{
				"old-blocked.example.": "name",
				"old-allowed.example.": "",
				"new-cname.example.":   "cname",
			}
			if len(rows) != len(want) {
				t.Fatalf("rows = %+v, want %d", rows, len(want))
			}
			for _, r := range rows {
				if w, ok := want[r.Domain]; !ok || r.BlockedBy != w {
					t.Errorf("%s blocked_by = %q, want %q", r.Domain, r.BlockedBy, w)
				}
			}

			// Re-running the migration is a no-op, not an error.
			if err := migrate(db.db); err != nil {
				t.Errorf("second migrate: %v", err)
			}
		})
	}
}

func TestFileLogger_CNAMEMarker(t *testing.T) {
	// CL 117 req 9: a CNAME-blocked line is "<ts> BLOCK <client> <domain> CNAME";
	// a name-blocked line has no marker; ALLOW lines keep CACHED and FAILED.
	for _, mode := range []string{"all", "blocked"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "queries.log")
			l := newTestFileLogger(t, path, mode)
			l.Log(Record{ClientIP: "1.2.3.4", Domain: "metrics.shop.example.", Blocked: true, Synthesized: true, BlockSource: BlockedByCNAME})
			l.Log(Record{ClientIP: "1.2.3.4", Domain: "ads.example.com.", Blocked: true, Synthesized: true, BlockSource: BlockedByName})
			l.Log(Record{ClientIP: "1.2.3.4", Domain: "cdn.example.com.", CacheHit: true})
			l.Log(Record{ClientIP: "1.2.3.4", Domain: "dead.example.com.", Rcode: rcodeServerFailure, Synthesized: true})
			l.Log(Record{ClientIP: "1.2.3.4", Domain: "ok.example.com.", BlockSource: BlockedByCNAME})
			closeFileLogger(t, l)

			got := map[string]string{}
			for _, line := range strings.Split(strings.TrimSpace(readAll(t, path)), "\n") {
				f := strings.Fields(line)
				if len(f) < 4 {
					t.Fatalf("short line %q", line)
				}
				if _, err := time.Parse(time.RFC3339, f[0]); err != nil {
					t.Errorf("line %q does not start with an RFC 3339 time", line)
				}
				rest := append([]string{f[1], f[2]}, f[4:]...)
				got[f[3]] = strings.Join(rest, " ")
			}
			want := map[string]string{
				"metrics.shop.example.": "BLOCK 1.2.3.4 CNAME",
				"ads.example.com.":      "BLOCK 1.2.3.4",
			}
			if mode == "all" {
				want["cdn.example.com."] = "ALLOW 1.2.3.4 CACHED"
				want["dead.example.com."] = "ALLOW 1.2.3.4 FAILED"
				want["ok.example.com."] = "ALLOW 1.2.3.4"
			}
			if len(got) != len(want) {
				t.Errorf("lines = %v, want %v", got, want)
			}
			for d, w := range want {
				if got[d] != w {
					t.Errorf("line for %s = %q (without time and domain), want %q", d, got[d], w)
				}
			}
		})
	}
}
