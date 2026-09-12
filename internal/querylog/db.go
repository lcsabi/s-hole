package querylog

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS queries (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	ts        TEXT    NOT NULL,
	client_ip TEXT    NOT NULL,
	domain    TEXT    NOT NULL,
	blocked   INTEGER NOT NULL,
	cache_hit INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_queries_ts      ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_queries_blocked ON queries(blocked);
CREATE INDEX IF NOT EXISTS idx_queries_domain  ON queries(domain);
`

// migrate brings an existing queries table up to the current schema. The
// CREATE TABLE above only ever creates the table with today's columns, so a
// database from an older build is missing the columns added since. SQLite has
// no "ADD COLUMN IF NOT EXISTS", so each additive column is gated on a
// table_info probe (ensureColumn). A newly created database already has every
// column, so migrate is a no-op on it. Existing rows take the column DEFAULT,
// so cache_hit reads 0 (not cached) for rows written before the upgrade.
func migrate(db *sql.DB) error {
	return ensureColumn(db, "queries", "cache_hit", "ALTER TABLE queries ADD COLUMN cache_hit INTEGER NOT NULL DEFAULT 0")
}

// ensureColumn runs ddl to add column to table only when the column is not
// already present. It reads PRAGMA table_info, which lists every column of the
// table, and skips the ALTER when the column exists so the call is idempotent.
func ensureColumn(db *sql.DB, table, column, ddl string) error {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		// PRAGMA table_info columns: cid, name, type, notnull, dflt_value, pk.
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return rows.Err() // already present
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec(ddl)
	return err
}

type entry struct {
	ts       time.Time
	clientIP string
	domain   string
	blocked  bool
	cacheHit bool
}

// Tuning constants for the async writer. flushBatchSize is the largest
// batch a single transaction commits; queryQueueSize is the channel
// capacity (entries beyond this are dropped to avoid blocking the DNS
// hot path). These are deliberately not config-exposed: changing them
// without a benchmark is unlikely to help, and the defaults already
// match the project's "small home network" target.
const (
	flushBatchSize  = 100
	queryQueueSize  = 1000
	pruneTickPeriod = 1 * time.Hour
)

// DBLogger writes queries asynchronously to a SQLite database.
// Entries are batched and flushed on a configurable interval or when
// flushBatchSize accumulate, whichever comes first. An optional
// retention prune deletes rows older than retentionDays once an hour.
//
// dropped counts entries refused by Log because the internal channel was
// full. Operators monitor it via shole_query_log_dropped_total on
// /metrics; a non-zero value means the configured flush interval cannot
// keep up with query volume.
type DBLogger struct {
	db            *sql.DB
	ch            chan entry
	done          chan struct{}
	wg            sync.WaitGroup
	logQueries    string
	flushInterval time.Duration
	retentionDays int // 0 = retain forever
	dropped       atomic.Uint64
}

// pragmas applied on every open. WAL + synchronous=NORMAL dramatically reduces
// write amplification on flash/SD storage compared to the default journal mode.
// busy_timeout makes a statement wait for a held lock instead of failing
// immediately with SQLITE_BUSY; defence against an external process (e.g. the
// sqlite3 CLI) touching the file; internal contention is already removed by
// SetMaxOpenConns(1) in NewDBLogger (b/038). These per-connection pragmas
// (all but journal_mode, which is stored in the file) reliably apply because
// that single connection serves every query.
const pragmas = `
PRAGMA busy_timeout=5000;
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=-8000;
PRAGMA temp_store=MEMORY;
`

// NewDBLogger opens (creating if needed) a SQLite database at path,
// applies the WAL pragmas, ensures the schema exists, and starts the
// background writer goroutine. retentionDays bounds row history; 0
// disables the prune. Returns an error if the database cannot be opened
// or initialised; callers should treat the error as non-fatal and
// continue without SQLite logging.
func NewDBLogger(path, logQueries string, flushInterval time.Duration, retentionDays int) (*DBLogger, error) {
	// Defense-in-depth: config.ParsedDBFlushInterval already rejects a
	// non-positive interval before main reaches here (b/046). Guard the
	// constructor too so the type can never panic its writer goroutine on
	// time.NewTicker regardless of caller.
	if flushInterval <= 0 {
		return nil, fmt.Errorf("flush interval must be positive, got %s", flushInterval)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// Serialise all access through one connection (b/038). SQLite allows a
	// single writer at a time; with the default multi-connection pool the
	// async batch writer and the retention prune (both writers) can land on
	// different connections and collide with SQLITE_BUSY, silently skipping a
	// prune. One connection makes database/sql queue callers instead, and
	// guarantees the per-connection pragmas below apply to the connection that
	// serves every query. At home-network query volume the lost read
	// concurrency is immaterial.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(pragmas); err != nil {
		_ = db.Close() // best-effort: the Exec error is the one worth reporting
		return nil, fmt.Errorf("pragmas: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	l := &DBLogger{
		db:            db,
		ch:            make(chan entry, queryQueueSize),
		done:          make(chan struct{}),
		logQueries:    logQueries,
		flushInterval: flushInterval,
		retentionDays: retentionDays,
	}
	l.wg.Add(1)
	go l.run()
	if retentionDays > 0 {
		l.wg.Add(1)
		go l.runPrune()
	}
	return l, nil
}

// runPrune deletes rows older than retentionDays once an hour. Runs in
// its own goroutine; honors the same done channel as the writer.
func (d *DBLogger) runPrune() {
	defer d.wg.Done()
	tick := time.NewTicker(pruneTickPeriod)
	defer tick.Stop()
	// Run once immediately on startup so a newly-enabled retention takes
	// effect without waiting an hour.
	d.prune()
	for {
		select {
		case <-tick.C:
			d.prune()
		case <-d.done:
			return
		}
	}
}

func (d *DBLogger) prune() {
	cutoff := time.Now().Add(-time.Duration(d.retentionDays) * 24 * time.Hour).Format(time.RFC3339)
	res, err := d.db.Exec("DELETE FROM queries WHERE ts < ?", cutoff)
	if err != nil {
		logger.Warn("retention prune failed", "err", err, "cutoff", cutoff)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		logger.Info("retention prune", "deleted", n, "cutoff", cutoff)
	}
}

// Log enqueues a single entry for asynchronous insertion. Respects the
// logQueries filter and silently drops if the internal channel is full;
// logging completeness is subordinate to DNS handler latency. Never
// blocks the caller.
func (d *DBLogger) Log(rec Record) {
	if d.logQueries == "none" {
		return
	}
	if d.logQueries == "blocked" && !rec.Blocked {
		return
	}
	select {
	case d.ch <- entry{ts: time.Now(), clientIP: rec.ClientIP, domain: rec.Domain, blocked: rec.Blocked, cacheHit: rec.CacheHit}:
	default:
		// Drop under extreme load rather than blocking a DNS goroutine.
		// The counter is surfaced via /metrics so operators see when this
		// fires; a sustained non-zero rate means flush_interval is too
		// long for the query volume.
		d.dropped.Add(1)
	}
}

// Dropped returns the cumulative number of entries that Log refused
// because the internal channel was full. Used by the /metrics endpoint
// to surface back-pressure to operators.
func (d *DBLogger) Dropped() uint64 {
	return d.dropped.Load()
}

// LogQueries returns the effective log_queries filter ("all", "blocked", or
// "none"). The history endpoint reports it so the dashboard can label the graph
// honestly: under "blocked" the log holds only blocked rows, so the graph shows
// a single blocked line, and under "none" it shows an empty state.
func (d *DBLogger) LogQueries() string {
	return d.logQueries
}

// Close signals the writer goroutine to flush remaining entries and waits for
// it to finish before closing the database. This prevents data loss on shutdown.
func (d *DBLogger) Close() error {
	close(d.done)
	d.wg.Wait()
	return d.db.Close()
}

func (d *DBLogger) run() {
	defer d.wg.Done()
	batch := make([]entry, 0, flushBatchSize)
	tick := time.NewTicker(d.flushInterval)
	defer tick.Stop()

	for {
		select {
		case e := <-d.ch:
			batch = append(batch, e)
			if len(batch) >= flushBatchSize {
				d.flush(batch)
				batch = batch[:0]
			}
		case <-tick.C:
			if len(batch) > 0 {
				d.flush(batch)
				batch = batch[:0]
			}
		case <-d.done:
			// Non-blocking drain: use select so len(ch) is not sampled
			// separately from the receive (avoids TOCTOU race).
		drain:
			for {
				select {
				case e := <-d.ch:
					batch = append(batch, e)
				default:
					break drain
				}
			}
			if len(batch) > 0 {
				d.flush(batch)
			}
			return
		}
	}
}

func (d *DBLogger) flush(batch []entry) {
	// Begin/Prepare/Commit failures discard the entire batch; log the size
	// so operators can correlate disk-full or DB-locked incidents with the
	// number of lost rows.
	tx, err := d.db.Begin()
	if err != nil {
		logger.Error("db begin failed, dropping batch", "entries", len(batch), "err", err)
		return
	}
	stmt, err := tx.Prepare("INSERT INTO queries(ts,client_ip,domain,blocked,cache_hit) VALUES(?,?,?,?,?)")
	if err != nil {
		logger.Error("db prepare failed, dropping batch", "entries", len(batch), "err", err)
		_ = tx.Rollback() // the Prepare error above is the actionable one
		return
	}
	defer stmt.Close()

	for _, e := range batch {
		if _, err := stmt.Exec(e.ts.Format(time.RFC3339), e.clientIP, e.domain, b2i(e.blocked), b2i(e.cacheHit)); err != nil {
			logger.Warn("db insert", "err", err)
		}
	}
	if err := tx.Commit(); err != nil {
		logger.Error("db commit failed, dropping batch", "entries", len(batch), "err", err)
	}
}

// Entry holds a name/count pair (used for top-domain results).
type Entry struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// QueryRow is a single row returned from the database.
type QueryRow struct {
	TS       string `json:"ts"`
	ClientIP string `json:"client_ip"`
	Domain   string `json:"domain"`
	Blocked  bool   `json:"blocked"`
}

// QueryFilter holds optional filters for a recent-query read. The zero value
// matches every row, so Search with a zero filter is a plain Recent.
//
// Every field filters over a stored column, so a filter can only ever match what
// the query-privacy mode wrote (CL 72 masks the client at write time). A client
// filter therefore matches the stored, already-masked value, never a raw address.
type QueryFilter struct {
	Domain  string // case-insensitive substring of the domain; "" matches any
	Client  string // exact match on the stored (masked) client; "" matches any
	Blocked *bool  // nil matches any; else true for blocked, false for allowed
}

// Search returns the last n queries that match f, ordered newest-first. ctx is
// honored as a query deadline; HTTP handlers pass r.Context() so an aborted
// client connection unblocks the database query.
//
// The conditions are built dynamically and every value is bound as a parameter,
// so no caller input reaches the SQL text. The domain filter is a substring
// LIKE, which cannot use idx_queries_domain; at home scale the retention-bounded
// table and the LIMIT keep the scan cheap (see the no-index note in CL 74).
func (d *DBLogger) Search(ctx context.Context, f QueryFilter, n int) ([]QueryRow, error) {
	var where []string
	var args []any
	if f.Domain != "" {
		// Domains are stored lowercase, so lowercasing the term makes the match
		// case-insensitive. Escape the LIKE metacharacters so a typed % or _ is a
		// literal, not a wildcard.
		where = append(where, "domain LIKE ? ESCAPE '\\'")
		args = append(args, "%"+escapeLike(strings.ToLower(f.Domain))+"%")
	}
	if f.Client != "" {
		where = append(where, "client_ip = ?")
		args = append(args, f.Client)
	}
	if f.Blocked != nil {
		where = append(where, "blocked = ?")
		args = append(args, b2i(*f.Blocked))
	}

	q := "SELECT ts, client_ip, domain, blocked FROM queries"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, n)

	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// Recent returns the last n queries ordered newest-first. It is Search with an
// empty filter, so the two share one query builder.
func (d *DBLogger) Recent(ctx context.Context, n int) ([]QueryRow, error) {
	return d.Search(ctx, QueryFilter{}, n)
}

// TopBlocked returns the n most-blocked domains across all recorded
// queries. ctx is honored as a query deadline.
func (d *DBLogger) TopBlocked(ctx context.Context, n int) ([]Entry, error) {
	// ORDER BY cnt DESC, domain ASC: the domain tie-break makes equal-count rows
	// deterministic (SQLite leaves the order of a plain ORDER BY cnt DESC
	// unspecified) and matches the in-memory topN tie-break, so the dashboard's
	// "Since start" and "All time" tabs order ties identically (b/056).
	rows, err := d.db.QueryContext(ctx, `
		SELECT domain, COUNT(*) AS cnt
		FROM queries WHERE blocked=1
		GROUP BY domain
		ORDER BY cnt DESC, domain ASC
		LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Name, &e.Count); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Bucket is one time bucket in a query-volume history series. Cached is the
// subset of Total served from the response cache. Blocked and Cached do not
// overlap (a blocked query never reaches the cache), so the forwarded count is
// the remainder: Total - Blocked - Cached.
type Bucket struct {
	Start   int64 `json:"start"` // bucket start, unix seconds (UTC)
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
	Cached  int64 `json:"cached"`
}

// History returns a dense per-bucket count series covering roughly the last
// window, each bucket wide, oldest first. Buckets with no rows are present with
// zero counts so the graph draws a continuous line. ctx is honored as a query
// deadline.
//
// ts is RFC3339 text with a timezone offset, so the bucket key is computed from
// the UTC epoch (strftime('%s', ts) parses the offset) rather than from the
// text. The WHERE cutoff stays an RFC3339 string to reuse idx_queries_ts and to
// match the prune path. The only imprecision is a one-bucket boundary wobble at
// the far window edge across a DST change, which is cosmetic on a graph.
func (d *DBLogger) History(ctx context.Context, window, bucket time.Duration) ([]Bucket, error) {
	bucketSecs := int64(bucket / time.Second)
	if bucketSecs <= 0 {
		bucketSecs = 1
	}
	n := int(window / bucket)
	if n <= 0 {
		n = 1
	}

	cutoff := time.Now().Add(-window).Format(time.RFC3339)
	rows, err := d.db.QueryContext(ctx, `
		SELECT (CAST(strftime('%s', ts) AS INTEGER) / ?1) * ?1 AS bucket_start,
		       COUNT(*)       AS total,
		       SUM(blocked)   AS blocked,
		       SUM(cache_hit) AS cached
		FROM queries
		WHERE ts >= ?2
		GROUP BY bucket_start`, bucketSecs, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[int64]Bucket)
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.Start, &b.Total, &b.Blocked, &b.Cached); err != nil {
			return nil, err
		}
		counts[b.Start] = b
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Emit a dense, zero-filled series so gaps draw as a line at zero. The last
	// bucket is the (partial) current one; align it the same way the SQL groups.
	last := (time.Now().Unix() / bucketSecs) * bucketSecs
	first := last - int64(n-1)*bucketSecs
	out := make([]Bucket, 0, n)
	for start := first; start <= last; start += bucketSecs {
		if b, ok := counts[start]; ok {
			b.Start = start
			out = append(out, b)
		} else {
			out = append(out, Bucket{Start: start})
		}
	}
	return out, nil
}

// escapeLike escapes the LIKE metacharacters so a user-typed term matches
// literally. The backslash is the ESCAPE character in Search, so escape it
// first, then the % and _ wildcards.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

// b2i maps a bool to the 0/1 the blocked and cache_hit columns store.
func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func scanRows(rows *sql.Rows) ([]QueryRow, error) {
	var out []QueryRow
	for rows.Next() {
		var r QueryRow
		var blocked int
		if err := rows.Scan(&r.TS, &r.ClientIP, &r.Domain, &blocked); err != nil {
			return nil, err
		}
		r.Blocked = blocked == 1
		out = append(out, r)
	}
	return out, rows.Err()
}
