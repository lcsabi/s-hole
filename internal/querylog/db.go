package querylog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
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
	blocked     INTEGER NOT NULL,
	cache_hit   INTEGER NOT NULL DEFAULT 0,
	rcode       INTEGER NOT NULL DEFAULT 0,
	synthesized INTEGER NOT NULL DEFAULT 0,
	block_source INTEGER NOT NULL DEFAULT 0
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
// so cache_hit reads 0 (not cached), rcode/synthesized read 0 (so an old
// row is never counted as a failed query), and block_source reads 0 (a block
// on the queried name, the only kind before CL 117), for rows written before
// the upgrade.
//
// It also rewrites rows from builds before CL 93 into today's form. Those
// stored ts in the host's local time with an offset, which compares wrongly
// as text after a time-zone or DST change; they now hold UTC ("...Z").
// They stored the domain with the client's letter case; they now hold it in
// lowercase (b/082). SQLite's strftime reads the offset. A row whose ts it
// cannot read is left as it is, so the migration cannot fail on one bad row.
// A database that is already migrated matches no row, so the cost after the
// first start is one index scan.
func migrate(db *sql.DB) error {
	if err := ensureColumn(db, "queries", "cache_hit", "ALTER TABLE queries ADD COLUMN cache_hit INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureColumn(db, "queries", "rcode", "ALTER TABLE queries ADD COLUMN rcode INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureColumn(db, "queries", "synthesized", "ALTER TABLE queries ADD COLUMN synthesized INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureColumn(db, "queries", "block_source", "ALTER TABLE queries ADD COLUMN block_source INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	res, err := db.Exec(`UPDATE queries SET ts = strftime('%Y-%m-%dT%H:%M:%SZ', ts)
		WHERE ts NOT LIKE '%Z' AND strftime('%Y-%m-%dT%H:%M:%SZ', ts) IS NOT NULL`)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		logger.Info("query log timestamps converted to UTC", "rows", n)
	}
	_, err = db.Exec("UPDATE queries SET domain = lower(domain) WHERE domain <> lower(domain)")
	return err
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
	ts          time.Time
	clientIP    string
	domain      string
	blocked     bool
	cacheHit    bool
	rcode       int
	synthesized bool
	blockSource BlockSource
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
	walPath       string // the database path plus "-wal"
	ch            chan entry
	done          chan struct{}
	wg            sync.WaitGroup
	logQueries    string
	flushInterval time.Duration
	retentionDays int // 0 = retain forever
	dropped       atomic.Uint64
	// purgeCh carries Purge requests to the writer goroutine, which owns the
	// batch and the queue, so a purge cannot race a flush.
	purgeCh chan chan error
}

// pragmas applied on every open. WAL + synchronous=NORMAL dramatically reduces
// write amplification on flash/SD storage compared to the default journal mode.
// busy_timeout makes a statement wait for a held lock instead of failing
// immediately with SQLITE_BUSY; defence against an external process (e.g. the
// sqlite3 CLI) touching the file; internal contention is already removed by
// SetMaxOpenConns(1) in NewDBLogger (b/038). These per-connection pragmas
// (all but journal_mode, which is stored in the file) reliably apply because
// that single connection serves every query.
//
// secure_delete=ON makes a DELETE overwrite the deleted rows with zeros.
// Without it SQLite only marks the space free, and a pruned or purged query
// stayed readable in the file (b/077). FAST is not enough: it leaves whole
// freed pages untouched. journal_size_limit=-1 stops SQLite from making the
// WAL shorter after a commit: the blocks that a truncate frees keep the old
// page images (PRIV-16). s-hole makes the WAL shorter only after wipeWAL has
// overwritten it with zeros (the TRUNCATE checkpoint of wipeWAL, then the
// close in Close); after a failed wipe, the last close still deletes it (see
// warnWipe).
const pragmas = `
PRAGMA busy_timeout=5000;
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA secure_delete=ON;
PRAGMA journal_size_limit=-1;
PRAGMA cache_size=-8000;
PRAGMA temp_store=MEMORY;
`

// NewDBLogger opens (creating if needed) a SQLite database at path,
// applies the WAL pragmas, ensures the schema exists, overwrites a leftover
// WAL with zeros (wipeWAL), and starts the background writer goroutine. retentionDays bounds row history; 0
// disables the prune. Returns an error if the database cannot be opened
// or initialised; callers should treat the error as non-fatal and
// continue without SQLite logging.
func NewDBLogger(path, logQueries string, flushInterval time.Duration, retentionDays int) (*DBLogger, error) {
	// Defense-in-depth: config.Load (setDuration) already rejects a
	// non-positive query_log.flush_interval before main reaches here (b/046). Guard the
	// constructor too so the type can never panic its writer goroutine on
	// time.NewTicker regardless of caller.
	if flushInterval <= 0 {
		return nil, fmt.Errorf("flush interval must be positive, got %s", flushInterval)
	}
	if err := preparePrivateDB(path); err != nil {
		return nil, fmt.Errorf("create db: %w", err)
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
		walPath:       path + "-wal",
		ch:            make(chan entry, queryQueueSize),
		done:          make(chan struct{}),
		logQueries:    logQueries,
		flushInterval: flushInterval,
		retentionDays: retentionDays,
		purgeCh:       make(chan chan error),
	}
	// A WAL that a crash left, or that the migration wrote, can hold page
	// images of rows that a later prune deletes. Zero it now, before the
	// writer starts.
	l.wipeWALOrWarn(context.Background(), "start")
	l.wg.Add(1)
	go l.run()
	if retentionDays > 0 {
		l.wg.Add(1)
		go l.runPrune()
	}
	return l, nil
}

// preparePrivateDB makes the query database owner-only before SQLite opens
// it: it creates a missing file with mode 0600, and sets an existing file and
// its -wal and -shm files to 0600. SQLite creates the -wal and -shm files with
// the mode of the database file, so they follow. A database written by an
// older build was 0644, readable by every account on the host (b/076). A
// failed chmod is a WARN, not an error: the history then stays as readable
// as before, which is no reason to stop recording it.
func preparePrivateDB(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: query_log.database from the config
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Warn("query database permissions could not be set to owner-only", "path", p, "err", err)
		}
	}
	return nil
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

// prune deletes the rows older than retentionDays. secure_delete overwrites
// them in the database pages, and wipeWAL then copies those pages into the
// database file and overwrites the WAL with zeros, so a deleted row is gone
// from both files, not only from the table (b/077), and from the disk blocks
// that the WAL frees (PRIV-16). It holds the one connection for the DELETE
// and the wipe, so no flush runs between them.
func (d *DBLogger) prune() {
	ctx := context.Background()
	c, err := d.db.Conn(ctx)
	if err != nil {
		logger.Warn("query log retention prune failed", "err", err)
		return
	}
	defer func() { _ = c.Close() }() // returns the connection to the pool
	cutoff := time.Now().UTC().Add(-time.Duration(d.retentionDays) * 24 * time.Hour).Format(time.RFC3339)
	res, err := c.ExecContext(ctx, "DELETE FROM queries WHERE ts < ?", cutoff)
	if err != nil {
		logger.Warn("query log retention prune failed", "err", err, "cutoff", cutoff)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return
	}
	logger.Info("query log retention prune done", "deleted", n, "cutoff", cutoff)
	if err := d.wipeWAL(ctx, c); err != nil {
		warnWipe("prune", err)
	}
}

// errClosed is returned by Purge after Close.
var errClosed = errors.New("query log database is closed")

// Purge deletes the whole query history: the queued entries, every row, and
// the row counter, then rebuilds the file. secure_delete has already zeroed
// the deleted rows; VACUUM writes a compact new file without the free pages,
// and wipeWAL, before and after the VACUUM, overwrites the WAL with zeros and
// empties it. Resetting sqlite_sequence matters too: the next row id would
// otherwise tell how many queries were ever recorded. The writer goroutine runs the purge, so no batch in flight
// is written after it, and the purge holds the one connection for every
// step, so a prune does not run between them.
func (d *DBLogger) Purge(ctx context.Context) error {
	reply := make(chan error, 1)
	select {
	case d.purgeCh <- reply:
	case <-d.done:
		return errClosed
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *DBLogger) purgeAll() error {
	ctx := context.Background()
	c, err := d.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }() // returns the connection to the pool
	exec := func(q string) func() error {
		return func() error {
			_, err := c.ExecContext(ctx, q)
			return err
		}
	}
	wipe := func() error { return d.wipeWAL(ctx, c) }
	for _, step := range []struct {
		name string
		run  func() error
	}{
		{"DELETE FROM queries", exec("DELETE FROM queries")},
		{"DELETE FROM sqlite_sequence", exec("DELETE FROM sqlite_sequence WHERE name = 'queries'")},
		{"WAL overwrite", wipe},
		{"VACUUM", exec("VACUUM")},
		{"WAL overwrite", wipe},
	} {
		if err := step.run(); err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
	}
	return nil
}

// errWALBusy is the error of wipeWAL when SQLite could not copy every WAL
// frame into the database, or another connection wrote to the database. The
// WAL then holds data that is not in the database file, so it must not be
// overwritten.
var errWALBusy = errors.New("another connection uses the query database")

// walFreeHook, when not nil, is called with the WAL path after wipeWAL has
// overwritten the WAL and before SQLite truncates or deletes it.
// walCheckpointHook, when not nil, is called after the RESTART checkpoint
// and before BEGIN IMMEDIATE, where another process could write. Only tests
// set them; production never writes them.
var (
	walFreeHook       func(walPath string)
	walCheckpointHook func()
)

// wipeWAL overwrites the WAL with zeros, then truncates it to zero bytes
// (PRIV-16). SQLite frees the WAL blocks without overwriting them, so
// without the wipe the page images in the WAL (with domains, clients, and
// times) would stay in free disk blocks after a prune, a purge, or a stop. c must be the one
// connection, held by the caller, so no other statement of s-hole runs
// during the wipe.
//
// The order keeps the live history safe:
//
//  1. wal_checkpoint(RESTART) copies every frame into the database file and
//     syncs it. wipeWAL goes on only if SQLite copied every frame.
//  2. BEGIN IMMEDIATE takes the write lock, so no other process can add a
//     frame. If PRAGMA data_version changed, another process wrote after
//     the checkpoint, and its frames are not in the database file yet.
//  3. ZeroFile overwrites the WAL, the header first (see ZeroFile). SQLite
//     reads no frame of a WAL that it has copied completely: it writes the
//     next transaction from the start of the WAL with a new header.
//  4. ROLLBACK ends the empty transaction, and wal_checkpoint(TRUNCATE)
//     truncates the WAL that holds only zeros now.
//
// wipeWAL opens only the -wal file: SQLite holds its POSIX locks on the
// database and -shm files, and closing another descriptor of those files
// would drop the locks. On an error the WAL is not truncated, so its data
// stays in the file, where the next wipe can reach it.
func (d *DBLogger) wipeWAL(ctx context.Context, c *sql.Conn) error {
	var busy, frames, copied int
	if err := c.QueryRowContext(ctx, "PRAGMA wal_checkpoint(RESTART)").Scan(&busy, &frames, &copied); err != nil {
		return err
	}
	if busy != 0 || frames != copied {
		return fmt.Errorf("%w: checkpoint copied %d of %d frames", errWALBusy, copied, frames)
	}
	var before, after int64
	if err := c.QueryRowContext(ctx, "PRAGMA data_version").Scan(&before); err != nil {
		return err
	}
	if walCheckpointHook != nil {
		walCheckpointHook()
	}
	if _, err := c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	err := c.QueryRowContext(ctx, "PRAGMA data_version").Scan(&after)
	if err == nil && after != before {
		err = fmt.Errorf("%w: another connection wrote after the checkpoint", errWALBusy)
	}
	if err == nil {
		if err = ZeroFile(d.walPath); errors.Is(err, fs.ErrNotExist) {
			err = nil // no WAL file: nothing to overwrite
		}
	}
	if _, rerr := c.ExecContext(ctx, "ROLLBACK"); err == nil {
		err = rerr
	}
	if err != nil {
		return err
	}
	if walFreeHook != nil {
		walFreeHook(d.walPath)
	}
	_, err = c.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

// wipeWALOrWarn runs wipeWAL on a connection of its own and logs a failure
// as a WARN. when names the point: "start" or "stop".
func (d *DBLogger) wipeWALOrWarn(ctx context.Context, when string) {
	c, err := d.db.Conn(ctx)
	if err == nil {
		err = d.wipeWAL(ctx, c)
		_ = c.Close() // returns the connection to the pool; it does not close it
	}
	if err != nil {
		warnWipe(when, err)
	}
}

// warnWipe logs a failed wipeWAL. The WAL then keeps its data until the next
// wipe; at a stop, the close of the last connection deletes it without the
// overwrite.
func warnWipe(when string, err error) {
	logger.Warn("query log WAL overwrite failed", "at", when, "err", err,
		"hint", "stop any other program that uses the query database; if err says not overwritten, see docs/TROUBLESHOOTING.md")
}

// StaleReport describes the stored rows that hold more than the current
// query_log settings would write: rows written under an older, less private
// setting. Rows is 0 when there are none. Retention removes the newest of
// them last, so Expires is that row's time plus the retention period; it is
// zero when retention is off.
type StaleReport struct {
	Rows    int64
	Newest  time.Time // time of the newest stale row
	Expires time.Time // when retention removes the last stale row; zero if retention is off
}

// StaleRows counts the stored rows that hold more than the current settings
// would write: any row under mode "none", an allowed row under "blocked", a
// row with a client address under clients "drop", and a row whose client is
// not masked under clients "subnet". It only reads. s-hole never rewrites or
// deletes such rows on its own: the operator decides, with a purge or by
// waiting for retention. main logs the result as a privacy warning.
//
// The query scans the table when the database holds no stale rows (no index
// covers client_ip), which is about 100 to 200 ms for 350,000 rows on a
// Raspberry Pi 5. It runs at startup and once an hour, off the DNS path.
func (d *DBLogger) StaleRows(ctx context.Context, clients string) (StaleReport, error) {
	var conds []string
	var args []any
	switch d.logQueries {
	case "none":
		conds = append(conds, "1")
	case "blocked":
		conds = append(conds, "blocked = 0")
	}
	switch clients {
	case "drop", "":
		conds = append(conds, "client_ip != ''")
	case "subnet":
		unmasked, err := d.unmaskedClients(ctx)
		if err != nil {
			return StaleReport{}, err
		}
		if len(unmasked) > 0 {
			conds = append(conds, "client_ip IN (?"+strings.Repeat(",?", len(unmasked)-1)+")")
			for _, c := range unmasked {
				args = append(args, c)
			}
		}
	}
	if len(conds) == 0 {
		return StaleReport{}, nil
	}
	var rep StaleReport
	var newest sql.NullString
	err := d.db.QueryRowContext(ctx, "SELECT COUNT(*), MAX(ts) FROM queries WHERE "+strings.Join(conds, " OR "), args...).Scan(&rep.Rows, &newest)
	if err != nil {
		return StaleReport{}, err
	}
	if rep.Rows == 0 || !newest.Valid {
		return StaleReport{}, nil
	}
	if t, err := time.Parse(time.RFC3339, newest.String); err == nil {
		rep.Newest = t
		if d.retentionDays > 0 {
			rep.Expires = t.Add(time.Duration(d.retentionDays) * 24 * time.Hour)
		}
	}
	return rep, nil
}

// unmaskedClients returns the distinct stored client values that subnet
// masking would change: full addresses, and values it cannot read. A home
// has a few dozen.
func (d *DBLogger) unmaskedClients(ctx context.Context) ([]string, error) {
	rows, err := d.db.QueryContext(ctx, "SELECT DISTINCT client_ip FROM queries WHERE client_ip != ''")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		if MaskClientIP(c, "subnet") != c {
			out = append(out, c)
		}
	}
	return out, rows.Err()
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
	case d.ch <- entry{ts: time.Now(), clientIP: rec.ClientIP, domain: rec.Domain, blocked: rec.Blocked, cacheHit: rec.CacheHit, rcode: rec.Rcode, synthesized: rec.Synthesized, blockSource: rec.BlockSource}:
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

// LogQueries returns the effective query_log.mode filter ("all", "blocked", or
// "none"). The history endpoint reports it so the dashboard can label the graph
// honestly: under "blocked" the log holds only blocked rows, so the graph shows
// a single blocked line, and under "none" it shows an empty state.
func (d *DBLogger) LogQueries() string {
	return d.logQueries
}

// Close signals the writer goroutine to flush remaining entries and waits for
// it to finish before closing the database. This prevents data loss on shutdown.
// Call Close once; a second call panics.
//
// Before it closes the database, Close overwrites the WAL with zeros
// (wipeWAL): SQLite deletes the WAL when the last connection closes, and the
// freed blocks would keep its page images (PRIV-16).
func (d *DBLogger) Close() error {
	close(d.done)
	d.wg.Wait()
	d.wipeWALOrWarn(context.Background(), "stop")
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
		case reply := <-d.purgeCh:
			// Discard what is not written yet, then delete what is.
			batch = batch[:0]
		discard:
			for {
				select {
				case <-d.ch:
				default:
					break discard
				}
			}
			reply <- d.purgeAll()
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
		logger.Error("query log begin failed, dropping batch", "entries", len(batch), "err", err)
		return
	}
	stmt, err := tx.Prepare("INSERT INTO queries(ts,client_ip,domain,blocked,cache_hit,rcode,synthesized,block_source) VALUES(?,?,?,?,?,?,?,?)")
	if err != nil {
		logger.Error("query log prepare failed, dropping batch", "entries", len(batch), "err", err)
		_ = tx.Rollback() // the Prepare error above is the actionable one
		return
	}
	defer stmt.Close()

	for _, e := range batch {
		if _, err := stmt.Exec(e.ts.UTC().Format(time.RFC3339), e.clientIP, e.domain, b2i(e.blocked), b2i(e.cacheHit), e.rcode, b2i(e.synthesized), int(e.blockSource)); err != nil {
			logger.Warn("query log insert failed", "err", err)
		}
	}
	if err := tx.Commit(); err != nil {
		logger.Error("query log commit failed, dropping batch", "entries", len(batch), "err", err)
	}
}

// Entry holds a name/count pair (used for top-domain results).
type Entry struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// QueryRow is a single row returned from the database. Rcode and Synthesized
// are the raw outcome columns; Outcome collapses them into the operator-facing
// status the dashboard and export show.
type QueryRow struct {
	TS          string `json:"ts"`
	ClientIP    string `json:"client_ip"`
	Domain      string `json:"domain"`
	Blocked     bool   `json:"blocked"`
	Rcode       int    `json:"rcode"`
	Synthesized bool   `json:"synthesized"`
	// BlockedBy says what matched a blocked query: "name" (the queried name
	// is on a list) or "cname" (a CNAME target in its answer is). It is empty
	// on an allowed row.
	BlockedBy string `json:"blocked_by,omitempty"`
}

// Outcome collapses the row's stored columns into the operator-facing status:
// "blocked", "unresolved" (s-hole synthesized a SERVFAIL), "upstream_error" (a
// relayed SERVFAIL/REFUSED), or "allowed" (everything else, including NXDOMAIN,
// which is a valid answer). It shares the failure rule with the Record helpers
// via isUnresolved/isUpstreamError, so the API label, the flat log, and the
// graph never disagree. The block check comes first: a blocked reply is
// synthesized, but its rcode is never a failure, so it is reported as blocked.
func (r QueryRow) Outcome() string {
	switch {
	case r.Blocked:
		return "blocked"
	case isUnresolved(r.Rcode, r.Synthesized):
		return "unresolved"
	case isUpstreamError(r.Rcode, r.Synthesized):
		return "upstream_error"
	default:
		return "allowed"
	}
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
	Outcome string // "" matches any; "unresolved" or "upstream-error" narrows to that failure
}

// where builds the dynamic WHERE clause (without the leading "WHERE") and the
// bound argument list from the non-empty filter fields. Search and Export share
// it so the two reads cannot drift, the way Recent shares Search's builder. Every
// value is bound as a parameter, so no caller input reaches the SQL text. The
// returned clause is empty when the filter is the zero value.
func (f QueryFilter) where() (clause string, args []any) {
	var conds []string
	if f.Domain != "" {
		// Domains are stored lowercase (the DNS handler lowercases the name, and
		// SQLite's LIKE ignores ASCII case anyway), so lowercasing the term
		// makes the match case-insensitive. Escape the LIKE metacharacters so a typed % or _ is a
		// literal, not a wildcard.
		conds = append(conds, "domain LIKE ? ESCAPE '\\'")
		args = append(args, "%"+escapeLike(strings.ToLower(f.Domain))+"%")
	}
	if f.Client != "" {
		conds = append(conds, "client_ip = ?")
		args = append(args, f.Client)
	}
	if f.Blocked != nil {
		conds = append(conds, "blocked = ?")
		args = append(args, b2i(*f.Blocked))
	}
	// The failure rule (synthesized + rcode) matches Record.Unresolved /
	// Record.UpstreamError and the History CASE sums; keep the three in step.
	switch f.Outcome {
	case "unresolved":
		conds = append(conds, "synthesized = 1 AND rcode = ?")
		args = append(args, rcodeServerFailure)
	case "upstream-error":
		conds = append(conds, "synthesized = 0 AND rcode IN (?, ?)")
		args = append(args, rcodeServerFailure, rcodeRefused)
	}
	if len(conds) > 0 {
		clause = " WHERE " + strings.Join(conds, " AND ")
	}
	return clause, args
}

// selectColumns is the column list every recent-query read returns, shared by
// Search and Export so the row shape and scanRows stay in one place.
const selectColumns = "SELECT ts, client_ip, domain, blocked, rcode, synthesized, block_source FROM queries"

// Search returns the last n queries that match f, ordered newest-first. ctx is
// honored as a query deadline; HTTP handlers pass r.Context() so an aborted
// client connection unblocks the database query.
//
// The conditions are built dynamically and every value is bound as a parameter,
// so no caller input reaches the SQL text. The domain filter is a substring
// LIKE, which cannot use idx_queries_domain; at home scale the retention-bounded
// table and the LIMIT keep the scan cheap (see the no-index note in CL 74).
func (d *DBLogger) Search(ctx context.Context, f QueryFilter, n int) ([]QueryRow, error) {
	clause, args := f.where()
	args = append(args, n)
	rows, err := d.db.QueryContext(ctx, selectColumns+clause+" ORDER BY id DESC LIMIT ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// Export streams every row that matches f, newest-first, to yield one row at a
// time instead of materialising a slice, so a large export holds flat memory
// regardless of table size. It is the bulk companion to Search and reuses the
// same where() builder, so a filtered export is the filtered query without the
// LIMIT cap. When n > 0 it bounds the stream to the newest n rows; n <= 0 streams
// the whole filtered log (bounded in practice by query_log.retention_days).
//
// ctx is honored as a query deadline. yield is called once per row in order; if
// it returns an error, Export stops and returns that error (the HTTP handler uses
// this to abort on a write failure). Because it holds the single write connection
// (b/038) for the whole scan, a very large export can briefly block the async
// writer and prune; at home scale over the retention window this is immaterial,
// and a sustained drop shows in shole_query_log_dropped_total.
func (d *DBLogger) Export(ctx context.Context, f QueryFilter, n int, yield func(QueryRow) error) error {
	clause, args := f.where()
	q := selectColumns + clause + " ORDER BY id DESC" //nolint:gosec // G202: where() joins constant conditions; every value is a bound parameter
	if n > 0 {
		q += " LIMIT ?"
		args = append(args, n)
	}
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r QueryRow
		var blocked, synthesized int
		var source BlockSource
		if err := rows.Scan(&r.TS, &r.ClientIP, &r.Domain, &blocked, &r.Rcode, &synthesized, &source); err != nil {
			return err
		}
		r.Blocked = blocked == 1
		r.Synthesized = synthesized == 1
		if r.Blocked {
			r.BlockedBy = source.String()
		}
		if err := yield(r); err != nil {
			return err
		}
	}
	return rows.Err()
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
	// "Since start" and "Stored" tabs order ties identically (b/056).
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
// the remainder: Total - Blocked - Cached. Unresolved and UpstreamError are the
// two failure kinds; both are subsets of the forwarded remainder (a blocked,
// cached, or local reply never fails), so they overlap neither Blocked nor
// Cached.
type Bucket struct {
	Start         int64 `json:"start"` // bucket start, unix seconds (UTC)
	Total         int64 `json:"total"`
	Blocked       int64 `json:"blocked"`
	Cached        int64 `json:"cached"`
	Unresolved    int64 `json:"unresolved"`     // s-hole synthesized a SERVFAIL
	UpstreamError int64 `json:"upstream_error"` // relayed SERVFAIL/REFUSED from an upstream
}

// History returns a dense per-bucket count series covering roughly the last
// window, each bucket wide, oldest first. Buckets with no rows are present with
// zero counts so the graph draws a continuous line. ctx is honored as a query
// deadline.
//
// ts is RFC3339 text in UTC ("...Z", see migrate), so the WHERE cutoff, a UTC
// RFC3339 string, compares correctly as text and reuses idx_queries_ts like
// the prune path. The bucket key is computed from the epoch
// (strftime('%s', ts)).
func (d *DBLogger) History(ctx context.Context, window, bucket time.Duration) ([]Bucket, error) {
	bucketSecs := int64(bucket / time.Second)
	if bucketSecs <= 0 {
		bucketSecs = 1
	}
	n := int(window / bucket)
	if n <= 0 {
		n = 1
	}

	cutoff := time.Now().UTC().Add(-window).Format(time.RFC3339)
	// The two failure CASE sums encode the same rule as Record.Unresolved /
	// Record.UpstreamError and the Search filter (rcode 2 = SERVFAIL, 5 =
	// REFUSED); keep the three in step. The literals are constants, not caller
	// input, so they are inlined rather than bound.
	rows, err := d.db.QueryContext(ctx, `
		SELECT (CAST(strftime('%s', ts) AS INTEGER) / ?1) * ?1 AS bucket_start,
		       COUNT(*)       AS total,
		       SUM(blocked)   AS blocked,
		       SUM(cache_hit) AS cached,
		       SUM(CASE WHEN synthesized=1 AND rcode=2 THEN 1 ELSE 0 END) AS unresolved,
		       SUM(CASE WHEN synthesized=0 AND rcode IN (2,5) THEN 1 ELSE 0 END) AS upstream_error
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
		if err := rows.Scan(&b.Start, &b.Total, &b.Blocked, &b.Cached, &b.Unresolved, &b.UpstreamError); err != nil {
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

// b2i maps a bool to the 0/1 the blocked, cache_hit, and synthesized columns store.
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
		var blocked, synthesized int
		var source BlockSource
		if err := rows.Scan(&r.TS, &r.ClientIP, &r.Domain, &blocked, &r.Rcode, &synthesized, &source); err != nil {
			return nil, err
		}
		r.Blocked = blocked == 1
		r.Synthesized = synthesized == 1
		if r.Blocked {
			r.BlockedBy = source.String()
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
