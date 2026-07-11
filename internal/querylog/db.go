package querylog

import (
	"context"
	"database/sql"
	"fmt"
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
	blocked   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queries_ts      ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_queries_blocked ON queries(blocked);
CREATE INDEX IF NOT EXISTS idx_queries_domain  ON queries(domain);
`

type entry struct {
	ts       time.Time
	clientIP string
	domain   string
	blocked  bool
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
const pragmas = `
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
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := db.Exec(pragmas); err != nil {
		_ = db.Close() // best-effort: the Exec error is the one worth reporting
		return nil, fmt.Errorf("pragmas: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("schema: %w", err)
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
// logQueries filter and silently drops if the internal channel is full —
// logging completeness is subordinate to DNS handler latency. Never
// blocks the caller.
func (d *DBLogger) Log(clientIP, domain string, blocked bool) {
	if d.logQueries == "none" {
		return
	}
	if d.logQueries == "blocked" && !blocked {
		return
	}
	select {
	case d.ch <- entry{ts: time.Now(), clientIP: clientIP, domain: domain, blocked: blocked}:
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
	stmt, err := tx.Prepare("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)")
	if err != nil {
		logger.Error("db prepare failed, dropping batch", "entries", len(batch), "err", err)
		_ = tx.Rollback() // the Prepare error above is the actionable one
		return
	}
	defer stmt.Close()

	for _, e := range batch {
		blocked := 0
		if e.blocked {
			blocked = 1
		}
		if _, err := stmt.Exec(e.ts.Format(time.RFC3339), e.clientIP, e.domain, blocked); err != nil {
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

// Recent returns the last n queries ordered newest-first. ctx is honored
// as a query deadline; HTTP handlers pass r.Context() so an aborted client
// connection unblocks the database query.
func (d *DBLogger) Recent(ctx context.Context, n int) ([]QueryRow, error) {
	rows, err := d.db.QueryContext(ctx,
		"SELECT ts, client_ip, domain, blocked FROM queries ORDER BY id DESC LIMIT ?", n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// TopBlocked returns the n most-blocked domains across all recorded
// queries. ctx is honored as a query deadline.
func (d *DBLogger) TopBlocked(ctx context.Context, n int) ([]Entry, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT domain, COUNT(*) AS cnt
		FROM queries WHERE blocked=1
		GROUP BY domain
		ORDER BY cnt DESC
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
