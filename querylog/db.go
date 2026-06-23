package querylog

import (
	"database/sql"
	"fmt"
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

// DBLogger writes queries asynchronously to a SQLite database.
// Entries are batched and flushed on a configurable interval or when 100
// accumulate, whichever comes first.
type DBLogger struct {
	db            *sql.DB
	ch            chan entry
	done          chan struct{}
	logQueries    string
	flushInterval time.Duration
}

// pragmas applied on every open. WAL + synchronous=NORMAL dramatically reduces
// write amplification on flash/SD storage compared to the default journal mode.
const pragmas = `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=-8000;
PRAGMA temp_store=MEMORY;
`

func NewDBLogger(path, logQueries string, flushInterval time.Duration) (*DBLogger, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := db.Exec(pragmas); err != nil {
		db.Close()
		return nil, fmt.Errorf("pragmas: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}

	l := &DBLogger{
		db:            db,
		ch:            make(chan entry, 1000),
		done:          make(chan struct{}),
		logQueries:    logQueries,
		flushInterval: flushInterval,
	}
	go l.run()
	return l, nil
}

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
	}
}

func (d *DBLogger) Close() error {
	close(d.done)
	return d.db.Close()
}

func (d *DBLogger) run() {
	batch := make([]entry, 0, 100)
	tick := time.NewTicker(d.flushInterval)
	defer tick.Stop()

	for {
		select {
		case e := <-d.ch:
			batch = append(batch, e)
			if len(batch) >= 100 {
				d.flush(batch)
				batch = batch[:0]
			}
		case <-tick.C:
			if len(batch) > 0 {
				d.flush(batch)
				batch = batch[:0]
			}
		case <-d.done:
			// Drain remaining entries before exit.
			for len(d.ch) > 0 {
				batch = append(batch, <-d.ch)
			}
			if len(batch) > 0 {
				d.flush(batch)
			}
			return
		}
	}
}

func (d *DBLogger) flush(batch []entry) {
	tx, err := d.db.Begin()
	if err != nil {
		fmt.Printf("[querylog] db begin: %v\n", err)
		return
	}
	stmt, err := tx.Prepare("INSERT INTO queries(ts,client_ip,domain,blocked) VALUES(?,?,?,?)")
	if err != nil {
		fmt.Printf("[querylog] db prepare: %v\n", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, e := range batch {
		blocked := 0
		if e.blocked {
			blocked = 1
		}
		stmt.Exec(e.ts.Format(time.RFC3339), e.clientIP, e.domain, blocked)
	}
	if err := tx.Commit(); err != nil {
		fmt.Printf("[querylog] db commit: %v\n", err)
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

// Recent returns the last n queries ordered newest-first.
func (d *DBLogger) Recent(n int) ([]QueryRow, error) {
	rows, err := d.db.Query(
		"SELECT ts, client_ip, domain, blocked FROM queries ORDER BY id DESC LIMIT ?", n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// TopBlocked returns the n most-blocked domains across all recorded queries.
func (d *DBLogger) TopBlocked(n int) ([]Entry, error) {
	rows, err := d.db.Query(`
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
