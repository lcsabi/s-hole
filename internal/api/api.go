// Package api implements the admin REST API and serves the embedded web UI.
//
// The HTTP server runs on a separate port from the DNS server (default
// 127.0.0.1:8080, localhost only; set api_listen to "0.0.0.0:8080" to
// expose to the LAN) and exposes JSON endpoints backed by the stats,
// querylog, and blocklist subsystems. The server is unauthenticated and
// intended for LAN-only deployment; conservative HTTP server timeouts
// and a per-request body size cap defend against slowloris and
// memory-exhaustion attacks but are not a substitute for proper access
// control on a multi-user network.
//
// Routes:
//
//	GET    /api/stats            JSON Snapshot
//	GET    /api/check            block decision for ?domain=NAME (diagnostic; no stats/log side effects)
//	GET    /api/queries          recent rows from SQLite (?limit=N, default 50, max 1000; filter ?domain= substring, ?client= exact, ?blocked=true/false, ?outcome=unresolved/upstream-error)
//	GET    /api/queries/export   stream the filtered query log (?format=csv|json, default csv; same filters as /api/queries; optional ?limit=N, else all)
//	GET    /api/top-blocked      all-time most-blocked domains from SQLite (?limit=N, default 50, max 1000)
//	GET    /api/history          per-bucket query volume from SQLite (?window=24h&bucket=1h; bucket count capped at 1000)
//	GET    /api/whitelist        runtime whitelist (sorted)
//	POST   /api/whitelist        add a domain (ValidDomain-gated, 64 KiB cap)
//	DELETE /api/whitelist        remove a domain
//	POST   /api/reload           reload the DoT certificate (if on) and refresh blocklists (single-flight)
//	GET    /healthz              liveness probe (always 200 when running)
//	GET    /readyz               readiness probe (200 once blocklist > 0)
//	GET    /metrics              Prometheus text exposition (queries, blocked, local_ptr, cache, failures, blocklist, DoT certificate, runtime gauges)
//	GET    /debug/pprof/*        net/http/pprof handlers (/symbol also POST); opt-in via EnablePprof
//	GET    /                     embedded SPA from internal/api/static/
package api

import (
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"net"
	"net/http"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
)

var logger = slog.With("pkg", "api")

//go:embed static
var staticFiles embed.FS

// CacheStatser is the subset of *cache.Cache that /metrics needs. Modelled
// as an interface so the field can be nil (caching disabled) and so the
// api package can be tested without instantiating a real cache.
type CacheStatser interface {
	Stats() (hits, misses uint64, size int)
	Dropped() uint64
}

// Server exposes the admin REST API and serves the web UI.
type Server struct {
	counter  *stats.Counter
	db       *querylog.DBLogger // nil when query_db is not configured
	store    *blocklist.Store
	dnsCache CacheStatser // nil when caching is disabled
	// reloadFn is the single-flight reload (the DoT certificate when DoT is
	// on, then the blocklists); the caller owns the mutex so the periodic
	// timer, the API, and SIGHUP are serialised against the same gate.
	// Returns false if a reload is already running.
	reloadFn func() bool
	// httpServer is stored by Serve, which runs in a background goroutine in
	// main, and read by Shutdown, which runs on the signal goroutine. It is an
	// atomic.Pointer so those two goroutines never race on the field; a plain
	// pointer was an unsynchronised write/read (b/053). Load returns nil until
	// Serve has stored the server, which Shutdown treats as "nothing to drain".
	httpServer atomic.Pointer[http.Server]
	// shutdownRequested closes the stop-before-store window (b/054). Shutdown
	// sets it before it loads httpServer; Serve checks it right after it stores
	// the server. Because the two set/load pairs cross, a Shutdown that runs
	// before Serve has stored the server cannot be lost: either Shutdown loads
	// the stored pointer and drains it, or Serve sees the flag and stops itself
	// before it blocks in Accept. Go's atomics are sequentially consistent, so
	// no both-miss interleaving exists. Without the flag such a stop read a nil
	// pointer, no-oped, and left Serve blocked with no one to drain it.
	shutdownRequested atomic.Bool
	enablePprof       bool
	// queryPrivacy echoes the active query_privacy mode ("raw", "drop", or
	// "subnet") on /api/stats. It is display metadata only; the client IP is
	// masked in the DNS handler, so the API never sees an unmasked address to
	// leak here.
	queryPrivacy string
	// labeler resolves a stored client value to a config client_names label at
	// display time. It keys off the already-masked value the store holds, so it
	// never exceeds the active queryPrivacy granularity. nil = attribution off.
	labeler *clientLabeler
	// upstreamTransportFailures returns the cumulative per-upstream
	// transport-failure counts for the shole_upstream_transport_failures_total{upstream}
	// metric. Wired from main to dnsserver.UpstreamTransportFailures; nil leaves
	// the metric off (the api package does not import dnsserver, so main bridges
	// the two).
	upstreamTransportFailures func() map[string]uint64
	// dotStatus reports the DNS-over-TLS certificate state for /api/stats and
	// /metrics. main wires it only when dot_listen is set; nil means DoT is off,
	// so /api/stats reports {"enabled": false} and the DoT metrics are omitted.
	dotStatus func() DoTStatus
	// readRuntimeMetrics reads the Go runtime gauges (shole_goroutines and the
	// heap gauges) for /metrics. It defaults to runtime/metrics.Read in New;
	// tests reassign it to a deterministic, call-counting fake so they can assert
	// the exact gauge values and that handleMetrics reads once per scrape (never
	// per gauge). Only tests write it, and the api package runs its tests
	// sequentially, so the swap is race-free.
	readRuntimeMetrics func([]metrics.Sample)
	// exportSem bounds concurrent /api/queries/export streams. Each export holds
	// the single query-log connection (b/038) for its whole scan, so unbounded
	// parallel exports on the unauthenticated LAN port could starve the async
	// writer. A buffered channel used as a semaphore caps in-flight exports;
	// excess requests get 429 rather than queueing. It does not throttle the
	// cheap JSON endpoints the dashboard polls. General API rate limiting is a
	// separate, broader decision (ROADMAP #34).
	exportSem chan struct{}
}

// maxConcurrentExports caps simultaneous /api/queries/export streams. Two lets a
// second operator export while one runs, without letting many parallel scans pin
// the single query-log connection.
const maxConcurrentExports = 2

// New constructs a Server. db and dnsCache may be nil to disable the
// corresponding metric/endpoint surfaces. reloadFn must be the
// single-flight reload closure owned by cmd/s-hole/main.go; see the
// reloadFn field for the contract.
func New(counter *stats.Counter, db *querylog.DBLogger, store *blocklist.Store, dnsCache CacheStatser, reloadFn func() bool) *Server {
	return &Server{
		counter:            counter,
		db:                 db,
		store:              store,
		dnsCache:           dnsCache,
		reloadFn:           reloadFn,
		readRuntimeMetrics: metrics.Read,
		exportSem:          make(chan struct{}, maxConcurrentExports),
	}
}

// EnablePprof toggles whether the server registers the net/http/pprof
// handlers under /debug/pprof/. Off by default. Call before Serve or
// ListenAndServe; toggling after the server is built has no effect.
func (s *Server) EnablePprof(on bool) {
	s.enablePprof = on
}

// SetQueryPrivacy records the active query_privacy mode for the /api/stats
// echo. It is metadata only and does not affect masking, which happens in the
// DNS handler. An empty mode reads as "raw" on the stats payload.
func (s *Server) SetQueryPrivacy(mode string) {
	s.queryPrivacy = mode
}

// SetClientNames installs the config client_names map as a display-time label
// resolver for the Top Clients panel and the recent-queries list. The labels
// are resolved against the already-masked client value, so they never expose
// more than the active query_privacy mode. Call before Serve; an empty map
// leaves attribution off. Like SetQueryPrivacy, this does not affect masking.
func (s *Server) SetClientNames(m map[string]string) {
	s.labeler = newClientLabeler(m)
}

// SetUpstreamTransportFailures wires the per-upstream transport-failure accessor
// (dnsserver.UpstreamTransportFailures) so /metrics can emit
// shole_upstream_transport_failures_total{upstream=...}. Call before Serve;
// leaving it unset omits that metric. main bridges the two packages so api need
// not import dnsserver.
func (s *Server) SetUpstreamTransportFailures(fn func() map[string]uint64) {
	s.upstreamTransportFailures = fn
}

// DoTStatus is the DNS-over-TLS state the admin API reports. main fills it
// from dnsserver.CertReloader.Status, so the api package does not import
// dnsserver. State is one of "ok", "expiring", "expired", or "reload_failed",
// computed where the expiry window is defined.
type DoTStatus struct {
	Listen          string
	Names           []string
	NotAfter        time.Time
	State           string
	LastReload      time.Time
	LastReloadError string
	ReloadFailures  uint64
}

// SetDoTStatus wires the DNS-over-TLS status accessor, so /api/stats reports
// the certificate state and /metrics emits the DoT certificate metrics. Call
// before Serve, and only when DoT is on.
func (s *Server) SetDoTStatus(fn func() DoTStatus) {
	s.dotStatus = fn
}

// Timeouts protect the unauthenticated admin server from slowloris-style
// attacks on the LAN. The UI itself only issues short JSON requests.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
	maxRequestBytes   = 64 * 1024
)

// ListenAndServe binds addr and serves the admin UI and REST API. It is the
// one-call form (Listen then Serve). A caller that wants to detect a bind
// failure synchronously, before backgrounding the serve loop, should bind with
// net.Listen itself and call Serve; main does this so a bad api_listen is
// surfaced at startup instead of in a goroutine (b/052).
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve serves the admin UI and REST API on an already-bound listener.
// http.ErrServerClosed (raised by a clean Shutdown) is suppressed so callers
// can treat any returned error as an actual failure.
func (s *Server) Serve(ln net.Listener) error {
	addr := ln.Addr().String()
	logger.Info("admin UI listening", "addr", addr, "url", "http://"+addr)
	hs := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	s.httpServer.Store(hs)
	// Double-check against a Shutdown that ran before the Store above (b/054).
	// Shutdown sets shutdownRequested before it loads httpServer, so if it saw a
	// nil pointer and no-oped, the flag is set here. Nothing has served on ln
	// yet, so close the listener directly and skip the serve loop instead of
	// blocking in Accept with no one to drain.
	if s.shutdownRequested.Load() {
		return ln.Close()
	}
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully stops the HTTP server, waiting up to the deadline in ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	// Record the stop before loading the server so a Serve that has not stored
	// it yet sees the request and stops itself (b/054); see shutdownRequested.
	s.shutdownRequested.Store(true)
	hs := s.httpServer.Load()
	if hs == nil {
		return nil
	}
	return hs.Shutdown(ctx)
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/stats", s.handleStats)
	mux.HandleFunc("GET /api/check", s.handleCheck)
	mux.HandleFunc("GET /api/queries", s.handleQueries)
	mux.HandleFunc("GET /api/queries/export", s.handleQueriesExport)
	mux.HandleFunc("GET /api/top-blocked", s.handleTopBlocked)
	mux.HandleFunc("GET /api/history", s.handleHistory)
	mux.HandleFunc("GET /api/whitelist", s.handleWhitelistList)
	mux.HandleFunc("POST /api/whitelist", s.handleWhitelistAdd)
	mux.HandleFunc("DELETE /api/whitelist", s.handleWhitelistRemove)
	mux.HandleFunc("POST /api/reload", s.handleReload)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	if s.enablePprof {
		registerPprof(mux)
		logger.Info("pprof endpoints registered", "prefix", "/debug/pprof/",
			"mutex_profiling", true, "block_profiling", true)
	}

	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		// Build-time impossible: the embed.FS contains a "static" subtree.
		// Treat as fatal; this should never fire in a released binary.
		logger.Error("embedded static FS missing 'static' subtree", "err", err)
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	return mux
}

// statsResponse is the /api/stats body: the stats snapshot plus the
// per-source blocklist health. Summary is embedded anonymously so its JSON
// fields stay at the top level (existing clients that decode into
// stats.Summary are unaffected); Sources adds the per-source array. The type
// lives here, not in the stats package, so stats does not take a dependency on
// blocklist. QueryPrivacy echoes the active query_privacy mode so the UI can
// describe the client column honestly (see the Top Clients panel).
//
// TopClients is redeclared here so it can carry the client_names label; the
// outer field shadows the one embedded from Summary for JSON, so the payload
// key stays "top_clients" and the stats package needs no change. The label is
// resolved from the masked Name, so it never exposes more than QueryPrivacy.
type statsResponse struct {
	stats.Summary
	TopClients   []clientEntry            `json:"top_clients"`
	Sources      []blocklist.SourceStatus `json:"sources"`
	QueryPrivacy string                   `json:"query_privacy"`
	DoT          dotResponse              `json:"dot"`
}

// dotResponse is the "dot" object in /api/stats. With DoT off it is just
// {"enabled": false}. ExpiresInDays is computed on the server, so the
// dashboard does not depend on the browser's clock; it is negative once the
// certificate has expired.
type dotResponse struct {
	Enabled         bool     `json:"enabled"`
	Listen          string   `json:"listen,omitempty"`
	Names           []string `json:"names,omitempty"`
	NotAfter        string   `json:"not_after,omitempty"`
	ExpiresInDays   *int     `json:"expires_in_days,omitempty"`
	State           string   `json:"state,omitempty"`
	LastReload      string   `json:"last_reload,omitempty"`
	LastReloadError string   `json:"last_reload_error,omitempty"`
}

// dotSummary builds the /api/stats "dot" object at now.
func (s *Server) dotSummary(now time.Time) dotResponse {
	if s.dotStatus == nil {
		return dotResponse{}
	}
	st := s.dotStatus()
	days := int(math.Floor(st.NotAfter.Sub(now).Hours() / 24))
	resp := dotResponse{
		Enabled:         true,
		Listen:          st.Listen,
		Names:           st.Names,
		NotAfter:        st.NotAfter.UTC().Format(time.RFC3339),
		ExpiresInDays:   &days,
		State:           st.State,
		LastReloadError: st.LastReloadError,
	}
	if !st.LastReload.IsZero() {
		resp.LastReload = st.LastReload.UTC().Format(time.RFC3339)
	}
	return resp
}

// clientEntry is a Top Clients row: the masked client value (Name), its query
// count, and an optional config-resolved display label.
type clientEntry struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
	Label string `json:"label,omitempty"`
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	snap := s.counter.Snapshot(10)
	snap.BlocklistSize = s.store.Len()
	privacy := s.queryPrivacy
	if privacy == "" {
		privacy = "raw"
	}
	clients := make([]clientEntry, len(snap.TopClients))
	for i, e := range snap.TopClients {
		clients[i] = clientEntry{Name: e.Name, Count: e.Count, Label: s.labeler.label(e.Name)}
	}
	writeJSON(w, statsResponse{
		Summary:      snap,
		TopClients:   clients,
		Sources:      s.store.Sources(),
		QueryPrivacy: privacy,
		DoT:          s.dotSummary(time.Now()),
	})
}

// handleCheck answers "why is this domain blocked?" by running the name through
// the same block decision as a real query and returning the outcome plus the
// full suffix walk (which parent matched, which whitelist entry overrode). It
// is a diagnostic: it bumps no stats counter and writes no query-log row,
// because it never touches the DNS handler path. It reveals nothing the UI
// could not already infer from the block set and whitelist, so it does not
// widen the read surface.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if !blocklist.ValidDomain(domain) {
		http.Error(w, "invalid or missing domain", http.StatusBadRequest)
		return
	}
	writeJSON(w, s.store.Explain(domain))
}

// defaultQueriesLimit and maxQueriesLimit bound the ?limit= parameter on
// /api/queries. The cap keeps a stray `?limit=10000000` from marshalling
// the entire history table into one JSON response on the unauthenticated
// admin port; the same defense-in-depth reasoning as maxRequestBytes.
const (
	defaultQueriesLimit = 50
	maxQueriesLimit     = 1000
)

// parseLimit extracts the ?limit= query parameter, substituting the
// default for absent, malformed, or non-positive values and clamping to
// maxQueriesLimit.
func parseLimit(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return defaultQueriesLimit
	}
	return min(n, maxQueriesLimit)
}

// queryRow is a recent-queries row: the stored columns plus an optional
// config-resolved client label and a derived outcome label. The label is
// resolved from the masked ClientIP, so the recent-queries list never exposes
// more than QueryPrivacy. Outcome ("blocked"/"allowed"/"unresolved"/
// "upstream_error") is computed once here from the row so the dashboard and any
// export read a name instead of decoding rcode and the synthesized flag.
type queryRow struct {
	querylog.QueryRow
	Label   string `json:"label,omitempty"`
	Outcome string `json:"outcome"`
}

// parseQueryFilter reads the optional recent-query filters from the request.
// domain is a substring, client an exact match on the stored (masked) value,
// blocked accepts "true" or "false", and outcome accepts "unresolved" or
// "upstream-error" to narrow to that failure kind (any other value leaves the
// status/outcome unfiltered). The upstream-error kind also accepts the
// underscore spelling "upstream_error", which is the value each row reports in
// its "outcome" field, so a caller can filter by the value it read back. Every
// field is optional; an empty filter matches every row. The dashboard status
// control sends either blocked or outcome, not both, but the two are
// independent filters here.
func parseQueryFilter(r *http.Request) querylog.QueryFilter {
	q := r.URL.Query()
	f := querylog.QueryFilter{
		Domain: strings.TrimSpace(q.Get("domain")),
		Client: strings.TrimSpace(q.Get("client")),
	}
	switch q.Get("blocked") {
	case "true":
		b := true
		f.Blocked = &b
	case "false":
		b := false
		f.Blocked = &b
	}
	switch q.Get("outcome") {
	case "unresolved":
		f.Outcome = "unresolved"
	case "upstream-error", "upstream_error":
		// The query token uses a hyphen; the row's "outcome" field uses an
		// underscore. Accept both and normalize to the token Search expects,
		// so a value read from a row filters instead of silently matching all.
		f.Outcome = "upstream-error"
	}
	return f
}

func (s *Server) handleQueries(w http.ResponseWriter, r *http.Request) {
	limit := parseLimit(r)
	filter := parseQueryFilter(r)

	type response struct {
		Queries []queryRow `json:"queries"`
	}

	if s.db == nil {
		writeJSON(w, response{Queries: []queryRow{}})
		return
	}

	rows, err := s.db.Search(r.Context(), filter, limit)
	if err != nil {
		logger.Warn("recent query failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]queryRow, len(rows))
	for i, row := range rows {
		out[i] = queryRow{QueryRow: row, Label: s.labeler.label(row.ClientIP), Outcome: row.Outcome()}
	}
	writeJSON(w, response{Queries: out})
}

// exportFilter echoes the active filter into the JSON export envelope so a saved
// file is self-describing. It mirrors querylog.QueryFilter with JSON tags; a
// nil Blocked and empty strings are omitted.
type exportFilter struct {
	Domain  string `json:"domain,omitempty"`
	Client  string `json:"client,omitempty"`
	Blocked *bool  `json:"blocked,omitempty"`
	Outcome string `json:"outcome,omitempty"`
}

// handleQueriesExport streams the filtered query log for download in CSV
// (default) or JSON. It reuses the /api/queries filters (parseQueryFilter), so a
// filtered export is the filtered query in bulk, and streams row by row so a
// large log holds flat memory. The rows are the same masked columns /api/queries
// serves (CL 72 masks the client at write time), so the export cannot leak more
// than the recent-query view. Unlike /api/queries it is uncapped by default
// (?limit= is optional); the table is bounded by query_db_retention_days.
//
// The active query_privacy mode and log_queries mode ride on response headers
// (and, for JSON, envelope fields), so a masked or empty value reads as
// intentional. When query logging is off (s.db == nil) it returns a valid empty
// export (a header-only CSV or an empty queries array), matching the
// degrade-not-fail contract of /api/queries.
func (s *Server) handleQueriesExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		http.Error(w, `invalid format: expected "csv" or "json"`, http.StatusBadRequest)
		return
	}

	// Bound concurrent exports so parallel scans cannot pin the single query-log
	// connection (b/038). A non-blocking acquire returns 429 instead of queueing.
	select {
	case s.exportSem <- struct{}{}:
		defer func() { <-s.exportSem }()
	default:
		w.Header().Set("Retry-After", "5")
		http.Error(w, "too many concurrent exports in progress", http.StatusTooManyRequests)
		return
	}

	filter := parseQueryFilter(r)
	limit := 0 // 0 = stream all matching rows; ?limit= bounds to the newest N
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = n
	}

	privacy := s.queryPrivacy
	if privacy == "" {
		privacy = "raw"
	}
	logging := "off"
	if s.db != nil {
		logging = s.db.LogQueries()
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="s-hole-queries-%s-%s.%s"`, privacy, ts, format))
	w.Header().Set("X-Shole-Query-Privacy", privacy)
	w.Header().Set("X-Shole-Query-Logging", logging)

	if format == "json" {
		s.exportJSON(w, r, filter, limit, privacy, logging)
		return
	}
	s.exportCSV(w, r, filter, limit)
}

// exportCSVColumns is the fixed CSV header, emitted every export so a downstream
// parser sees one schema regardless of whether client_names is configured.
var exportCSVColumns = []string{"ts", "client_ip", "label", "domain", "blocked", "outcome", "rcode", "synthesized"}

// exportCSV writes the filtered rows as CSV: the fixed header, then one row per
// query. Each field is passed through csvSanitize so a client-influenced value
// (the queried domain) cannot inject a spreadsheet formula. Because headers are
// already sent, a mid-stream error is logged and leaves a truncated file, which
// is the failure signal.
func (s *Server) exportCSV(w http.ResponseWriter, r *http.Request, f querylog.QueryFilter, limit int) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	rc := http.NewResponseController(w)
	cw := csv.NewWriter(w)
	_ = cw.Write(exportCSVColumns)

	if s.db != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
		err := s.db.Export(r.Context(), f, limit, func(row querylog.QueryRow) error {
			rec := []string{
				row.TS,
				csvSanitize(row.ClientIP),
				csvSanitize(s.labeler.label(row.ClientIP)),
				csvSanitize(row.Domain),
				strconv.FormatBool(row.Blocked),
				row.Outcome(),
				strconv.Itoa(row.Rcode),
				strconv.FormatBool(row.Synthesized),
			}
			if err := cw.Write(rec); err != nil {
				return err
			}
			// Roll the write deadline forward on each row so a long but healthy
			// export is not cut off at writeTimeout, while a stalled client still
			// trips the deadline on its next blocking write (slowloris guard).
			_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
			return nil
		})
		if err != nil {
			logger.Warn("query export failed", "format", "csv", "err", err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		logger.Warn("query export flush failed", "format", "csv", "err", err)
	}
}

// exportJSON writes a streamed envelope: the metadata (query_privacy, exported_at,
// logging mode, and the echoed filter) first, then the queries array streamed row
// by row. On a mid-stream error the array is left unterminated (no closing "]}"),
// so a consumer sees an invalid document rather than a silently short one.
func (s *Server) exportJSON(w http.ResponseWriter, r *http.Request, f querylog.QueryFilter, limit int, privacy, logging string) {
	w.Header().Set("Content-Type", "application/json")
	rc := http.NewResponseController(w)

	meta := struct {
		QueryPrivacy string       `json:"query_privacy"`
		ExportedAt   string       `json:"exported_at"`
		Logging      string       `json:"logging"`
		Filter       exportFilter `json:"filter"`
	}{
		QueryPrivacy: privacy,
		ExportedAt:   time.Now().UTC().Format(time.RFC3339),
		Logging:      logging,
		Filter:       exportFilter{Domain: f.Domain, Client: f.Client, Blocked: f.Blocked, Outcome: f.Outcome},
	}
	head, err := json.Marshal(meta)
	if err != nil {
		// meta is plain strings and a bool pointer; marshalling cannot realistically
		// fail. Nothing is written yet, so a 500 is still valid here.
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Splice the streamed array into the envelope: drop the meta object's closing
	// '}', open the queries array, and re-close after the last row.
	if _, err := w.Write(append(head[:len(head)-1], []byte(`,"queries":[`)...)); err != nil {
		logger.Warn("query export failed", "format", "json", "err", err)
		return
	}

	first := true
	if s.db != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
		err := s.db.Export(r.Context(), f, limit, func(row querylog.QueryRow) error {
			b, err := json.Marshal(queryRow{QueryRow: row, Label: s.labeler.label(row.ClientIP), Outcome: row.Outcome()})
			if err != nil {
				return err
			}
			if !first {
				if _, err := w.Write([]byte{','}); err != nil {
					return err
				}
			}
			first = false
			if _, err := w.Write(b); err != nil {
				return err
			}
			_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
			return nil
		})
		if err != nil {
			logger.Warn("query export failed", "format", "json", "err", err)
			return // leave the JSON unterminated as the failure signal
		}
	}
	if _, err := io.WriteString(w, "]}"); err != nil {
		logger.Warn("query export failed", "format", "json", "err", err)
	}
}

// csvSanitize defends a spreadsheet that opens the export from CSV formula
// injection. A field a client can influence (notably the queried domain) may
// begin with a formula trigger; prefix such a field with a single quote so
// Excel/Sheets treat it as text. Covers the OWASP set (= + - @) plus tab and CR,
// which can also start a formula.
func csvSanitize(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// handleTopBlocked serves the all-time most-blocked domains from the SQLite
// query log, the persistent, unpruned companion to the in-memory
// top_domains list in /api/stats (which resets on restart and caps at
// topNMaxEntries). When query logging is disabled (s.db == nil) it returns an
// empty list rather than an error, so the dashboard's "All time" toggle
// degrades to an empty panel instead of a failure, exactly like /api/queries.
func (s *Server) handleTopBlocked(w http.ResponseWriter, r *http.Request) {
	limit := parseLimit(r)

	type response struct {
		Domains []querylog.Entry `json:"domains"`
	}

	if s.db == nil {
		writeJSON(w, response{Domains: []querylog.Entry{}})
		return
	}

	rows, err := s.db.TopBlocked(r.Context(), limit)
	if err != nil {
		logger.Warn("top-blocked query failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []querylog.Entry{}
	}
	writeJSON(w, response{Domains: rows})
}

const (
	defaultHistoryWindow = 24 * time.Hour
	defaultHistoryBucket = time.Hour
	minHistoryBucket     = time.Minute
	maxHistoryWindow     = 30 * 24 * time.Hour
	// maxHistoryBuckets caps the series length (and the SQL group count) so a
	// crafted request such as window=7d&bucket=1s cannot ask for 600k buckets.
	// Mirrors maxQueriesLimit.
	maxHistoryBuckets = 1000
)

// parseHistoryParams extracts and clamps the ?window= and ?bucket= duration
// parameters for the history series. Absent, malformed, or non-positive values
// fall back to the defaults. The window is clamped to [minHistoryBucket,
// maxHistoryWindow] and the bucket to [minHistoryBucket, window]; the bucket is
// then widened if needed so the bucket count never exceeds maxHistoryBuckets.
func parseHistoryParams(r *http.Request) (window, bucket time.Duration) {
	window = parseDurationParam(r, "window", defaultHistoryWindow)
	bucket = parseDurationParam(r, "bucket", defaultHistoryBucket)

	if window > maxHistoryWindow {
		window = maxHistoryWindow
	}
	if window < minHistoryBucket {
		window = minHistoryBucket
	}
	if bucket < minHistoryBucket {
		bucket = minHistoryBucket
	}
	if bucket > window {
		bucket = window
	}
	// Widen the bucket if the count would exceed the cap. Round up to a whole
	// number of seconds so the SQL integer division stays exact.
	if window/bucket > maxHistoryBuckets {
		secs := (int64(window/time.Second) + maxHistoryBuckets - 1) / maxHistoryBuckets
		bucket = time.Duration(secs) * time.Second
	}
	return window, bucket
}

// parseDurationParam reads a duration query parameter, returning def for an
// absent, malformed, or non-positive value.
func parseDurationParam(r *http.Request, name string, def time.Duration) time.Duration {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	d, err := parseFlexDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// parseFlexDuration extends time.ParseDuration with a whole-day "d" suffix.
// time.ParseDuration stops at hours, so window=7d would otherwise fail to parse
// and fall back to the default. Everything else delegates to the standard
// parser (h/m/s and friends).
func parseFlexDuration(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// handleHistory serves a query-volume-over-time series from the SQLite query
// log: per-bucket total, blocked, cached, and the two failure counts (unresolved
// and upstream-error) over the requested window. When
// query logging is disabled (s.db == nil) it returns an empty series rather than
// an error, so the dashboard graph degrades to an empty panel instead of a
// failure, exactly like /api/queries and /api/top-blocked.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	window, bucket := parseHistoryParams(r)

	type response struct {
		Window int64 `json:"window"` // effective window, seconds
		Bucket int64 `json:"bucket"` // effective bucket, seconds
		// Logging is the effective query-log mode the series reflects: "all",
		// "blocked", "none", or "off" when query_db is unset. The dashboard reads
		// it to draw the graph honestly (a single blocked line under "blocked", an
		// empty state under "none"/"off") instead of a misleading total.
		Logging string            `json:"logging"`
		Series  []querylog.Bucket `json:"series"`
	}
	resp := response{
		Window:  int64(window / time.Second),
		Bucket:  int64(bucket / time.Second),
		Logging: "off",
		Series:  []querylog.Bucket{},
	}

	if s.db == nil {
		writeJSON(w, resp)
		return
	}
	resp.Logging = s.db.LogQueries()

	series, err := s.db.History(r.Context(), window, bucket)
	if err != nil {
		logger.Warn("history query failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if series != nil {
		resp.Series = series
	}
	writeJSON(w, resp)
}

func (s *Server) handleWhitelistList(w http.ResponseWriter, _ *http.Request) {
	type response struct {
		Domains []string `json:"domains"`
	}
	domains := s.store.GetWhitelist()
	if domains == nil {
		domains = []string{}
	}
	// R37: return a stable order so the UI doesn't shuffle on every refresh.
	sort.Strings(domains)
	writeJSON(w, response{Domains: domains})
}

func (s *Server) handleWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	// Cap the request body so an attacker on the LAN cannot exhaust memory
	// by streaming an unbounded JSON payload to the unauthenticated server.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var body struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Domain) == "" {
		http.Error(w, `invalid body: expected {"domain":"..."}`, http.StatusBadRequest)
		return
	}
	domain := strings.TrimSpace(body.Domain)
	if !blocklist.ValidDomain(domain) {
		http.Error(w, "invalid domain (max 253 chars, must contain a dot, alphanumerics/hyphen/underscore only)", http.StatusBadRequest)
		return
	}
	s.store.AddToWhitelist(domain)
	logger.Info("whitelist entry added", "domain", domain, "client", clientIP(r))
	writeJSON(w, map[string]string{"domain": domain, "status": "whitelisted"})
}

func (s *Server) handleWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		http.Error(w, "missing ?domain= query parameter", http.StatusBadRequest)
		return
	}
	s.store.RemoveFromWhitelist(domain)
	logger.Info("whitelist entry removed", "domain", domain, "client", clientIP(r))
	writeJSON(w, map[string]string{"domain": domain, "status": "removed"})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	logger.Info("reload requested via API", "client", clientIP(r))
	if !s.reloadFn() {
		writeJSON(w, map[string]string{"status": "reload already in progress"})
		return
	}
	writeJSON(w, map[string]string{"status": "reload triggered"})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Body may be half-written at this point; we cannot fix that, but
		// at least surface the failure to the operator instead of letting
		// the client see a silent truncation.
		logger.Warn("json encode failed", "err", err)
	}
}

// clientIP returns the requester address for an audit-log line. It drops
// the ephemeral source port from RemoteAddr and falls back to the raw
// value if the address carries no port.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
