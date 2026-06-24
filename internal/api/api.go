// Package api implements the admin REST API and serves the embedded web UI.
//
// The HTTP server runs on a separate port from the DNS server (default
// :8080) and exposes JSON endpoints backed by the stats, querylog, and
// blocklist subsystems. It is unauthenticated and intended for LAN-only
// deployment; conservative HTTP server timeouts and a per-request body
// size cap defend against slowloris and memory-exhaustion attacks but
// are not a substitute for proper access control on a multi-user network.
package api

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/laszlo/s-hole/internal/blocklist"
	"github.com/laszlo/s-hole/internal/querylog"
	"github.com/laszlo/s-hole/internal/stats"
)

var logger = slog.With("pkg", "api")

//go:embed static
var staticFiles embed.FS

// CacheStatser is the subset of *cache.Cache that /metrics needs. Modelled
// as an interface so the field can be nil (caching disabled) and so the
// api package can be tested without instantiating a real cache.
type CacheStatser interface {
	Stats() (hits, misses uint64, size int)
}

// Server exposes the admin REST API and serves the web UI.
type Server struct {
	counter  *stats.Counter
	db       *querylog.DBLogger // nil when query_db is not configured
	store    *blocklist.Store
	dnsCache CacheStatser // nil when caching is disabled
	// reloadFn is the single-flight blocklist refresh; the caller owns the
	// mutex so the periodic timer and the API are serialised against the
	// same gate. Returns false if a refresh is already running.
	reloadFn   func() bool
	httpServer *http.Server
}

// New constructs a Server. db and dnsCache may be nil to disable the
// corresponding metric/endpoint surfaces. reloadFn must be the
// single-flight blocklist refresh closure owned by main.go; see the
// reloadFn field for the contract.
func New(counter *stats.Counter, db *querylog.DBLogger, store *blocklist.Store, dnsCache CacheStatser, reloadFn func() bool) *Server {
	return &Server{counter: counter, db: db, store: store, dnsCache: dnsCache, reloadFn: reloadFn}
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

// ListenAndServe binds addr and serves the admin UI and REST API.
// http.ErrServerClosed (raised by a clean Shutdown) is suppressed so callers
// can treat any returned error as an actual failure.
func (s *Server) ListenAndServe(addr string) error {
	logger.Info("admin UI listening", "addr", addr, "url", "http://"+addr)
	hs := &http.Server{
		Addr:              addr,
		Handler:           s.handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	s.httpServer = hs
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully stops the HTTP server, waiting up to the deadline in ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/stats", s.handleStats)
	mux.HandleFunc("GET /api/queries", s.handleQueries)
	mux.HandleFunc("GET /api/whitelist", s.handleWhitelistList)
	mux.HandleFunc("POST /api/whitelist", s.handleWhitelistAdd)
	mux.HandleFunc("DELETE /api/whitelist", s.handleWhitelistRemove)
	mux.HandleFunc("POST /api/reload", s.handleReload)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		// Build-time impossible: the embed.FS contains a "static" subtree.
		// Treat as fatal — this should never fire in a released binary.
		logger.Error("embedded static FS missing 'static' subtree", "err", err)
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	return mux
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.counter.Snapshot(10))
}

func (s *Server) handleQueries(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	type response struct {
		Queries []querylog.QueryRow `json:"queries"`
	}

	if s.db == nil {
		writeJSON(w, response{Queries: []querylog.QueryRow{}})
		return
	}

	rows, err := s.db.Recent(r.Context(), limit)
	if err != nil {
		logger.Warn("recent query failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []querylog.QueryRow{}
	}
	writeJSON(w, response{Queries: rows})
}

func (s *Server) handleWhitelistList(w http.ResponseWriter, _ *http.Request) {
	type response struct {
		Domains []string `json:"domains"`
	}
	domains := s.store.GetWhitelist()
	if domains == nil {
		domains = []string{}
	}
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
	writeJSON(w, map[string]string{"domain": domain, "status": "whitelisted"})
}

func (s *Server) handleWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		http.Error(w, "missing ?domain= query parameter", http.StatusBadRequest)
		return
	}
	s.store.RemoveFromWhitelist(domain)
	writeJSON(w, map[string]string{"domain": domain, "status": "removed"})
}

func (s *Server) handleReload(w http.ResponseWriter, _ *http.Request) {
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
