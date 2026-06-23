package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/laszlo/s-hole/blocklist"
	"github.com/laszlo/s-hole/querylog"
	"github.com/laszlo/s-hole/stats"
)

//go:embed static
var staticFiles embed.FS

// Server exposes the admin REST API and serves the web UI.
type Server struct {
	counter  *stats.Counter
	db       *querylog.DBLogger // nil when query_db is not configured
	store    *blocklist.Store
	reloadFn func()
}

func New(counter *stats.Counter, db *querylog.DBLogger, store *blocklist.Store, reloadFn func()) *Server {
	return &Server{counter: counter, db: db, store: store, reloadFn: reloadFn}
}

func (s *Server) ListenAndServe(addr string) error {
	fmt.Printf("[api] admin UI → http://%s\n", addr)
	return http.ListenAndServe(addr, s.handler())
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/stats", s.handleStats)
	mux.HandleFunc("GET /api/queries", s.handleQueries)
	mux.HandleFunc("GET /api/whitelist", s.handleWhitelistList)
	mux.HandleFunc("POST /api/whitelist", s.handleWhitelistAdd)
	mux.HandleFunc("DELETE /api/whitelist", s.handleWhitelistRemove)
	mux.HandleFunc("POST /api/reload", s.handleReload)

	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("[api] embed: %v", err)
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

	rows, err := s.db.Recent(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	var body struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Domain) == "" {
		http.Error(w, `invalid body: expected {"domain":"..."}`, http.StatusBadRequest)
		return
	}
	domain := strings.TrimSpace(body.Domain)
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
	go s.reloadFn()
	writeJSON(w, map[string]string{"status": "reload triggered"})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
