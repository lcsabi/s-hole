package api

import (
	"fmt"
	"net/http"
)

// handleHealth is a liveness probe. It returns 200 as long as the HTTP
// server itself is responsive. The endpoint deliberately makes no
// downstream calls (DNS, DB, blocklist refresh) so a flaky upstream does
// not cause the container orchestrator to restart s-hole.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

// handleReady is a readiness probe. It returns 200 once the blocklist
// has at least one domain — i.e. the process is actually filtering
// queries — and 503 otherwise. Kubernetes routes traffic away from a
// pod that fails this check, which is the right behaviour while the
// initial blocklist download is still in flight.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if s.store.Len() == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "blocklist empty")
		return
	}
	fmt.Fprintln(w, "ok")
}

// handleMetrics serves the in-process counters in Prometheus text exposition
// format. We hand-roll the format (instead of importing prometheus/client_golang)
// to keep the dependency graph small, matching the project's "auditable in
// an afternoon" goal. The format is RFC-stable: every line is either a
// `# HELP`, a `# TYPE`, or a metric sample.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	snap := s.counter.Snapshot(0)

	fmt.Fprintln(w, "# HELP shole_queries_total Total DNS queries handled.")
	fmt.Fprintln(w, "# TYPE shole_queries_total counter")
	fmt.Fprintf(w, "shole_queries_total %d\n", snap.TotalQueries)

	fmt.Fprintln(w, "# HELP shole_blocked_total Total DNS queries that matched a blocklist.")
	fmt.Fprintln(w, "# TYPE shole_blocked_total counter")
	fmt.Fprintf(w, "shole_blocked_total %d\n", snap.BlockedCount)

	fmt.Fprintln(w, "# HELP shole_cache_hits_total Total DNS responses served from the in-memory cache.")
	fmt.Fprintln(w, "# TYPE shole_cache_hits_total counter")
	fmt.Fprintf(w, "shole_cache_hits_total %d\n", snap.CacheHits)

	if s.dnsCache != nil {
		hits, misses, size := s.dnsCache.Stats()
		fmt.Fprintln(w, "# HELP shole_cache_misses_total DNS cache misses (forwarded to upstream).")
		fmt.Fprintln(w, "# TYPE shole_cache_misses_total counter")
		fmt.Fprintf(w, "shole_cache_misses_total %d\n", misses)
		_ = hits // already exposed via shole_cache_hits_total
		fmt.Fprintln(w, "# HELP shole_cache_size Current number of entries in the DNS response cache.")
		fmt.Fprintln(w, "# TYPE shole_cache_size gauge")
		fmt.Fprintf(w, "shole_cache_size %d\n", size)
	}

	fmt.Fprintln(w, "# HELP shole_blocklist_size Current number of domains in the block set.")
	fmt.Fprintln(w, "# TYPE shole_blocklist_size gauge")
	fmt.Fprintf(w, "shole_blocklist_size %d\n", s.store.Len())

	fmt.Fprintln(w, "# HELP shole_whitelist_size Current number of domains in the runtime whitelist.")
	fmt.Fprintln(w, "# TYPE shole_whitelist_size gauge")
	fmt.Fprintf(w, "shole_whitelist_size %d\n", s.store.WhitelistLen())

	// Querylog back-pressure: non-zero means flush_interval is too long
	// for the query volume or the database is too slow to drain the queue.
	if s.db != nil {
		fmt.Fprintln(w, "# HELP shole_query_log_dropped_total Query log entries dropped because the writer queue was full.")
		fmt.Fprintln(w, "# TYPE shole_query_log_dropped_total counter")
		fmt.Fprintf(w, "shole_query_log_dropped_total %d\n", s.db.Dropped())
	}
}
