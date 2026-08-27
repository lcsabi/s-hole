package api

import (
	"fmt"
	"net/http"
	"strings"
)

// labelEscaper escapes a Prometheus label value per the text exposition
// format: backslash, double-quote, and newline. URLs from operator config
// rarely contain any of these, but a label value must never break the line
// format or inject a second label.
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func escapeLabel(v string) string { return labelEscaper.Replace(v) }

// handleHealth is a liveness probe. It returns 200 as long as the HTTP
// server itself is responsive. The endpoint deliberately makes no
// downstream calls (DNS, DB, blocklist refresh) so a flaky upstream does
// not cause the container orchestrator to restart s-hole.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

// handleReady is a readiness probe. It returns 200 once the blocklist
// has at least one domain, i.e. the process is actually filtering
// queries, and 503 otherwise. Kubernetes routes traffic away from a
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

	fmt.Fprintln(w, "# HELP shole_local_ptr_total Total PTR queries for RFC 6303 private-range zones answered locally with NXDOMAIN.")
	fmt.Fprintln(w, "# TYPE shole_local_ptr_total counter")
	fmt.Fprintf(w, "shole_local_ptr_total %d\n", snap.LocalPTRCount)

	fmt.Fprintln(w, "# HELP shole_cache_hits_total Total DNS responses served from the in-memory cache.")
	fmt.Fprintln(w, "# TYPE shole_cache_hits_total counter")
	fmt.Fprintf(w, "shole_cache_hits_total %d\n", snap.CacheHits)

	if s.dnsCache != nil {
		// Hits are already exposed above from the stats counter; only
		// misses and size come from the cache itself.
		_, misses, size := s.dnsCache.Stats()
		fmt.Fprintln(w, "# HELP shole_cache_misses_total DNS cache misses (forwarded to upstream).")
		fmt.Fprintln(w, "# TYPE shole_cache_misses_total counter")
		fmt.Fprintf(w, "shole_cache_misses_total %d\n", misses)
		fmt.Fprintln(w, "# HELP shole_cache_size Current number of entries in the DNS response cache.")
		fmt.Fprintln(w, "# TYPE shole_cache_size gauge")
		fmt.Fprintf(w, "shole_cache_size %d\n", size)
		// Cache back-pressure: non-zero means the cache filled with live
		// entries and dropped inserts. A sustained rate means cache_size is
		// too small for the working set.
		fmt.Fprintln(w, "# HELP shole_cache_dropped_total DNS cache entries dropped because the cache was full of unexpired entries.")
		fmt.Fprintln(w, "# TYPE shole_cache_dropped_total counter")
		fmt.Fprintf(w, "shole_cache_dropped_total %d\n", s.dnsCache.Dropped())
	}

	fmt.Fprintln(w, "# HELP shole_blocklist_size Current number of domains in the block set.")
	fmt.Fprintln(w, "# TYPE shole_blocklist_size gauge")
	fmt.Fprintf(w, "shole_blocklist_size %d\n", s.store.Len())

	// Per-source breakdown: the aggregate above hides a single source that
	// silently returned an empty or truncated list. size is pre-dedup, so the
	// samples sum to more than shole_blocklist_size. stale is 1 while a source
	// is served from its on-disk cache after a failed fetch, or has never
	// loaded. Cardinality is bounded by the configured URL count.
	if sources := s.store.Sources(); len(sources) > 0 {
		fmt.Fprintln(w, "# HELP shole_blocklist_source_size Domains contributed by one blocklist source (pre-dedup).")
		fmt.Fprintln(w, "# TYPE shole_blocklist_source_size gauge")
		for _, src := range sources {
			fmt.Fprintf(w, "shole_blocklist_source_size{url=\"%s\"} %d\n", escapeLabel(src.URL), src.Count)
		}
		fmt.Fprintln(w, "# HELP shole_blocklist_source_stale Whether a blocklist source is serving stale or no data (1) or fresh data (0).")
		fmt.Fprintln(w, "# TYPE shole_blocklist_source_stale gauge")
		for _, src := range sources {
			stale := 0
			if src.Stale {
				stale = 1
			}
			fmt.Fprintf(w, "shole_blocklist_source_stale{url=\"%s\"} %d\n", escapeLabel(src.URL), stale)
		}
	}

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
