package api

import (
	"fmt"
	"net/http"
	"runtime/metrics"
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

	// Failure visibility (CL 77). forward_failures is the "does the app hold
	// up" signal: s-hole could not resolve the query and synthesized a SERVFAIL.
	// upstream_errors is a failure rcode a live upstream returned and s-hole
	// relayed, usually not s-hole's fault.
	fmt.Fprintln(w, "# HELP shole_forward_failures_total Total DNS queries s-hole could not resolve (every upstream failed, so it synthesized a SERVFAIL).")
	fmt.Fprintln(w, "# TYPE shole_forward_failures_total counter")
	fmt.Fprintf(w, "shole_forward_failures_total %d\n", snap.ForwardFailures)

	fmt.Fprintln(w, "# HELP shole_upstream_errors_total Total failure rcodes (SERVFAIL/REFUSED) relayed from a live upstream.")
	fmt.Fprintln(w, "# TYPE shole_upstream_errors_total counter")
	fmt.Fprintf(w, "shole_upstream_errors_total %d\n", snap.UpstreamErrors)

	// Per-upstream transport failures: which upstream is flaky, the attribution
	// the query log cannot give (forward aggregates several upstreams into one
	// generic error). Distinct from shole_upstream_errors_total above: that
	// counts relayed failure rcodes (a successful exchange with a bad answer),
	// this counts transport failures (no answer at all), so the two measure
	// disjoint events. Cardinality is bounded by the configured upstream count.
	if s.upstreamTransportFailures != nil {
		if failures := s.upstreamTransportFailures(); len(failures) > 0 {
			fmt.Fprintln(w, "# HELP shole_upstream_transport_failures_total Per-upstream cumulative transport failures (no usable answer: a timeout, a refused connection, or for a DoH upstream a non-200 status or unparsable body) seen by the forward cooldown tracker.")
			fmt.Fprintln(w, "# TYPE shole_upstream_transport_failures_total counter")
			for addr, n := range failures {
				fmt.Fprintf(w, "shole_upstream_transport_failures_total{upstream=\"%s\"} %d\n", escapeLabel(addr), n)
			}
		}
	}

	// DNS-over-TLS certificate health, emitted only while DoT is on. The expiry
	// is a Unix timestamp so an alert rule can compare it with time(), the
	// usual way to watch a certificate; the reload-failure counter catches a
	// renewal whose files did not load (the listener kept the old one).
	if s.dotStatus != nil {
		st := s.dotStatus()
		fmt.Fprintln(w, "# HELP shole_dot_certificate_expiry_timestamp_seconds Unix time when the DNS-over-TLS certificate being served expires.")
		fmt.Fprintln(w, "# TYPE shole_dot_certificate_expiry_timestamp_seconds gauge")
		fmt.Fprintf(w, "shole_dot_certificate_expiry_timestamp_seconds %d\n", st.NotAfter.Unix())
		fmt.Fprintln(w, "# HELP shole_dot_certificate_reload_failures_total Reloads whose certificate files did not load; the listener kept the previous certificate.")
		fmt.Fprintln(w, "# TYPE shole_dot_certificate_reload_failures_total counter")
		fmt.Fprintf(w, "shole_dot_certificate_reload_failures_total %d\n", st.ReloadFailures)
	}

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

	s.writeRuntimeGauges(w)
}

// runtime/metrics sample names for the Go runtime gauges. See writeRuntimeGauges
// for the mapping to the shole_ gauge names.
const (
	metricGoroutines  = "/sched/goroutines:goroutines"
	metricHeapObjects = "/memory/classes/heap/objects:bytes"
	metricHeapUnused  = "/memory/classes/heap/unused:bytes"
)

// writeRuntimeGauges emits the Go runtime gauges (CL 78). They let an external
// monitor see the process leaking before it falls over: s-hole spawns one
// goroutine per query, so a shole_goroutines count that climbs and never settles
// means a handler path is not returning (the goleak tests guard the same property
// in CI). The gauges are read here, at scrape time, never on the query path.
//
// We read the sampled runtime/metrics API instead of runtime.ReadMemStats so a
// scrape never triggers a stop-the-world pause: the runtime maintains these
// values continuously and Read only copies them. The shole_ prefix keeps every
// series under one namespace; the runtime/metrics source path for each gauge is:
//
//	shole_goroutines               /sched/goroutines:goroutines
//	shole_memory_alloc_bytes       /memory/classes/heap/objects:bytes (== MemStats.HeapAlloc)
//	shole_memory_heap_inuse_bytes  /memory/classes/heap/objects:bytes + /memory/classes/heap/unused:bytes
//	                               (== MemStats.HeapInuse: in-use span bytes, i.e.
//	                               allocated objects plus span fragmentation)
//
// The three samples are read in one Read call, never one per gauge, so a scrape
// costs a single sampled read. A sample whose Kind is not KindUint64 (a name a
// future Go release dropped) is skipped rather than emitted as a garbage value.
func (s *Server) writeRuntimeGauges(w http.ResponseWriter) {
	samples := []metrics.Sample{
		{Name: metricGoroutines},
		{Name: metricHeapObjects},
		{Name: metricHeapUnused},
	}
	s.readRuntimeMetrics(samples)

	vals := make(map[string]uint64, len(samples))
	for _, sm := range samples {
		if sm.Value.Kind() == metrics.KindUint64 {
			vals[sm.Name] = sm.Value.Uint64()
		}
	}
	_, haveGoroutines := vals[metricGoroutines]
	_, haveObjects := vals[metricHeapObjects]
	_, haveUnused := vals[metricHeapUnused]

	if haveGoroutines {
		fmt.Fprintln(w, "# HELP shole_goroutines Current number of goroutines.")
		fmt.Fprintln(w, "# TYPE shole_goroutines gauge")
		fmt.Fprintf(w, "shole_goroutines %d\n", vals[metricGoroutines])
	}
	if haveObjects {
		fmt.Fprintln(w, "# HELP shole_memory_alloc_bytes Bytes of allocated heap objects (live and not-yet-freed).")
		fmt.Fprintln(w, "# TYPE shole_memory_alloc_bytes gauge")
		fmt.Fprintf(w, "shole_memory_alloc_bytes %d\n", vals[metricHeapObjects])
	}
	if haveObjects && haveUnused {
		fmt.Fprintln(w, "# HELP shole_memory_heap_inuse_bytes Bytes in in-use heap spans (allocated objects plus span fragmentation).")
		fmt.Fprintln(w, "# TYPE shole_memory_heap_inuse_bytes gauge")
		fmt.Fprintf(w, "shole_memory_heap_inuse_bytes %d\n", vals[metricHeapObjects]+vals[metricHeapUnused])
	}
}
