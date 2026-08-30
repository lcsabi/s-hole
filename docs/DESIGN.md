# s-hole: Network-Level DNS Sinkhole

**Authors:** Laszlo (@lcsabi)  
**Created:** 2026-06-23  
**Last Updated:** 2026-08-18  
**Status:** Implementation Complete

---

## Background

Advertising and tracking domains are a persistent source of unwanted traffic on home and small-office networks. Blocking them at the DNS layer, before a connection is even established, is more effective than browser-level filtering, which only protects devices with the extension installed and can be circumvented by per-app DNS-over-HTTPS.

Pi-Hole is the canonical tool for this problem, but it carries significant operational weight: a web stack, a database engine (FTL/dnsmasq fork), and an installer that assumes a Debian-like system. For users who want a lightweight, portable, self-contained binary they can reason about and modify, there is no widely-adopted alternative.

s-hole ("sinkhole") is a minimal DNS sinkhole written in Go. It is designed to be deployed on any always-on machine on the local network, with the router's DHCP server advertising its IP as the DNS resolver for all clients. This gives network-wide ad blocking without per-device configuration and without running software on the router itself.

---

## Goals

- Block DNS queries for domains on community-maintained blocklists before any network connection is made.
- Forward all other queries to a configurable upstream resolver (default: Cloudflare 1.1.1.1, Google 8.8.8.8).
- Cache DNS responses in memory to reduce upstream load and improve latency on embedded hardware.
- Log every query with client IP, domain, and disposition (allowed/blocked) to both a flat file and a SQLite database.
- Expose per-session and historical statistics: total queries, block rate, cache hit rate, top blocked domains, top active clients.
- Surface an admin web UI and REST API for observability and runtime whitelist management.
- Ship as a single static binary with a single YAML config file and no runtime dependencies.
- Be auditable: the full codebase should be small enough for a single engineer to read in an afternoon.
- Run efficiently on low-power ARM hardware (Raspberry Pi) with SD card–friendly I/O patterns.

## Non-Goals

- **DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) termination.** Upstream forwarding uses plain DNS. DoH upstream support is planned as follow-up work (`docs/ROADMAP.md` #5) but is not part of the current implementation.
- **Running on the router.** We assume the router is a commodity device that does not support arbitrary software. Network-wide coverage is achieved by pointing the router's DHCP DNS field at the host running s-hole.
- **DNSSEC validation.** DNSSEC records are passed through transparently; we do not validate or strip them.
- **Per-client policy.** All clients share the same blocklist and whitelist.
- **Admin UI authentication.** The UI is intended for LAN use and has no login. Operators requiring access control should use a firewall rule or reverse proxy.
- **Negative caching.** NXDOMAIN responses are not cached. Only successful (NOERROR) responses with at least one answer record enter the cache.

---

## Design

### High-Level Architecture

```
Client devices (DNS server learned via DHCP from router)
        │ UDP/TCP :53
        ▼
┌────────────────────────────────────────────────────────────────────┐
│                           s-hole process                           │
│                                                                    │
│  ┌──────────┐  blocked?   ┌──────────────────────────────────────┐ │
│  │ Handler  │────────────▶│ Sinkhole reply (zero / NXDOMAIN)     │ │
│  │          │             │ EDNS0 OPT mirrored from request      │ │
│  │          │  cache hit? └──────────────────────────────────────┘ │
│  │          │────────────▶ DNS Response Cache (atomic hits/misses) │
│  │          │  cache miss → upstream forward (health-tracked)      │
│  └────┬─────┘                                                      │
│       │ every query                                                │
│  ┌────▼──────┐  ┌──────────────┐  ┌───────────────────────────┐    │
│  │ Blocklist │  │    Stats     │  │ Query Logger              │    │
│  │   Store   │  │   Counter    │  │ (file + SQLite WAL)       │    │
│  │ (atomic   │  │ (top-N maps  │  │ context-aware reads;      │    │
│  │  Replace) │  │  bounded)    │  │ optional retention prune) │    │
│  └───────────┘  └──────────────┘  └───────────────────────────┘    │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │   Admin HTTP Server (default 127.0.0.1:8080)             │      │
│  │   REST API  +  embedded web UI                           │      │
│  │   /healthz  +  /readyz  +  /metrics                      │      │
│  │   /debug/pprof/*  (opt-in via enable_pprof)              │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                    │
│  ┌─────────────────────┐  ┌──────────────────────────────────┐     │
│  │  Periodic refresh   │  │  Periodic stats print            │     │
│  │  ticker  ── shares ─┼──┤  ticker (panic-recovered)        │     │
│  │  single-flight gate │  └──────────────────────────────────┘     │
│  └─────────────────────┘                                           │
│                                                                    │
│  Structured logging via log/slog. JSON format opt-in.              │
└────────────────────────────────────────────────────────────────────┘
        │ cache miss; ctx-bounded; per-upstream 3 s + cooldown
        ▼
  Upstream DNS (1.1.1.1:53, 8.8.8.8:53, …)
```

### DNS Server (`internal/dnsserver/`)

We use `github.com/miekg/dns` rather than the standard library's `net` package because it provides a complete RFC-compliant DNS message codec, a `ServeMux`-style handler interface, and handles both UDP and TCP transports. Rolling our own DNS codec would be a source of subtle correctness bugs.

Both UDP and TCP listeners are started on the same address:port (default `":53"`, a dual-stack wildcard, so IPv4 and IPv6 clients are served by the same listener; CL 23). DNS clients fall back to TCP automatically when a UDP response is truncated (TC bit set), so both must be active. The forwarder mirrors that fallback on the upstream side: it queries upstreams over UDP first and, when the reply comes back truncated, retries the same upstream over TCP before returning. Without that retry the client's own TCP fallback would dead-end: a TCP query to s-hole would still be forwarded over UDP and yield the same truncated answer. If the TCP retry itself fails, the truncated UDP reply is passed through (the upstream is demonstrably alive, and TC plus a partial answer beats SERVFAIL); truncated responses are never cached.

The `Handler` struct is the core routing point. For each query:

1. Extract the question's domain name and client IP.
2. If `local_ptr` is enabled and the query is a PTR for an RFC 6303 private-range zone (10/8, 172.16/12, 192.168/16, fc00::/7, fe80::/10), record it and return authoritative NXDOMAIN locally, with no blocklist check, no cache, and no upstream call. No public resolver can answer these queries; forwarding only wastes a round-trip and leaks LAN addressing (CL 27).
3. Record the query in `stats.Counter` and `querylog` loggers.
4. If the domain (or any of its parent domains) is on `blocklist.Store` (and no parent is whitelisted), write a sinkhole reply and return.
5. Check the DNS response cache. If a valid (non-expired) entry exists, decrement its TTLs and return it directly.
6. Forward to the first responsive upstream resolver. On success, store the response in the cache.

Upstream forwarding uses a 3-second per-upstream timeout. Upstreams are tried in order; the first successful response wins. Forwarding accepts a `context.Context` so the overall query has a hard deadline (default 10 s) and is cancelled if the calling DNS handler exits.

An in-process upstream health tracker remembers which upstream failed most recently. On the next query, upstreams that failed within the last 30 seconds are skipped on the first sweep, so a primary outage no longer adds 3 s of round-trip latency to every subsequent query. If every upstream is in cooldown, the tracker is bypassed and every upstream is retried (we never want a transient outage to turn into a hard failure).

Blocked replies preserve the EDNS0 OPT pseudo-record from the request when the client advertised one, so a client that advertises EDNS0 (and DNSSEC OK) does not fall back to legacy DNS for the sinkholed response.

### Blocklist Store (`internal/blocklist/`)

The store is an in-memory `map[string]struct{}` (hash set) keyed on normalised domain names (lowercase, no trailing dot). Incoming queries are normalised the same way before lookup (DNS names arrive with a trailing dot and arbitrary casing), so both sides of the comparison share one key space.

Lookup is a **suffix walk** (CL 30): `IsBlocked` tests the queried name and each of its parent domains in turn (`a.b.example.com → b.example.com → example.com → com`), so a single list entry of `example.com` blocks every domain in its subtree. This closes the subdomain-rotation gap that exact-match blocking left open: trackers that rotate `x1.ads.example.com`, `x2.ads.example.com`, … are all caught by one `ads.example.com` entry. The walk reslices the name in place (no allocation) and costs O(labels) hash-set probes, effectively constant for real domain names, and `BenchmarkStore_IsBlocked` (plus its `_Miss` companion, the allowed-query worst case that walks every label) guards the hot path against regression. No new data structure is introduced: it is still two flat hash sets. There is deliberately **no config knob** to restore exact-match blocking; the whitelist (below) is the per-domain escape hatch for an over-broad block entry, so a global switch would only preserve the gap the change exists to close.

Multiple blocklists are merged by construction rather than by an explicit dedup pass: `Update` concatenates the parsed lists and `Replace` inserts them all into the set, where entries appearing in several lists (or differing only in case/trailing dot) collapse to a single key. The `total` reported at startup is the deduplicated set size, which is why it is smaller than the sum of the per-list counts.

Blocklists are downloaded from configurable URLs on startup and periodically thereafter (default: every 24 hours). Both the hosts-file format (`0.0.0.0 ads.example.com`) and the plain-domain-per-line format are supported. Downloaded files are cached on disk so a restart does not require a network round-trip. If a download fails or the server returns a non-200 status, the stale cache is used (the error response body is never written to disk).

If every configured URL fails on a refresh (typically: total network outage), `blocklist.Update` preserves the existing block set rather than replacing it with an empty slice. This prevents a transient outage from silently unblocking every ad until the next successful refresh. The function returns a wrapped error reporting the last failure; the caller logs it but continues to run.

Whenever an update leaves the block set empty, `Update` raises a loud `WARN` (`warnIfEmpty`) so an operator notices s-hole is answering queries while blocking nothing. This covers two cases the ordinary logs would otherwise hide: a fresh first run that could reach no source and had no cache to fall back on, and a source that returned HTTP 200 but parsed to zero valid domains (which previously logged `blocklist updated total=0` at `Info`, indistinguishable from a healthy refresh). `/readyz` already reports the empty state as 503, but that signal is easy to miss on a headless box. An embedded fallback blocklist was considered and rejected for this role (see `docs/ROADMAP.md` #6) because it would mask the failure with stale, license-encumbered data rather than surface it.

Downloads use a dedicated `http.Client` with a 60-second timeout. The response body is wrapped in `io.LimitReader` capped at 256 MiB to bound disk and memory use if a server misbehaves.

A whitelist is checked with the same suffix walk and takes precedence at every level: if the queried name or any of its parents is whitelisted, the query is allowed regardless of blocklist membership, even when a more specific parent is on the block set. Whitelisting `safe.doubleclick.net` lets that name and its subtree through while `ads.doubleclick.net` stays blocked; whitelisting `example.com` exempts everything beneath it. Because whitelist precedence is global (not most-specific-wins), the walk cannot stop at the first blocked parent; it continues until it either finds a whitelisted suffix or exhausts the labels. The whitelist can be extended at runtime via the REST API; runtime additions take effect immediately but do not persist across restarts.

Both entry paths validate entries with `blocklist.ValidDomain`, so a bare label such as a TLD (which, being suffix-matched, would otherwise exempt its whole subtree) cannot reach the store. The two paths differ only in how they refuse: the REST handler rejects an invalid addition outright (`400`), while at startup `config.Load` drops any invalid `whitelist` entry and logs it at `WARN` rather than aborting. A config typo must not take DNS down for the whole LAN, and a dropped entry fails safe: the domain simply stays blockable (CL 31).

Blocklist replacement is atomic from the perspective of DNS handlers: `Store.Replace` swaps the internal map pointer under a write lock, so handlers either see the old list or the new list, never a partial update.

The on-disk cache file is also written atomically: `fetchList` streams to a sibling `.tmp` file and `os.Rename`s on success. A network drop or `kill -9` mid-download leaves only the `.tmp` and the prior cache file in place; the next start still sees a usable cache.

Cache files are deliberately per-URL, verbatim copies of what each server sent, never merged or deduplicated on disk. The stale-fallback contract is per-list (a failing URL falls back to *its own* last good snapshot, independent of the other lists), and an untransformed copy is inspectable evidence when a source misbehaves (see b/007). Deduplication happens for free in the in-memory set.

Entries in a parsed list that fail `ValidDomain` (empty, no dot, over 253 chars, or containing characters illegal in a DNS label) are silently dropped so one malformed blocklist line cannot pollute the store. The same validator gates user-supplied whitelist entries via `POST /api/whitelist`.

### DNS Response Cache (`internal/cache/`)

The cache is a size-bounded, TTL-respecting in-memory store for upstream DNS responses. Its purpose is to avoid redundant upstream round-trips for frequently queried domains, which is especially valuable on low-power hardware where upstream latency is comparatively high.

Key design decisions:

- **Key:** `<qname>\x00<qtype>\x00<qclass>`, the full question identity. `Qclass` is included so cross-class queries (e.g. `ClassCHAOS` for `version.bind`) cannot collide with the dominant `ClassINET` traffic.
- **Value:** a cloned `dns.Msg` with the time it was cached and the minimum TTL across all answer records.
- **TTL adjustment:** on retrieval, elapsed seconds are subtracted from each record's TTL so clients receive accurate expiry times.
- **Eviction:** when the cache reaches `cache_size` entries, `Set` first tries to reclaim a slot from an expired entry (a bounded scan of at most `reclaimScanLimit` entries). `Get` marks expired entries as misses but leaves them in the map until the once-a-minute sweep, so without on-insert reclaim a cache full of not-yet-swept corpses would refuse every insert for up to a minute. If the bounded scan finds no expired entry, the cache is full of live entries: the new entry is dropped and counted, and `shole_cache_dropped_total` surfaces the rate so a sustained non-zero value is the signal to raise `cache_size`. LRU is deliberately not used: it requires a move-to-front on every `Get`, a write on the read path. `Get` is a bare `RLock` read today (the hit/miss counters are atomic), so LRU would turn every cache hit into an exclusive `Lock` and serialize readers, the contention `BenchmarkCache_Get_Parallel` exists to catch. For a read-dominated cache at home-DNS scale that is the wrong trade; if recency ever mattered, a scheme that keeps `Get` read-only (CLOCK or SIEVE: an atomic visited-bit, no reorder on hit) is the way in, not LRU.
- **Only NOERROR responses with at least one answer are cached.** NXDOMAIN, SERVFAIL, empty-answer, and truncated (TC bit) responses are not stored, because a truncated message carries an incomplete answer section that would otherwise be replayed for its full TTL.
- **Cleanup:** a background goroutine sweeps expired entries every minute. It exits cleanly on `Cache.Close()`, which is invoked from the shutdown path so the goroutine never outlives the process.
- **Cache hit rate** is tracked in `stats.Counter` and reported in both the periodic `Print()` output and `GET /api/stats`.

### Sinkhole Responses

Two modes are supported via `block_mode` in config:

| Mode | A query reply | AAAA query reply | Other types |
|------|--------------|-----------------|-------------|
| `zero` (default) | `0.0.0.0` | `::` | NOERROR, empty answer |
| `nxdomain` | NXDOMAIN | NXDOMAIN | NXDOMAIN |

`zero` is the default because `NXDOMAIN` causes some clients to aggressively retry, log errors, or display alarming UI. Returning a routable-but-unroutable address fails silently at the TCP connect layer, which is the behaviour most consistent with "nothing happened."

The TTL on sinkhole replies is configurable (`block_ttl`, default 300 seconds). A short TTL means a whitelisted domain becomes reachable within TTL seconds after being added to the whitelist, without requiring a client cache flush. An explicit `block_ttl: 0` is honored: it tells clients not to cache sinkhole replies at all, trading query volume for instant whitelist effect.

### Query Logging (`internal/querylog/`)

Query logging is split into two independent backends behind a `Multi` fan-out:

**FileLogger** writes one line per query to a flat file:
```
2026-06-23T10:04:05Z BLOCK 192.168.1.42 ads.example.com.
```
Suitable for `grep`, `tail -f`, and log rotation via external tools (e.g. `logrotate`).

**DBLogger** writes to a SQLite database (`modernc.org/sqlite`, pure Go, no CGO). It runs an internal goroutine that batches inserts: entries accumulate for up to `db_flush_interval` (default 30 seconds) or 100 entries, then are committed in a single transaction. This decouples DNS handler latency from disk I/O. If the channel buffer (capacity 1000) is full, entries are dropped rather than blocking a DNS goroutine, since logging completeness is subordinate to DNS availability.

On shutdown, `DBLogger.Close()` blocks on a `sync.WaitGroup` until the writer goroutine has drained the channel and committed the final batch. Only then is the underlying `*sql.DB` closed. This guarantees the last batch of queries is never lost on a clean exit.

`Recent` and `TopBlocked` accept a `context.Context` and pass it through to `db.QueryContext`, so a client-disconnect on the admin server cancels the underlying SQL query rather than letting it run to completion.

A retention prune goroutine runs every hour when `query_db_retention_days > 0`, issuing `DELETE FROM queries WHERE ts < ?` against the configured cutoff. Default is 0 (retain forever).

The `querylog.Logger` interface (`Log(clientIP, domain string, blocked bool)`) is implemented by `FileLogger`, `DBLogger`, and `Multi`, with compile-time assertions in the package so a future signature drift is caught at build time rather than at the call site.

**SQLite pragmas applied on open:**
```sql
PRAGMA busy_timeout=5000;      -- wait for a held lock instead of failing with SQLITE_BUSY
PRAGMA journal_mode=WAL;       -- write-ahead log: reads don't block writes
PRAGMA synchronous=NORMAL;     -- no fsync per commit; WAL checkpoint is still safe
PRAGMA cache_size=-8000;       -- 8 MB page cache
PRAGMA temp_store=MEMORY;      -- keep temp tables off disk
```
WAL mode combined with `synchronous=NORMAL` reduces write amplification by roughly 10× compared to SQLite's default rollback journal. This is the primary mitigation for SD card wear on Raspberry Pi deployments.

The `*sql.DB` pool is pinned to a **single connection** (`SetMaxOpenConns(1)`). SQLite permits only one writer at a time; with the default multi-connection pool the async batch writer and the retention prune (both writers) could land on separate connections and collide with `SQLITE_BUSY`, silently skipping a prune (b/038). One connection makes `database/sql` queue callers instead, and ensures the per-connection pragmas above apply to the connection that serves every query. `busy_timeout` remains as defence against an external process holding the lock. At home-network query volume the lost read concurrency is immaterial.

The SQLite schema:
```sql
CREATE TABLE queries (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT    NOT NULL,
    client_ip TEXT    NOT NULL,
    domain    TEXT    NOT NULL,
    blocked   INTEGER NOT NULL
);
```

`log_queries` controls verbosity: `all` (default), `blocked`-only, or `none`. Both backends respect this setting independently.

### Statistics (`internal/stats/`)

`Counter` maintains atomic counters for total queries and cache hits. The blocked count is deliberately *not* atomic: `RecordQuery` already takes the mutex to update the top-domain tally, so `blocked` is guarded by that same mutex; promoting it to an atomic would be redundant and misleading. Per-domain block counts and per-client query counts are tracked in the mutex-protected maps. Top-N extraction copies the map entries under the lock (resolving the map pointer *inside* the lock, since the prune reassigns it, R31) and sorts the copy outside it to minimise contention.

`Snapshot(topN int)` returns a `Summary` struct with json tags, making it directly serialisable by the REST API without coupling the stats package to any HTTP library. Fields include uptime, totals, block percentage, local-PTR count (`local_ptr_count`, queries answered locally per RFC 6303), cache hit count and percentage, blocklist size (`blocklist_size`, set by the API handler after calling `Snapshot`, since the stats package does not depend on the blocklist package), and top-N entry lists. The per-source blocklist health (`sources`, an array of `{url, count, last_refresh, stale}`) is added the same way: the api handler wraps `Summary` in a `statsResponse` and fills `sources` from `blocklist.Store.Sources()`, so the stats package still takes no blocklist dependency. `count` is the pre-dedup domain count each source contributed, so the sum exceeds `blocklist_size`; `stale` is true while a source is served from its on-disk cache after a failed fetch, or has never loaded.

`Snapshot` loads `blocked`, `localPTR`, and `cacheHit` all *before* `total`. This load order matters: `RecordQuery` increments `total` atomically *before* taking the mutex and incrementing `blocked`, so reading `total` first allows concurrent queries to inflate `blocked` past the snapshotted `total` and yield a block percentage greater than 100. Reading `blocked` first guarantees the invariant `blocked ≤ total`. `localPTR` and `cacheHit` are also incremented after `total` (by `RecordLocalPTR` and the cache-hit path, both after `RecordQuery`), so each must be read before `total` for the same reason. The cache-hit-rate denominator is `total − blocked − localPTR` because neither blocked nor local-PTR queries ever reach the cache or the upstream.

The per-domain and per-client tally maps are capped at 4 096 entries each. When the cap is exceeded, the bottom half by count is dropped, preserving the high-traffic entries that the top-N report cares about and keeping memory bounded against a long-running process that sees millions of unique keys.

### Admin Interface (`internal/api/`)

An HTTP server (default `127.0.0.1:8080`, localhost only) serves two things:

1. **REST API.** JSON endpoints backed by `stats.Snapshot`, `querylog.DBLogger.Recent`, and `blocklist.Store` methods.
2. **Web UI.** A single-page dashboard embedded in the binary via `//go:embed`. It polls `/api/stats` and `/api/queries` every 3 seconds and renders stat cards, top domain/client tables, a per-source blocklist health panel (URL, domain count, last refresh, and an OK/STALE badge), an actions panel (blocklist reload, whitelist add, and a "why is this blocked?" domain check that shows the decision and the full suffix walk), and a recent query log. The Top Blocked Domains panel has a "Since start / All time" toggle: "Since start" reads the in-memory `top_domains` tally from `/api/stats` (resets on restart, caps at `topNMaxEntries`), while "All time" polls `/api/top-blocked` for the persistent SQLite tally.

The web UI has no external dependencies (no CDN, no framework). It is pure HTML/CSS/JS and works without an internet connection.

The HTTP server is held in an `atomic.Pointer[http.Server]` so it can be gracefully shut down. `Serve` stores it from the background serve goroutine and `Shutdown` reads it from the signal goroutine, so the field is atomic to keep those two accesses race-free (b/053). `doStop` in `cmd/s-hole/main.go` calls `apiServer.Shutdown(ctx)` with a 5-second context before terminating the process, which drains in-flight admin requests. A Shutdown that runs before `Serve` has stored the server records the stop request (a second atomic); `Serve` checks that flag right after it stores the server and stops instead of blocking in Accept, so the stop is never lost even in that startup window (b/054). `http.ErrServerClosed` is suppressed inside `Serve` so a clean shutdown does not log a spurious error.

main binds `api_listen` synchronously (`net.Listen`, then `apiServer.Serve(ln)`) so a bad address or a port conflict is caught at startup, not inside a goroutine. A failed admin bind is fail-open: main logs a WARN, keeps serving DNS, and the startup banner reports the admin UI as unavailable rather than advertising a URL that refuses connections. DNS is the critical service, so it must not die because the optional dashboard could not bind (b/052). `ListenAndServe(addr)` remains as the one-call bind-and-serve form.

Explicit timeouts are configured on the server (`ReadHeaderTimeout=5s`, `ReadTimeout=15s`, `WriteTimeout=30s`, `IdleTimeout=60s`) to defend the unauthenticated LAN-facing endpoint from slowloris-style attacks. POST handlers that accept JSON bodies wrap `r.Body` in `http.MaxBytesReader` (64 KiB) so an attacker cannot exhaust memory by streaming an unbounded payload.

Blocklist refresh is single-flighted via a `sync.Mutex` held in `cmd/s-hole/main.go` and shared between the periodic refresh timer and the API. The reload closure tries to acquire the lock and returns `true` synchronously if it took it (work proceeds asynchronously in a goroutine) or `false` if a refresh is already running. `POST /api/reload` surfaces the boolean as `"reload triggered"` vs `"reload already in progress"`. Centralising the lock in the closure rather than in `api.Server` ensures the periodic timer cannot bypass the gate.

State-changing admin requests leave an audit line in the application log. A whitelist add or remove logs the domain and the requester address at `Info`. Each blocklist reload logs its trigger source: `via API` with the client address, `via timer`, or the existing SIGHUP `reload signal received` line. The admin API is unauthenticated on the LAN, so a whitelist change un-blocks a domain for the whole network. The log is the record of who changed what and when. slog writes it to stdout (journald captures it under systemd, and the Windows Event Log captures it under the SCM), and s-hole keeps no separate audit store.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Live stats snapshot (uptime, totals, cache rate, blocklist size, per-source blocklist health, top domains/clients) |
| `/api/check` | GET | Block decision for `?domain=NAME`: outcome plus the full suffix walk (matched block entry, overriding whitelist entry). Diagnostic; bumps no counter and writes no query-log row |
| `/api/queries` | GET | Recent queries from SQLite (`?limit=N`, default 50, capped at 1000) |
| `/api/top-blocked` | GET | All-time most-blocked domains from SQLite (`?limit=N`, default 50, capped at 1000); empty list when `query_db` is unset |
| `/api/whitelist` | GET | List runtime-whitelisted domains |
| `/api/whitelist` | POST | Add domain: `{"domain":"..."}`. 64 KiB body cap; rejects malformed domains via `blocklist.ValidDomain`. |
| `/api/whitelist` | DELETE | Remove domain: `?domain=...` |
| `/api/reload` | POST | Trigger immediate blocklist refresh (de-duplicated via single-flight mutex) |
| `/healthz` | GET | Liveness probe. Returns 200 OK while the HTTP server is responsive |
| `/readyz` | GET | Readiness probe. 200 OK once the blocklist has loaded at least one entry, 503 otherwise. Used by container orchestrators to route traffic away while the initial download is in flight. |
| `/metrics` | GET | Prometheus text exposition: `shole_queries_total`, `shole_blocked_total`, `shole_local_ptr_total`, `shole_cache_hits_total`, `shole_cache_misses_total`, `shole_cache_size`, `shole_cache_dropped_total`, `shole_blocklist_size`, `shole_blocklist_source_size`, `shole_blocklist_source_stale`, `shole_whitelist_size`, `shole_query_log_dropped_total` |
| `/debug/pprof/*` | GET | Standard Go pprof handlers. **Only registered when `enable_pprof: true`** (or `S_HOLE_ENABLE_PPROF=1`). Off by default; intended for incident response on a localhost-bound admin server. |

### Observability and Logging

Logging is structured via `log/slog`. Each package binds a child logger with a `pkg=<name>` attribute so a grep on the log stream cleanly separates DNS, blocklist, querylog, and api messages. The default handler is text on stdout (`time=… level=… msg=… key=value`); `S_HOLE_LOG_FORMAT=json` switches to JSON, which is what most container/log-aggregation pipelines expect. A Windows service process has no console, so a stdout handler would discard every line. When `service.IsWindowsService()` reports the process was launched by the SCM, `setupLogger` routes slog to the Windows Event Log instead (source `s-hole`, mapping `Info`/`Warn`/`Error` to the three Event Log severities); if opening the source fails it falls back to the stdout handler, so the process is never left with no logger. The event-log handler drops the time and level from the message text because the Event Log records both itself. This is the application log only; the per-query `ALLOW`/`BLOCK` stream is the separate `FileLogger` (`log_file`).

Operational diagnostics ship over two surfaces:

- **`/healthz`**: a tiny endpoint that returns 200 as long as the HTTP server is responsive. Liveness only; it deliberately makes no downstream call so a flaky upstream cannot cause the container orchestrator to restart the process.
- **`/readyz`**: a readiness probe that returns 200 once `store.Len() > 0` (the blocklist has loaded at least one entry) and 503 otherwise. Pairs with `/healthz` to give a Kubernetes-style probe split: don't restart, but do route traffic away while the initial blocklist download is in flight.
- **`/metrics`**: Prometheus text exposition (format `0.0.4`) for the in-process counters: query totals, block counts, local-PTR count (`shole_local_ptr_total`, private-range PTR queries answered locally per RFC 6303), cache hits/misses, cache size, `shole_cache_dropped_total` (entries dropped because the cache was full of unexpired entries), blocklist size, per-source blocklist health (`shole_blocklist_source_size` and `shole_blocklist_source_stale`, labeled by URL), whitelist size, and `shole_query_log_dropped_total` (entries dropped because the writer channel was full; a sustained non-zero rate means `db_flush_interval` is too long for the query volume). The full metric list is in the API table above. We hand-roll the exposition rather than pulling in `prometheus/client_golang` to keep the dependency graph small.
- **`/debug/pprof/*`**: the six standard `net/http/pprof` handlers (index, cmdline, profile, symbol, trace, plus the typed profiles under the index). Registered only when `enable_pprof: true` is set in config (or `S_HOLE_ENABLE_PPROF=1`). Off by default; required for live CPU/heap profiling during incident response. Enabling it also turns on mutex and block profiling (`runtime.SetMutexProfileFraction` / `SetBlockProfileRate`, CL 53), which stay off in the Go runtime by default, so `/debug/pprof/mutex` and `/debug/pprof/block` report the lock contention on the RWMutex-guarded hot path; both sample rather than record every event, so the cost is paid only while pprof is on. A WARN log fires at startup when enabled, recommending a localhost-bound `api_listen`.

Periodic `runTicker` goroutines (stats print, blocklist refresh) are wrapped in `recover()`. A panic inside the ticker function is logged with its goroutine stack and the next tick still fires, so a transient parser failure no longer silently freezes the refresh loop. `runTicker` also honors an application-wide `context.Context` that `doStop` cancels first, so the tickers unwind cleanly rather than depending on `os.Exit` to reclaim them.

### Startup Network Hint

On startup, `cmd/s-hole/main.go` calls `printNetworkHint`, which enumerates local interface addresses via `net.InterfaceAddrs()`, filters out loopback and link-local addresses, and prints a bordered box listing the DNS server address for each LAN-facing IPv4 address. The Admin UI line honors where the API is actually bound (T4): with the localhost-only default it prints a single `http://127.0.0.1:<port> (this machine only)` line rather than advertising LAN URLs that would refuse connections. This removes the need for the operator to manually discover the machine's IP when configuring the router's DHCP DNS field. `deploy/install-linux.sh` prints the same banner at the end of installation using `hostname -I`, with the same `api_listen`-aware Admin UI logic.

### Configuration (`internal/config/`)

All configuration lives in a single YAML file. The struct uses `yaml` tags and applies safe defaults in `applyDefaults()` so the minimal valid config is an empty file. Duration fields are stored as strings and parsed at startup; invalid durations are fatal errors rather than silently ignored.

Three fields (`cache_size`, `block_ttl`, and `local_ptr`) have defaults seeded onto the struct *before* the YAML decode instead of in `applyDefaults()`. Their zero values are meaningful settings (`cache_size: 0` disables the cache; `block_ttl: 0` disables client caching of sinkhole replies; `local_ptr: false` opts out of RFC 6303 local PTR answering), and a post-decode fixup cannot tell an explicit 0/false in the file apart from an absent key.

A `Validate()` method runs after `Load()` and rejects unrecognised values for the enumerated fields (`block_mode`, `log_queries`). A typo such as `block_mode: "NXDOMAIN"` is now a fatal startup error instead of a silent fallback to the default, so operator misconfiguration is surfaced immediately at the source.

`applyEnvOverrides()` runs after `applyDefaults()` and lets a container deployment override any commonly-tuned field via an `S_HOLE_*` environment variable without rebuilding a bind-mounted YAML file. The full list is in `../README.md`. Malformed numeric values are silently ignored so a typo in an env var never blocks startup.

### Packaging and Deployment (`internal/service/`, `deploy/`, `Dockerfile`)

Three deployment targets are supported:

**Windows Service.** `internal/service/svc_windows.go` (build tag `windows`) integrates with the Windows Service Control Manager via `golang.org/x/sys/windows/svc`. The binary accepts `-service install|uninstall|start|stop` flags. When launched by the SCM, `svc.IsWindowsService()` is detected and the process enters the SCM event loop; a stop control from the SCM calls the same `doStop` function as a Ctrl+C in interactive mode. `internal/service/svc_other.go` (build tag `!windows`) provides no-op stubs with the same function signatures so `cmd/s-hole/main.go` requires no platform conditionals of its own.

Because a service has no console, `-service install` also registers a Windows Event Log source (`eventlog.InstallAsEventCreate`) and `-service uninstall` removes it, and `setupLogger` routes slog to that source when the SCM launches the process (see the logging note above). The handler logic lives in `internal/service/eventlog.go` behind a small `eventWriter` interface with no build tag, so it compiles and is unit-tested on Linux with a fake writer; only the `eventlog.Open` constructor (`eventlog_windows.go`, with a `!windows` stub in `eventlog_other.go`) is platform-specific.

**Linux systemd.** `deploy/s-hole.service` runs as a dedicated `s-hole` system user. `AmbientCapabilities=CAP_NET_BIND_SERVICE` allows binding port 53 without root. `ProtectSystem=strict` and `NoNewPrivileges` limit the blast radius of any exploit. `deploy/install-linux.sh` automates the full installation; the systemd unit is embedded as a heredoc inside the script, so only the script itself (plus the binary and config) needs to be copied to the target machine. A companion `deploy/uninstall-linux.sh` reverses it (service, unit, binary, config, and system user/group), preserving the data directory unless `--purge` is given, and restoring the `systemd-resolved` stub (removing the `DNSStubListener=no` drop-in) only under `--restore-resolved`.

**Docker.** A multi-stage `Dockerfile` builds a statically linked binary (`CGO_ENABLED=0`) in a `golang:alpine` stage and copies it into an `alpine` runtime image for SSL certificate access (needed for HTTPS blocklist downloads). The binary lives on `PATH` (`/usr/local/bin/s-hole`), deliberately outside the `/app` directory, which is declared a `VOLUME` for config and database persistence, since a bind mount over `/app` would otherwise shadow a binary placed there (b/039).

**Cross-compilation.** A `Makefile` provides `make pi` (arm64), `make pi32` (armv7), and `make linux` (amd64) targets. All produce stripped binaries (~10–17 MB) with no host toolchain requirements beyond the Go compiler. The Makefile also exposes the standard development targets (`make check`, `test`, `test-race`, `bench`, `lint`, `fmt`, `vet`, `install`, `version`); `make help` lists the full set.

**Build identity.** `internal/version` holds three vars (`Version`, `Commit`, `BuildDate`) written at link time via `-X` ldflags. The Makefile populates them from `git describe`, `git rev-parse`, and the current UTC timestamp; the Dockerfile accepts them as `--build-arg`; CI fills them from the GitHub Actions context. Source builds without those flags fall back to placeholder values (`dev` / `unknown` / `unknown`), which is acceptable for `go install` use. `s-hole -version` prints the full identity at any time.

---

## Alternatives Considered

### Use Pi-Hole directly

Pi-Hole solves this problem well for Raspberry Pi / Debian deployments. We ruled it out because: it requires a full Linux install, cannot be deployed as a single binary on Windows or macOS, and the codebase (a PHP web UI + a C DNS daemon fork) is not easily auditable or modified.

### Use CoreDNS with a blocklist plugin

CoreDNS is production-grade and has a plugin ecosystem. The `ads` plugin does DNS sinkholing. We ruled this out because the goal is also to learn by building: using CoreDNS would replace the implementation with configuration. CoreDNS also pulls in a large dependency tree.

### Use `NXDOMAIN` as the default sinkhole response

`NXDOMAIN` is semantically correct ("this domain does not exist") and is what Pi-Hole uses in some modes. We chose `0.0.0.0` as the default because some client applications (notably Windows Update, certain game launchers) interpret `NXDOMAIN` as a network error and surface it to the user, while a connection to `0.0.0.0` fails silently at the socket layer. Both modes are available via `block_mode`.

### In-process blocklist update via a signal

Linux is the primary deployment target: the Raspberry Pi optimisations, the hardened systemd unit, and the Docker image are all built around it; Windows is supported (`-service install` and SCM integration) but is not the design's centre of gravity. Accordingly, `SIGHUP` is wired up as the conventional "reload config" gesture on every non-Windows build: `kill -HUP $(pidof s-hole)` triggers the same single-flight refresh as `POST /api/reload`. Operators get the muscle-memory behaviour even when the admin API is disabled or firewalled.

The implementation lives in two tiny build-tagged files (`cmd/s-hole/signals_unix.go` and `cmd/s-hole/signals_windows.go`) so `cmd/s-hole/main.go` itself contains no platform-specific code. On Windows, `reloadSignals()` returns nil and the only signals notified are SIGINT/SIGTERM. The SCM is the canonical lifecycle control there, and POST /api/reload remains available for on-demand refresh.

### LRU eviction for the DNS cache

LRU eviction would make better use of cache capacity by removing the least-recently-used entries when full. We chose drop-on-full (with expired-slot reclaim on a full insert) because: (a) home DNS traffic is dominated by a small hot set of domains that will be re-cached quickly, (b) the cache is sized generously (default 2000 entries) relative to typical household domain diversity, and (c) LRU requires a move-to-front on every `Get`, a write on the read path. `Get` is a bare `RLock` read today, so LRU would turn every cache hit into an exclusive `Lock` and serialize readers, the contention `BenchmarkCache_Get_Parallel` exists to catch; for a read-dominated cache that is the wrong trade. If recency ever mattered, a scheme that keeps `Get` read-only (CLOCK or SIEVE) would be the way in, not LRU. Whether even that is needed is now measurable: `shole_cache_dropped_total` counts inserts refused because the cache was full of live entries, so the decision to add a smarter eviction policy is gated on that metric showing sustained pressure (see the pending decision in `docs/ROADMAP.md`), not on speculation about thrashing.

### `kardianos/service` for cross-platform service management

`kardianos/service` provides a unified API for Windows, systemd, and launchd service registration. We chose to implement only Windows SCM integration (using `golang.org/x/sys/windows/svc`) and provide a static systemd unit file for Linux, because: the library adds a dependency, the systemd unit gives more control over hardening flags, and launchd (macOS) is not a target deployment platform.

---

## Security Considerations

- **DNS amplification:** s-hole listens on a LAN-facing address. It should not be exposed on a public IP. No rate-limiting or source validation is implemented; this is accepted scope for a LAN deployment.
- **Blocklist URLs:** URLs come from operator-controlled config, not from user input. The downloader follows HTTP redirects without restriction; operators should use HTTPS URLs from trusted sources.
- **SQLite file permissions:** The query log database is created with mode `0644`. On a shared machine, other local users can read query history. Operators requiring confidentiality should use filesystem-level access controls.
- **Port 53 binding:** Binding to port 53 requires elevated privileges (root / Administrator) or `CAP_NET_BIND_SERVICE`. The systemd unit grants the capability without running as root. On Windows, the binary runs as the LocalSystem account when installed as a service. Port 53 is non-negotiable for deployment: DHCP options, `resolv.conf`, and OS network settings identify DNS servers by IP address only (there is no port field anywhere in that chain), so every client on the LAN sends to `<ip>:53` unconditionally. High ports (e.g. 5353 in the CONTRIBUTING smoke test) are strictly a development convenience for queries addressed to the server explicitly.
- **Admin UI:** The HTTP server has no authentication. As of CL 12 the default `api_listen` is `127.0.0.1:8080`; operators who want LAN access must opt in by setting `0.0.0.0:8080` (or a specific LAN interface). The HTTP server enforces conservative timeouts (`ReadHeaderTimeout=5s`, `ReadTimeout=15s`, `WriteTimeout=30s`, `IdleTimeout=60s`) and a 64 KiB body cap on POST endpoints to defend against slowloris and memory-exhaustion attacks from LAN peers.
- **`/healthz`, `/readyz`, and `/metrics`** are unauthenticated alongside the rest of the API. They are intended for local Prometheus / probe access; do not expose to the public internet.
- **`/debug/pprof/*`** when enabled (`enable_pprof: true`) reveals goroutine stacks, heap layouts, and binary symbols, which are useful for incident response and dangerous if exposed to the LAN. Enabling it also activates mutex and block profiling, which add per-lock bookkeeping to every goroutine while on. The startup log fires a WARN when it is on; operators should pair it with `api_listen: "127.0.0.1:8080"`.

## Privacy Considerations

The query log records client IP addresses and all queried domain names. On a home network this constitutes a detailed browsing history for all devices. The SQLite file and flat log file should be treated as sensitive data. Operators should consider setting `log_queries: blocked` or `log_queries: none` if a full query log is not needed.

---

## Testing Strategy

- **Unit tests:** Every implementation package under `internal/` ships a `*_test.go` file. Coverage targets (checked in review, not a strict CI gate): `stats`, `config`, and `version` 100 %; `cache` ≥ 94 %; `api`, `blocklist`, `dnsserver`, and `querylog` ≥ 85 %. The `cmd/s-hole` bootstrap (the `main()` wiring and signal-dispatch goroutine) and the platform-specific `internal/service` glue run below these targets because they need a running binary or Windows; both are exercised by manual smoke tests. Run `go test -cover ./...` for the current numbers; module-wide coverage tracks around 80 %.
- **What the unit tests exercise:** `blocklist.Store` lookup, suffix (subdomain) blocking and whitelist suffix precedence, atomic `Replace`, the `Explain` diagnostic walk (decision plus matched block/whitelist entries), `parseHostsFormat` against both formats, `Update` preserving the store on full-failure refresh, raising the empty-block-set alarm when a refresh loads nothing, and recording per-source status (healthy plus hard-failure), `ValidDomain` rejecting garbage, atomic cache file write; `cache.Cache` TTL decrement, drop-on-full (with the drop counter and expired-slot reclaim on a full insert), Qclass-aware keying, `cleanupExpired` sweep, `Close` shutdown; `config.Load` with empty/partial/invalid YAML dropping invalid whitelist entries, `Validate` rejecting bogus enums, every duration-parser error path, every `S_HOLE_*` env override; `stats.Counter` concurrent invariants (block rate never exceeds 100 % under parallel writers, `local_ptr_count` never exceeds `total_queries` under parallel PTR writers, cache hit rate never exceeds 100 % under parallel cache-hit writers), top-N map cap, `Print` output; `querylog.FileLogger` filtering modes + fallback paths, `DBLogger` round-trip, final-flush-on-Close, retention prune; `dnsserver.Handler` sinkhole (zero + nxdomain), local PTR (RFC 6303 private-range zones, case-insensitive name matching, NXDOMAIN with EDNS0, disabled-forwards-upstream, public-PTR-forwarded), cache-hit, cache-miss-forward, whitelist override, empty-question, EDNS0 pass-through, write-error branches; `dnsserver.Server` full Start→query→Shutdown lifecycle on a real UDP port; the upstream health tracker (cooldown, failover, second-sweep retry); the `api` HTTP handlers including reload single-flight, the 64 KiB body cap, `Serve`/`ListenAndServe`/`Shutdown` lifecycle, the synchronous bind-failure path, and the concurrent `Serve`/`Shutdown` race guard, `/healthz`, `/metrics`, `blocklist_size` and per-source health fields in `/api/stats`, `/api/check` (blocked/whitelisted/allowed decisions, bad-domain rejection, and the no-stats-side-effect guarantee), `/api/top-blocked` (real-DB ordering and the db-disabled empty-list path), malformed-input rejection, encoder-error branch.
- **Regression traceability:** many of these are regression tests pinned to specific bug numbers (b/005, b/007, b/010, b/017, b/018, b/021, b/022, b/024, b/026, b/028, b/029, b/032, b/033, b/034, b/035, b/036, b/038) or staff-review IDs (R3, R4, R5, R6, R8, R9, R12, R13, R14, R15, R16, R17, R18, R19, R26, R27, R31, R32, R33, R34, R35, R36, R37, R38, T1–T6). The `b/NNN` and `R/S/T NN` identifiers appear in the relevant test comments and, for bugs, in `docs/BUGS.md`.
- **DNS handler unit tests** use a `fakeWriter` implementing `dns.ResponseWriter`; the cache-hit path is exercised by pre-populating the in-memory cache, bypassing the upstream resolver entirely. The forwarder tests use a real in-process miekg/dns server on `127.0.0.1:0` so the production code path (including `dns.Client.ExchangeContext`) is exercised end-to-end.
- **Server lifecycle test** binds the production `dnsserver.Server` to a free port (UDP + TCP), confirms a real `dns.Client.Exchange` round-trips through the handler, and verifies `Shutdown` causes `Start` to return. It is the only test that touches the bind+listen path.
- **Fuzz tests:** `internal/blocklist/fuzz_test.go` fuzzes `ValidDomain`, `parseHostsFormat`, and `cacheFilename`. The parser fuzz asserts every emitted domain itself passes `ValidDomain`; the filename fuzz asserts the result is platform-safe (no `/`, `\`, or `:`). Run with `go test -fuzz=FuzzValidDomain -fuzztime=30s ./internal/blocklist/`.
- **Integration test:** `internal/dnsserver/integration_test.go` wires the full stack (`blocklist.Store` + `cache.Cache` + `querylog.DBLogger` on a real SQLite file + `dnsserver.Handler` + `dnsserver.Server` on a free UDP port + a mock upstream) and exercises three real DNS queries (blocked, forwarded-and-cached, cache-hit). Catches wiring bugs (constructor arg order, nil dependencies, fan-out misconfig) that unit tests miss.
- **Benchmarks:** the set covers the in-process request cycle (blocklist decision → cache lookup → reply construction) plus the stats record path and the periodic parse path. `BenchmarkStore_IsBlocked` and `BenchmarkStore_IsBlocked_Miss` run against a 100 000-entry store and guard against accidental O(n) regressions; the `_Miss` variant walks a deep, not-blocked name to the TLD (the suffix walk's worst case and the common allowed-query path). `BenchmarkCache_Get` (CL 32) measures the cache-hit path, whose cost and per-op allocations are dominated by the defensive `msg.Copy` and `decrementTTLs` walk. `BenchmarkHandler_ServeDNS` (CL 32) drives `Handler.ServeDNS` through the stub `ResponseWriter` on its `Blocked` and `Cached` sub-paths; all three CL-32 benchmarks call `ReportAllocs`. `BenchmarkCounter_RecordQuery` (CL 52) covers the per-query stats update; its `ManyDomains` sub-benchmark drives the top-N map past its cap so the prune path runs, which the handler benchmark never reaches because it reuses one domain. `BenchmarkCache_Set` (CL 52) covers the cache write path taken on a miss, the counterpart to `BenchmarkCache_Get`. `BenchmarkParseHostsFormat` (CL 52) covers blocklist parse throughput over a 100 000-line list, the startup and refresh path. `BenchmarkStore_IsBlocked_Parallel`, `BenchmarkCache_Get_Parallel`, and `BenchmarkHandler_ServeDNS_Parallel` (CL 53) run those read paths under `b.RunParallel`, the one-goroutine-per-query concurrency the handler runs in, so a lock-contention regression a serial benchmark cannot see (an exclusive `Lock` on a read path, or work moved under a mutex) shows up. `BenchmarkStore_Replace` (CL 53) measures the reload swap that rebuilds the blocked set under the write lock. `BenchmarkCache_Set_DropOnFull` and `BenchmarkCache_CleanupExpired` (CL 53) cover the two cache-maintenance paths the write benchmark skips: the copy-then-drop cost on a full cache, and the once-a-minute O(n) sweep held under the write lock. `BenchmarkDBLogger_Flush` (CL 53) measures the query-log batch commit, the single-connection drain budget (b/038) that bounds how fast the async writer clears its channel before `Log` starts dropping; `BenchmarkDBLogger_Log_Parallel` confirms the enqueue stays non-blocking under concurrent callers. The upstream-forwarding path is left unbenchmarked on purpose, because it is bounded by the network round-trip, not handler code. `make bench` runs each once as a regression smoke, not a measurement. The measurement and profiling workflow (benchstat, pprof, live `/debug/pprof`) is documented in `CONTRIBUTING.md`.
- **Goroutine-leak detection:** the `cache`, `querylog`, and `dnsserver` packages (the three that own long-lived goroutines: cache cleanup sweep; DBLogger batch-writer and retention-prune; UDP/TCP listeners) run their suites under `go.uber.org/goleak` via a `TestMain` (`leak_test.go`). If any test leaves a goroutine running after it returns, the package fails. `blocklist` is deliberately excluded: its `httptest`-based tests can register transient keep-alive goroutines that would flake the check. goleak is a test-only dependency and is not linked into the shipped binary.
- **CI:** `.github/workflows/ci.yml` runs a `golangci-lint` (v2) job, then `go mod verify`, `go build`, `go vet`, `go test -race`, single-iteration benchmarks, a `govulncheck` job (fails on any known CVE reachable from our code; also available locally via `make vuln`), and a cross-compile matrix (linux/amd64, linux/arm64, linux/armv7, windows/amd64) on every push and PR. Branch protection on `master` requires all checks to pass and PR branches to be up to date before merging.
- **Manual smoke test:** `CONTRIBUTING.md` documents the full 7-step pre-release pass (probes → DNS behaviour → dashboard → whitelist round-trip → reload single-flight → stats/metrics cross-check → persistence + shutdown). The network-level variant: configure a single device's DNS to the running instance, browse an ad-heavy site, verify blocked domains resolve to `0.0.0.0` and ads do not render, and on Linux verify `kill -HUP $(pidof s-hole)` triggers a refresh.

---

## Open Questions

| # | Question | Owner | Status |
|---|----------|-------|--------|
| 1 | Should we support DNS-over-HTTPS upstream forwarding? Some ISPs intercept plain DNS on port 53. | n/a | **Resolved**: yes, planned (`docs/ROADMAP.md` #5) |
| 2 | Is there a use case for per-client whitelists (e.g., unblocking streaming services for one device)? | n/a | **Resolved**: settled as a non-goal (`docs/ROADMAP.md`) |
| 3 | Should the SQLite DB have a max-size or TTL-based retention policy to prevent unbounded growth? | n/a | **Resolved**: TTL-based prune via `query_db_retention_days` (CL 12, R16) |
| 4 | Should the binary register itself as a Windows Service via `golang.org/x/sys/windows/svc`? | n/a | **Resolved**: implemented in Phase 6 |
| 5 | Should the DNS cache use LRU eviction instead of drop-on-full? | n/a | **Resolved**: drop-on-full stays; settled as a non-goal (`docs/ROADMAP.md`; see Alternatives Considered) |
| 6 | Should the admin UI require authentication (e.g., a configurable API key)? | n/a | **Resolved**: no; LAN-trust is a documented scope decision, localhost-by-default `api_listen` is the mitigation (`docs/ROADMAP.md`, CL 12, R18) |
| 7 | Should we support DoH/DoT for blocklist downloads as well as upstream forwarding? Operator-controlled URLs over HTTPS already cover most threat models. | n/a | Open |
