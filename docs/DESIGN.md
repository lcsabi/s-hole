# s-hole: Network-Level DNS Sinkhole

**Authors:** Laszlo (@lcsabi)  
**Created:** 2026-06-23  
**Last Updated:** 2026-07-11  
**Status:** Implementation Complete

---

## Background

Advertising and tracking domains are a persistent source of unwanted traffic on home and small-office networks. Blocking them at the DNS layer — before a connection is even established — is more effective than browser-level filtering, which only protects devices with the extension installed and can be circumvented by per-app DNS-over-HTTPS.

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
- **Wildcard subdomain blocking.** Blocklists are exact-domain sets in the current implementation. Suffix-match blocking is planned as follow-up work (`docs/ROADMAP.md` #3).
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

Both UDP and TCP listeners are started on the same address:port (default `":53"` — a dual-stack wildcard, so IPv4 and IPv6 clients are served by the same listener; CL 23). DNS clients fall back to TCP automatically when a UDP response is truncated (TC bit set), so both must be active. The forwarder mirrors that fallback on the upstream side: it queries upstreams over UDP first and, when the reply comes back truncated, retries the same upstream over TCP before returning. Without that retry the client's own TCP fallback would dead-end — a TCP query to s-hole would still be forwarded over UDP and yield the same truncated answer. If the TCP retry itself fails, the truncated UDP reply is passed through (the upstream is demonstrably alive, and TC plus a partial answer beats SERVFAIL); truncated responses are never cached.

The `Handler` struct is the core routing point. For each query:

1. Extract the question's domain name and client IP.
2. Record the query in `stats.Counter` and `querylog` loggers.
3. If the domain is in `blocklist.Store`, write a sinkhole reply and return.
4. Check the DNS response cache. If a valid (non-expired) entry exists, decrement its TTLs and return it directly.
5. Forward to the first responsive upstream resolver. On success, store the response in the cache.

Upstream forwarding uses a 3-second per-upstream timeout. Upstreams are tried in order; the first successful response wins. Forwarding accepts a `context.Context` so the overall query has a hard deadline (default 10 s) and is cancelled if the calling DNS handler exits.

An in-process upstream health tracker remembers which upstream failed most recently. On the next query, upstreams that failed within the last 30 seconds are skipped on the first sweep — so a primary outage no longer adds 3 s of round-trip latency to every subsequent query. If every upstream is in cooldown, the tracker is bypassed and every upstream is retried (we never want a transient outage to turn into a hard failure).

Blocked replies preserve the EDNS0 OPT pseudo-record from the request when the client advertised one, so a client that advertises EDNS0 (and DNSSEC OK) does not fall back to legacy DNS for the sinkholed response.

### Blocklist Store (`internal/blocklist/`)

The store is an in-memory `map[string]struct{}` (hash set) keyed on normalised domain names (lowercase, no trailing dot). Incoming queries are normalised the same way before lookup — DNS names arrive with a trailing dot and arbitrary casing — so both sides of the comparison share one key space. Lookup is O(1).

Multiple blocklists are merged by construction rather than by an explicit dedup pass: `Update` concatenates the parsed lists and `Replace` inserts them all into the set, where entries appearing in several lists (or differing only in case/trailing dot) collapse to a single key. The `total` reported at startup is the deduplicated set size, which is why it is smaller than the sum of the per-list counts.

Blocklists are downloaded from configurable URLs on startup and periodically thereafter (default: every 24 hours). Both the hosts-file format (`0.0.0.0 ads.example.com`) and the plain-domain-per-line format are supported. Downloaded files are cached on disk so a restart does not require a network round-trip. If a download fails or the server returns a non-200 status, the stale cache is used (the error response body is never written to disk).

If every configured URL fails on a refresh (typically: total network outage), `blocklist.Update` preserves the existing block set rather than replacing it with an empty slice. This prevents a transient outage from silently unblocking every ad until the next successful refresh. The function returns a wrapped error reporting the last failure; the caller logs it but continues to run.

Downloads use a dedicated `http.Client` with a 60-second timeout. The response body is wrapped in `io.LimitReader` capped at 256 MB to bound disk and memory use if a server misbehaves.

A whitelist (exact domain names) is checked before the blocklist. A whitelisted domain is never blocked regardless of blocklist membership. The whitelist can be extended at runtime via the REST API; runtime additions take effect immediately but do not persist across restarts.

Blocklist replacement is atomic from the perspective of DNS handlers: `Store.Replace` swaps the internal map pointer under a write lock, so handlers either see the old list or the new list — never a partial update.

The on-disk cache file is also written atomically: `fetchList` streams to a sibling `.tmp` file and `os.Rename`s on success. A network drop or `kill -9` mid-download leaves only the `.tmp` and the prior cache file in place; the next start still sees a usable cache.

Cache files are deliberately per-URL, verbatim copies of what each server sent — never merged or deduplicated on disk. The stale-fallback contract is per-list (a failing URL falls back to *its own* last good snapshot, independent of the other lists), and an untransformed copy is inspectable evidence when a source misbehaves (see b/007). Deduplication happens for free in the in-memory set.

Entries in a parsed list that fail `ValidDomain` (empty, no dot, over 253 chars, or containing characters illegal in a DNS label) are silently dropped so one malformed blocklist line cannot pollute the store. The same validator gates user-supplied whitelist entries via `POST /api/whitelist`.

### DNS Response Cache (`internal/cache/`)

The cache is a size-bounded, TTL-respecting in-memory store for upstream DNS responses. Its purpose is to avoid redundant upstream round-trips for frequently queried domains, which is especially valuable on low-power hardware where upstream latency is comparatively high.

Key design decisions:

- **Key:** `<qname>\x00<qtype>\x00<qclass>` — full question identity. `Qclass` is included so cross-class queries (e.g. `ClassCHAOS` for `version.bind`) cannot collide with the dominant `ClassINET` traffic.
- **Value:** a cloned `dns.Msg` with the time it was cached and the minimum TTL across all answer records.
- **TTL adjustment:** on retrieval, elapsed seconds are subtracted from each record's TTL so clients receive accurate expiry times.
- **Eviction:** when the cache reaches `cache_size` entries, new entries are silently dropped rather than evicting existing ones. This avoids the complexity of LRU at the scale of home DNS traffic.
- **Only NOERROR responses with at least one answer are cached.** NXDOMAIN, SERVFAIL, empty-answer, and truncated (TC bit) responses are not stored — a truncated message carries an incomplete answer section that would otherwise be replayed for its full TTL.
- **Cleanup:** a background goroutine sweeps expired entries every minute. It exits cleanly on `Cache.Close()`, which is invoked from the shutdown path so the goroutine never outlives the process.
- **Cache hit rate** is tracked in `stats.Counter` and reported in both the periodic `Print()` output and `GET /api/stats`.

### Sinkhole Responses

Two modes are supported via `block_mode` in config:

| Mode | A query reply | AAAA query reply | Other types |
|------|--------------|-----------------|-------------|
| `zero` (default) | `0.0.0.0` | `::` | NOERROR, empty answer |
| `nxdomain` | NXDOMAIN | NXDOMAIN | NXDOMAIN |

`zero` is the default because `NXDOMAIN` causes some clients to aggressively retry, log errors, or display alarming UI. Returning a routable-but-unroutable address fails silently at the TCP connect layer, which is the behaviour most consistent with "nothing happened."

The TTL on sinkhole replies is configurable (`block_ttl`, default 300 seconds). A short TTL means a whitelisted domain becomes reachable within TTL seconds after being added to the whitelist, without requiring a client cache flush. An explicit `block_ttl: 0` is honored — it tells clients not to cache sinkhole replies at all, trading query volume for instant whitelist effect.

### Query Logging (`internal/querylog/`)

Query logging is split into two independent backends behind a `Multi` fan-out:

**FileLogger** writes one line per query to a flat file:
```
2026-06-23T10:04:05Z BLOCK 192.168.1.42 ads.example.com.
```
Suitable for `grep`, `tail -f`, and log rotation via external tools (e.g. `logrotate`).

**DBLogger** writes to a SQLite database (`modernc.org/sqlite`, pure Go, no CGO). It runs an internal goroutine that batches inserts: entries accumulate for up to `db_flush_interval` (default 30 seconds) or 100 entries, then are committed in a single transaction. This decouples DNS handler latency from disk I/O. If the channel buffer (capacity 1000) is full, entries are dropped rather than blocking a DNS goroutine — logging completeness is subordinate to DNS availability.

On shutdown, `DBLogger.Close()` blocks on a `sync.WaitGroup` until the writer goroutine has drained the channel and committed the final batch. Only then is the underlying `*sql.DB` closed. This guarantees the last batch of queries is never lost on a clean exit.

`Recent` and `TopBlocked` accept a `context.Context` and pass it through to `db.QueryContext`, so a client-disconnect on the admin server cancels the underlying SQL query rather than letting it run to completion.

A retention prune goroutine runs every hour when `query_db_retention_days > 0`, issuing `DELETE FROM queries WHERE ts < ?` against the configured cutoff. Default is 0 (retain forever).

The `querylog.Logger` interface (`Log(clientIP, domain string, blocked bool)`) is implemented by `FileLogger`, `DBLogger`, and `Multi`, with compile-time assertions in the package so a future signature drift is caught at build time rather than at the call site.

**SQLite pragmas applied on open:**
```sql
PRAGMA journal_mode=WAL;       -- write-ahead log: reads don't block writes
PRAGMA synchronous=NORMAL;     -- no fsync per commit; WAL checkpoint is still safe
PRAGMA cache_size=-8000;       -- 8 MB page cache
PRAGMA temp_store=MEMORY;      -- keep temp tables off disk
```
WAL mode combined with `synchronous=NORMAL` reduces write amplification by roughly 10× compared to SQLite's default rollback journal. This is the primary mitigation for SD card wear on Raspberry Pi deployments.

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

`Counter` maintains atomic counters for total queries and cache hits. The blocked count is deliberately *not* atomic: `RecordQuery` already takes the mutex to update the top-domain tally, so `blocked` is guarded by that same mutex — promoting it to an atomic would be redundant and misleading. Per-domain block counts and per-client query counts are tracked in the mutex-protected maps. Top-N extraction copies the map entries under the lock (resolving the map pointer *inside* the lock, since the prune reassigns it — R31) and sorts the copy outside it to minimise contention.

`Snapshot(topN int)` returns a `Summary` struct with json tags, making it directly serialisable by the REST API without coupling the stats package to any HTTP library. Fields include uptime, totals, block percentage, cache hit count and percentage, and top-N entry lists.

`Snapshot` loads `blocked` *before* `total`. This load order matters: `RecordQuery` increments `total` atomically *before* taking the mutex and incrementing `blocked`, so reading `total` first allows concurrent queries to inflate `blocked` past the snapshotted `total` and yield a block percentage greater than 100. Reading `blocked` first guarantees the invariant `blocked ≤ total` because every `blocked.Add(1)` is preceded by a `total.Add(1)`.

The per-domain and per-client tally maps are capped at 4 096 entries each. When the cap is exceeded, the bottom half by count is dropped — preserving the high-traffic entries that the top-N report cares about and keeping memory bounded against a long-running process that sees millions of unique keys.

### Admin Interface (`internal/api/`)

An HTTP server (default `127.0.0.1:8080` — localhost only) serves two things:

1. **REST API** — JSON endpoints backed by `stats.Snapshot`, `querylog.DBLogger.Recent`, and `blocklist.Store` methods.
2. **Web UI** — a single-page dashboard embedded in the binary via `//go:embed`. It polls `/api/stats` and `/api/queries` every 3 seconds and renders stat cards, top domain/client tables, a recent query log, and an actions panel (blocklist reload, whitelist add).

The web UI has no external dependencies (no CDN, no framework). It is pure HTML/CSS/JS and works without an internet connection.

The HTTP server is held as an `*http.Server` so it can be gracefully shut down. `doStop` in `cmd/s-hole/main.go` calls `apiServer.Shutdown(ctx)` with a 5-second context before terminating the process, which drains in-flight admin requests. `http.ErrServerClosed` is suppressed inside `ListenAndServe` so a clean shutdown does not log a spurious error.

Explicit timeouts are configured on the server (`ReadHeaderTimeout=5s`, `ReadTimeout=15s`, `WriteTimeout=30s`, `IdleTimeout=60s`) to defend the unauthenticated LAN-facing endpoint from slowloris-style attacks. POST handlers that accept JSON bodies wrap `r.Body` in `http.MaxBytesReader` (64 KiB) so an attacker cannot exhaust memory by streaming an unbounded payload.

Blocklist refresh is single-flighted via a `sync.Mutex` held in `cmd/s-hole/main.go` and shared between the periodic refresh timer and the API. The reload closure tries to acquire the lock and returns `true` synchronously if it took it (work proceeds asynchronously in a goroutine) or `false` if a refresh is already running. `POST /api/reload` surfaces the boolean as `"reload triggered"` vs `"reload already in progress"`. Centralising the lock in the closure rather than in `api.Server` ensures the periodic timer cannot bypass the gate.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Live stats snapshot (uptime, totals, cache rate, top domains/clients) |
| `/api/queries` | GET | Recent queries from SQLite (`?limit=N`, default 50, capped at 1000) |
| `/api/whitelist` | GET | List runtime-whitelisted domains |
| `/api/whitelist` | POST | Add domain: `{"domain":"..."}`. 64 KiB body cap; rejects malformed domains via `blocklist.ValidDomain`. |
| `/api/whitelist` | DELETE | Remove domain: `?domain=...` |
| `/api/reload` | POST | Trigger immediate blocklist refresh (de-duplicated via single-flight mutex) |
| `/healthz` | GET | Liveness probe — returns 200 OK while the HTTP server is responsive |
| `/readyz` | GET | Readiness probe — 200 OK once the blocklist has loaded at least one entry; 503 otherwise. Used by container orchestrators to route traffic away while the initial download is in flight. |
| `/metrics` | GET | Prometheus text exposition: `shole_queries_total`, `shole_blocked_total`, `shole_cache_hits_total`, `shole_cache_misses_total`, `shole_cache_size`, `shole_blocklist_size`, `shole_whitelist_size`, `shole_query_log_dropped_total` |
| `/debug/pprof/*` | GET | Standard Go pprof handlers. **Only registered when `enable_pprof: true`** (or `S_HOLE_ENABLE_PPROF=1`). Off by default; intended for incident response on a localhost-bound admin server. |

### Observability and Logging

Logging is structured via `log/slog`. Each package binds a child logger with a `pkg=<name>` attribute so a grep on the log stream cleanly separates DNS, blocklist, querylog, and api messages. The default handler is text on stdout (`time=… level=… msg=… key=value`); `S_HOLE_LOG_FORMAT=json` switches to JSON, which is what most container/log-aggregation pipelines expect.

Operational diagnostics ship over two surfaces:

- **`/healthz`** — a tiny endpoint that returns 200 as long as the HTTP server is responsive. Liveness only — it deliberately makes no downstream call so a flaky upstream cannot cause the container orchestrator to restart the process.
- **`/readyz`** — a readiness probe that returns 200 once `store.Len() > 0` (the blocklist has loaded at least one entry) and 503 otherwise. Pairs with `/healthz` to give a Kubernetes-style probe split: don't restart, but do route traffic away while the initial blocklist download is in flight.
- **`/metrics`** — Prometheus text exposition (format `0.0.4`) for the in-process counters: query totals, block counts, cache hits/misses, cache size, blocklist size, whitelist size, and `shole_query_log_dropped_total` (entries dropped because the writer channel was full — a sustained non-zero rate means `db_flush_interval` is too long for the query volume). We hand-roll the exposition rather than pulling in `prometheus/client_golang` to keep the dependency graph small.
- **`/debug/pprof/*`** — the six standard `net/http/pprof` handlers (index, cmdline, profile, symbol, trace, plus the typed profiles under the index). Registered only when `enable_pprof: true` is set in config (or `S_HOLE_ENABLE_PPROF=1`). Off by default; required for live CPU/heap profiling during incident response. A WARN log fires at startup when enabled, recommending a localhost-bound `api_listen`.

Periodic `runTicker` goroutines (stats print, blocklist refresh) are wrapped in `recover()`. A panic inside the ticker function is logged with its goroutine stack and the next tick still fires — a transient parser failure no longer silently freezes the refresh loop. `runTicker` also honors an application-wide `context.Context` that `doStop` cancels first, so the tickers unwind cleanly rather than depending on `os.Exit` to reclaim them.

### Startup Network Hint

On startup, `cmd/s-hole/main.go` calls `printNetworkHint`, which enumerates local interface addresses via `net.InterfaceAddrs()`, filters out loopback and link-local addresses, and prints a bordered box listing the DNS server address for each LAN-facing IPv4 address. The Admin UI line honors where the API is actually bound (T4): with the localhost-only default it prints a single `http://127.0.0.1:<port> (this machine only)` line rather than advertising LAN URLs that would refuse connections. This removes the need for the operator to manually discover the machine's IP when configuring the router's DHCP DNS field. `deploy/install-linux.sh` prints the same banner at the end of installation using `hostname -I`, with the same `api_listen`-aware Admin UI logic.

### Configuration (`internal/config/`)

All configuration lives in a single YAML file. The struct uses `yaml` tags and applies safe defaults in `applyDefaults()` so the minimal valid config is an empty file. Duration fields are stored as strings and parsed at startup; invalid durations are fatal errors rather than silently ignored.

Two fields — `cache_size` and `block_ttl` — have defaults seeded onto the struct *before* the YAML decode instead of in `applyDefaults()`. Their zero values are meaningful settings (`cache_size: 0` disables the cache; `block_ttl: 0` disables client caching of sinkhole replies), and a post-decode fixup cannot tell an explicit 0 in the file apart from an absent key.

A `Validate()` method runs after `Load()` and rejects unrecognised values for the enumerated fields (`block_mode`, `log_queries`). A typo such as `block_mode: "NXDOMAIN"` is now a fatal startup error instead of a silent fallback to the default — operator misconfiguration is surfaced immediately at the source.

`applyEnvOverrides()` runs after `applyDefaults()` and lets a container deployment override any commonly-tuned field via an `S_HOLE_*` environment variable without rebuilding a bind-mounted YAML file. The full list is in `../README.md`. Malformed numeric values are silently ignored so a typo in an env var never blocks startup.

### Packaging and Deployment (`internal/service/`, `deploy/`, `Dockerfile`)

Three deployment targets are supported:

**Windows Service** — `internal/service/svc_windows.go` (build tag `windows`) integrates with the Windows Service Control Manager via `golang.org/x/sys/windows/svc`. The binary accepts `-service install|uninstall|start|stop` flags. When launched by the SCM, `svc.IsWindowsService()` is detected and the process enters the SCM event loop; a stop control from the SCM calls the same `doStop` function as a Ctrl+C in interactive mode. `internal/service/svc_other.go` (build tag `!windows`) provides no-op stubs with the same function signatures so `cmd/s-hole/main.go` requires no platform conditionals of its own.

**Linux systemd** — `deploy/s-hole.service` runs as a dedicated `s-hole` system user. `AmbientCapabilities=CAP_NET_BIND_SERVICE` allows binding port 53 without root. `ProtectSystem=strict` and `NoNewPrivileges` limit the blast radius of any exploit. `deploy/install-linux.sh` automates the full installation; the systemd unit is embedded as a heredoc inside the script, so only the script itself (plus the binary and config) needs to be copied to the target machine.

**Docker** — a multi-stage `Dockerfile` builds a statically linked binary (`CGO_ENABLED=0`) in a `golang:alpine` stage and copies it into an `alpine` runtime image for SSL certificate access (needed for HTTPS blocklist downloads). The `/app` directory is declared a `VOLUME` for config and database persistence.

**Cross-compilation** — a `Makefile` provides `make pi` (arm64), `make pi32` (armv7), and `make linux` (amd64) targets. All produce stripped binaries (~10–17 MB) with no host toolchain requirements beyond the Go compiler. The Makefile also exposes the standard development targets (`make check`, `test`, `test-race`, `bench`, `lint`, `fmt`, `vet`, `install`, `version`) — `make help` lists the full set.

**Build identity** — `internal/version` holds three vars (`Version`, `Commit`, `BuildDate`) written at link time via `-X` ldflags. The Makefile populates them from `git describe`, `git rev-parse`, and the current UTC timestamp; the Dockerfile accepts them as `--build-arg`; CI fills them from the GitHub Actions context. Source builds without those flags fall back to placeholder values (`dev` / `unknown` / `unknown`), which is acceptable for `go install` use. `s-hole -version` prints the full identity at any time.

---

## Alternatives Considered

### Use Pi-Hole directly

Pi-Hole solves this problem well for Raspberry Pi / Debian deployments. We ruled it out because: it requires a full Linux install, cannot be deployed as a single binary on Windows or macOS, and the codebase (a PHP web UI + a C DNS daemon fork) is not easily auditable or modified.

### Use CoreDNS with a blocklist plugin

CoreDNS is production-grade and has a plugin ecosystem. The `ads` plugin does DNS sinkholing. We ruled this out because the goal is also to learn by building: using CoreDNS would replace the implementation with configuration. CoreDNS also pulls in a large dependency tree.

### Use `NXDOMAIN` as the default sinkhole response

`NXDOMAIN` is semantically correct ("this domain does not exist") and is what Pi-Hole uses in some modes. We chose `0.0.0.0` as the default because some client applications (notably Windows Update, certain game launchers) interpret `NXDOMAIN` as a network error and surface it to the user, while a connection to `0.0.0.0` fails silently at the socket layer. Both modes are available via `block_mode`.

### In-process blocklist update via a signal

Linux is the primary deployment target — the Raspberry Pi optimisations, the hardened systemd unit, and the Docker image are all built around it; Windows is supported (`-service install` and SCM integration) but is not the design's centre of gravity. Accordingly, `SIGHUP` is wired up as the conventional "reload config" gesture on every non-Windows build: `kill -HUP $(pidof s-hole)` triggers the same single-flight refresh as `POST /api/reload`. Operators get the muscle-memory behaviour even when the admin API is disabled or firewalled.

The implementation lives in two tiny build-tagged files (`cmd/s-hole/signals_unix.go` and `cmd/s-hole/signals_windows.go`) so `cmd/s-hole/main.go` itself contains no platform-specific code. On Windows, `reloadSignals()` returns nil and the only signals notified are SIGINT/SIGTERM — the SCM is the canonical lifecycle control there, and POST /api/reload remains available for on-demand refresh.

### LRU eviction for the DNS cache

LRU eviction would make better use of cache capacity by removing the least-recently-used entries when full. We chose simple drop-on-full because: (a) home DNS traffic is dominated by a small hot set of domains that will be re-cached quickly, (b) the cache is sized generously (default 2000 entries) relative to typical household domain diversity, and (c) LRU adds locking complexity. This can be revisited if cache thrashing is observed in practice.

### `kardianos/service` for cross-platform service management

`kardianos/service` provides a unified API for Windows, systemd, and launchd service registration. We chose to implement only Windows SCM integration (using `golang.org/x/sys/windows/svc`) and provide a static systemd unit file for Linux, because: the library adds a dependency, the systemd unit gives more control over hardening flags, and launchd (macOS) is not a target deployment platform.

---

## Security Considerations

- **DNS amplification:** s-hole listens on a LAN-facing address. It should not be exposed on a public IP. No rate-limiting or source validation is implemented; this is accepted scope for a LAN deployment.
- **Blocklist URLs:** URLs come from operator-controlled config, not from user input. The downloader follows HTTP redirects without restriction; operators should use HTTPS URLs from trusted sources.
- **SQLite file permissions:** The query log database is created with mode `0644`. On a shared machine, other local users can read query history. Operators requiring confidentiality should use filesystem-level access controls.
- **Port 53 binding:** Binding to port 53 requires elevated privileges (root / Administrator) or `CAP_NET_BIND_SERVICE`. The systemd unit grants the capability without running as root. On Windows, the binary runs as the LocalSystem account when installed as a service. Port 53 is non-negotiable for deployment: DHCP options, `resolv.conf`, and OS network settings identify DNS servers by IP address only — there is no port field anywhere in that chain — so every client on the LAN sends to `<ip>:53` unconditionally. High ports (e.g. 5353 in the CONTRIBUTING smoke test) are strictly a development convenience for queries addressed to the server explicitly.
- **Admin UI:** The HTTP server has no authentication. As of CL 12 the default `api_listen` is `127.0.0.1:8080` — operators who want LAN access must opt in by setting `0.0.0.0:8080` (or a specific LAN interface). The HTTP server enforces conservative timeouts (`ReadHeaderTimeout=5s`, `ReadTimeout=15s`, `WriteTimeout=30s`, `IdleTimeout=60s`) and a 64 KiB body cap on POST endpoints to defend against slowloris and memory-exhaustion attacks from LAN peers.
- **`/healthz`, `/readyz`, and `/metrics`** are unauthenticated alongside the rest of the API. They are intended for local Prometheus / probe access; do not expose to the public internet.
- **`/debug/pprof/*`** when enabled (`enable_pprof: true`) reveals goroutine stacks, heap layouts, and binary symbols — useful for incident response, dangerous if exposed to the LAN. The startup log fires a WARN when it is on; operators should pair it with `api_listen: "127.0.0.1:8080"`.

## Privacy Considerations

The query log records client IP addresses and all queried domain names. On a home network this constitutes a detailed browsing history for all devices. The SQLite file and flat log file should be treated as sensitive data. Operators should consider setting `log_queries: blocked` or `log_queries: none` if a full query log is not needed.

---

## Testing Strategy

- **Unit tests:** Every implementation package under `internal/` ships a `*_test.go` file. Line coverage by package: `stats`, `config`, and `version` 100 %; `cache` 94.8 %; `api` 90.8 %; `blocklist` 89.6 %; `dnsserver` 88.1 %; `querylog` 85.6 %. The `cmd/s-hole` package is at 31.7 % — the rest is the `main()` bootstrap and signal-dispatch goroutine, which require running the binary. Module-wide coverage is 76.8 % (measured with `go test -coverpkg=./... ./...` on Linux). Coverage includes `blocklist.Store` lookup, whitelist precedence, atomic `Replace`, `parseHostsFormat` against both formats, `Update` preserving the store on full-failure refresh, `ValidDomain` rejecting garbage, atomic cache file write; `cache.Cache` TTL decrement, drop-on-full, Qclass-aware keying, `cleanupExpired` sweep, `Close` shutdown; `config.Load` with empty/partial/invalid YAML, `Validate` rejecting bogus enums, every duration-parser error path, every `S_HOLE_*` env override; `stats.Counter` concurrent invariants (block rate never exceeds 100 % under parallel writers), top-N map cap, `Print` output; `querylog.FileLogger` filtering modes + fallback paths, `DBLogger` round-trip, final-flush-on-Close, retention prune; `dnsserver.Handler` sinkhole (zero + nxdomain), cache-hit, cache-miss-forward, whitelist override, empty-question, EDNS0 pass-through, write-error branches; `dnsserver.Server` full Start→query→Shutdown lifecycle on a real UDP port; the upstream health tracker (cooldown, failover, second-sweep retry); the `api` HTTP handlers including reload single-flight, the 64 KiB body cap, `ListenAndServe`/`Shutdown` lifecycle, `/healthz`, `/metrics`, malformed-input rejection, encoder-error branch. Many tests are regression tests for specific bug numbers (b/005, b/007, b/010, b/017, b/018, b/021, b/022, b/024, b/026, b/028) or staff-review IDs (R3, R4, R5, R6, R8, R9, R12, R13, R14, R15, R16, R17, R18, R19, R26, R27, R31, R32, R33, R34, R35, R36, R37, R38, T1–T6).
- **DNS handler unit tests** use a `fakeWriter` implementing `dns.ResponseWriter`; the cache-hit path is exercised by pre-populating the in-memory cache, bypassing the upstream resolver entirely. The forwarder tests use a real in-process miekg/dns server on `127.0.0.1:0` so the production code path (including `dns.Client.ExchangeContext`) is exercised end-to-end.
- **Server lifecycle test** binds the production `dnsserver.Server` to a free port (UDP + TCP), confirms a real `dns.Client.Exchange` round-trips through the handler, and verifies `Shutdown` causes `Start` to return — the only test that touches the bind+listen path.
- **Fuzz tests:** `internal/blocklist/fuzz_test.go` fuzzes `ValidDomain`, `parseHostsFormat`, and `cacheFilename`. The parser fuzz asserts every emitted domain itself passes `ValidDomain`; the filename fuzz asserts the result is platform-safe (no `/`, `\`, or `:`). Run with `go test -fuzz=FuzzValidDomain -fuzztime=30s ./internal/blocklist/`.
- **Integration test:** `internal/dnsserver/integration_test.go` wires the full stack — `blocklist.Store` + `cache.Cache` + `querylog.DBLogger` on a real SQLite file + `dnsserver.Handler` + `dnsserver.Server` on a free UDP port + a mock upstream — and exercises three real DNS queries (blocked, forwarded-and-cached, cache-hit). Catches wiring bugs (constructor arg order, nil dependencies, fan-out misconfig) that unit tests miss.
- **Benchmark:** `BenchmarkStore_IsBlocked` against a 100 000-entry store guards the hot DNS path against accidental O(n) regressions.
- **CI:** `.github/workflows/ci.yml` runs a `golangci-lint` (v2) job, then `go mod verify`, `go build`, `go vet`, `go test -race`, single-iteration benchmarks, and a cross-compile matrix (linux/amd64, linux/arm64, linux/armv7, windows/amd64) on every push and PR. Branch protection on `master` requires all checks to pass and PR branches to be up to date before merging.
- **Manual smoke test:** `CONTRIBUTING.md` documents the full 7-step pre-release pass (probes → DNS behaviour → dashboard → whitelist round-trip → reload single-flight → stats/metrics cross-check → persistence + shutdown). The network-level variant: configure a single device's DNS to the running instance, browse an ad-heavy site, verify blocked domains resolve to `0.0.0.0` and ads do not render, and on Linux verify `kill -HUP $(pidof s-hole)` triggers a refresh.

---

## Open Questions

| # | Question | Owner | Status |
|---|----------|-------|--------|
| 1 | Should we support DNS-over-HTTPS upstream forwarding? Some ISPs intercept plain DNS on port 53. | — | **Resolved** — yes, planned (`docs/ROADMAP.md` #5) |
| 2 | Is there a use case for per-client whitelists (e.g., unblocking streaming services for one device)? | — | **Resolved** — settled as a non-goal (`docs/ROADMAP.md`) |
| 3 | Should the SQLite DB have a max-size or TTL-based retention policy to prevent unbounded growth? | — | **Resolved** — TTL-based prune via `query_db_retention_days` (CL 12, R16) |
| 4 | Should the binary register itself as a Windows Service via `golang.org/x/sys/windows/svc`? | — | **Resolved** — implemented in Phase 6 |
| 5 | Should the DNS cache use LRU eviction instead of drop-on-full? | — | **Resolved** — drop-on-full stays; settled as a non-goal (`docs/ROADMAP.md`; see Alternatives Considered) |
| 6 | Should the admin UI require authentication (e.g., a configurable API key)? | — | **Resolved** — no; LAN-trust is a documented scope decision, localhost-by-default `api_listen` is the mitigation (`docs/ROADMAP.md`, CL 12, R18) |
| 7 | Should we support DoH/DoT for blocklist downloads as well as upstream forwarding? Operator-controlled URLs over HTTPS already cover most threat models. | — | Open |
