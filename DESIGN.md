# s-hole: Network-Level DNS Sinkhole

**Authors:** Laszlo  
**Created:** 2026-06-23  
**Last Updated:** 2026-06-24  
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

- **DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) termination.** Upstream forwarding uses plain DNS. DoH support is a separate, opt-in feature with distinct certificate management concerns.
- **Running on the router.** We assume the router is a commodity device that does not support arbitrary software. Network-wide coverage is achieved by pointing the router's DHCP DNS field at the host running s-hole.
- **Wildcard subdomain blocking.** Blocklists are exact-domain sets. Wildcard support requires a different data structure and is left for a follow-up.
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
┌───────────────────────────────────────────────────────────────┐
│                        s-hole process                          │
│                                                               │
│  ┌──────────┐  blocked?   ┌─────────────────────────────────┐ │
│  │ Handler  │────────────▶│ Sinkhole reply                  │ │
│  │          │             │ (0.0.0.0 / :: or NXDOMAIN)      │ │
│  │          │  cache hit? └─────────────────────────────────┘ │
│  │          │────────────▶ DNS Response Cache (in-memory)      │
│  │          │  cache miss → upstream forward                   │
│  └────┬─────┘                                                 │
│       │ every query                                           │
│  ┌────▼──────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Blocklist │  │    Stats     │  │    Query Logger       │  │
│  │   Store   │  │   Counter    │  │  (file + SQLite WAL)  │  │
│  └───────────┘  └──────────────┘  └──────────────────────┘  │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐    │
│  │              Admin HTTP Server (:8080)                │    │
│  │          REST API  +  embedded web UI                 │    │
│  └──────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────┘
        │ cache miss
        ▼
  Upstream DNS (1.1.1.1:53, 8.8.8.8:53, …)
```

### DNS Server (`internal/dns/`)

We use `github.com/miekg/dns` rather than the standard library's `net` package because it provides a complete RFC-compliant DNS message codec, a `ServeMux`-style handler interface, and handles both UDP and TCP transports. Rolling our own DNS codec would be a source of subtle correctness bugs.

Both UDP and TCP listeners are started on the same address:port. DNS clients fall back to TCP automatically when a UDP response is truncated (TC bit set), so both must be active.

The `Handler` struct is the core routing point. For each query:

1. Extract the question's domain name and client IP.
2. Record the query in `stats.Counter` and `querylog` loggers.
3. If the domain is in `blocklist.Store`, write a sinkhole reply and return.
4. Check the DNS response cache. If a valid (non-expired) entry exists, decrement its TTLs and return it directly.
5. Forward to the first responsive upstream resolver. On success, store the response in the cache.

Upstream forwarding uses a 3-second per-upstream timeout. Upstreams are tried in order; the first successful response wins.

### Blocklist Store (`internal/blocklist/`)

The store is an in-memory `map[string]struct{}` (hash set) keyed on normalised domain names (lowercase, no trailing dot). Lookup is O(1).

Blocklists are downloaded from configurable URLs on startup and periodically thereafter (default: every 24 hours). Both the hosts-file format (`0.0.0.0 ads.example.com`) and the plain-domain-per-line format are supported. Downloaded files are cached on disk so a restart does not require a network round-trip. If a download fails or the server returns a non-200 status, the stale cache is used (the error response body is never written to disk).

If every configured URL fails on a refresh (typically: total network outage), `blocklist.Update` preserves the existing block set rather than replacing it with an empty slice. This prevents a transient outage from silently unblocking every ad until the next successful refresh. The function returns a wrapped error reporting the last failure; the caller logs it but continues to run.

Downloads use a dedicated `http.Client` with a 60-second timeout. The response body is wrapped in `io.LimitReader` capped at 256 MB to bound disk and memory use if a server misbehaves.

A whitelist (exact domain names) is checked before the blocklist. A whitelisted domain is never blocked regardless of blocklist membership. The whitelist can be extended at runtime via the REST API; runtime additions take effect immediately but do not persist across restarts.

Blocklist replacement is atomic from the perspective of DNS handlers: `Store.Replace` swaps the internal map pointer under a write lock, so handlers either see the old list or the new list — never a partial update.

### DNS Response Cache (`internal/cache/`)

The cache is a size-bounded, TTL-respecting in-memory store for upstream DNS responses. Its purpose is to avoid redundant upstream round-trips for frequently queried domains, which is especially valuable on low-power hardware where upstream latency is comparatively high.

Key design decisions:

- **Key:** `<qname>\x00<qtype>\x00<qclass>` — full question identity. `Qclass` is included so cross-class queries (e.g. `ClassCHAOS` for `version.bind`) cannot collide with the dominant `ClassINET` traffic.
- **Value:** a cloned `dns.Msg` with the time it was cached and the minimum TTL across all answer records.
- **TTL adjustment:** on retrieval, elapsed seconds are subtracted from each record's TTL so clients receive accurate expiry times.
- **Eviction:** when the cache reaches `cache_size` entries, new entries are silently dropped rather than evicting existing ones. This avoids the complexity of LRU at the scale of home DNS traffic.
- **Only NOERROR responses with at least one answer are cached.** NXDOMAIN, SERVFAIL, and empty-answer responses are not stored.
- **Cleanup:** a background goroutine sweeps expired entries every minute. It exits cleanly on `Cache.Close()`, which is invoked from the shutdown path so the goroutine never outlives the process.
- **Cache hit rate** is tracked in `stats.Counter` and reported in both the periodic `Print()` output and `GET /api/stats`.

### Sinkhole Responses

Two modes are supported via `block_mode` in config:

| Mode | A query reply | AAAA query reply | Other types |
|------|--------------|-----------------|-------------|
| `zero` (default) | `0.0.0.0` | `::` | NOERROR, empty answer |
| `nxdomain` | NXDOMAIN | NXDOMAIN | NXDOMAIN |

`zero` is the default because `NXDOMAIN` causes some clients to aggressively retry, log errors, or display alarming UI. Returning a routable-but-unroutable address fails silently at the TCP connect layer, which is the behaviour most consistent with "nothing happened."

The TTL on sinkhole replies is configurable (`block_ttl`, default 300 seconds). A short TTL means a whitelisted domain becomes reachable within TTL seconds after being added to the whitelist, without requiring a client cache flush.

### Query Logging (`internal/querylog/`)

Query logging is split into two independent backends behind a `Multi` fan-out:

**FileLogger** writes one line per query to a flat file:
```
2026-06-23T10:04:05Z BLOCK 192.168.1.42 ads.example.com.
```
Suitable for `grep`, `tail -f`, and log rotation via external tools (e.g. `logrotate`).

**DBLogger** writes to a SQLite database (`modernc.org/sqlite`, pure Go, no CGO). It runs an internal goroutine that batches inserts: entries accumulate for up to `db_flush_interval` (default 30 seconds) or 100 entries, then are committed in a single transaction. This decouples DNS handler latency from disk I/O. If the channel buffer (capacity 1000) is full, entries are dropped rather than blocking a DNS goroutine — logging completeness is subordinate to DNS availability.

On shutdown, `DBLogger.Close()` blocks on a `sync.WaitGroup` until the writer goroutine has drained the channel and committed the final batch. Only then is the underlying `*sql.DB` closed. This guarantees the last batch of queries is never lost on a clean exit.

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

`Counter` maintains atomic int64 counters for total queries, blocked queries, and cache hits. Per-domain block counts and per-client query counts are tracked in mutex-protected maps. Top-N extraction sorts a snapshot of those maps; the sort runs on a copy taken outside the lock to minimise contention.

`Snapshot(topN int)` returns a `Summary` struct with json tags, making it directly serialisable by the REST API without coupling the stats package to any HTTP library. Fields include uptime, totals, block percentage, cache hit count and percentage, and top-N entry lists.

`Snapshot` loads `blocked` *before* `total`. This load order matters: `RecordQuery` increments `total` atomically *before* taking the mutex and incrementing `blocked`, so reading `total` first allows concurrent queries to inflate `blocked` past the snapshotted `total` and yield a block percentage greater than 100. Reading `blocked` first guarantees the invariant `blocked ≤ total` because every `blocked.Add(1)` is preceded by a `total.Add(1)`.

### Admin Interface (`internal/api/`)

An HTTP server (default `:8080`) serves two things:

1. **REST API** — JSON endpoints backed by `stats.Snapshot`, `querylog.DBLogger.Recent`, and `blocklist.Store` methods.
2. **Web UI** — a single-page dashboard embedded in the binary via `//go:embed`. It polls `/api/stats` and `/api/queries` every 5 seconds and renders stat cards, top domain/client tables, a recent query log, and an actions panel (blocklist reload, whitelist add).

The web UI has no external dependencies (no CDN, no framework). It is pure HTML/CSS/JS and works without an internet connection.

The HTTP server is held as an `*http.Server` so it can be gracefully shut down. `doStop` in `main.go` calls `apiServer.Shutdown(ctx)` with a 5-second context before terminating the process, which drains in-flight admin requests. `http.ErrServerClosed` is suppressed inside `ListenAndServe` so a clean shutdown does not log a spurious error.

Explicit timeouts are configured on the server (`ReadHeaderTimeout=5s`, `ReadTimeout=15s`, `WriteTimeout=30s`, `IdleTimeout=60s`) to defend the unauthenticated LAN-facing endpoint from slowloris-style attacks. POST handlers that accept JSON bodies wrap `r.Body` in `http.MaxBytesReader` (64 KiB) so an attacker cannot exhaust memory by streaming an unbounded payload.

Blocklist refresh is single-flighted via a `sync.Mutex` held in `main.go` and shared between the periodic refresh timer and the API. The reload closure tries to acquire the lock and returns `true` synchronously if it took it (work proceeds asynchronously in a goroutine) or `false` if a refresh is already running. `POST /api/reload` surfaces the boolean as `"reload triggered"` vs `"reload already in progress"`. Centralising the lock in the closure rather than in `api.Server` ensures the periodic timer cannot bypass the gate.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Live stats snapshot (uptime, totals, cache rate, top domains/clients) |
| `/api/queries` | GET | Recent queries from SQLite (`?limit=N`, default 50) |
| `/api/whitelist` | GET | List runtime-whitelisted domains |
| `/api/whitelist` | POST | Add domain: `{"domain":"..."}` |
| `/api/whitelist` | DELETE | Remove domain: `?domain=...` |
| `/api/reload` | POST | Trigger immediate blocklist refresh (de-duplicated via single-flight mutex) |

### Startup Network Hint

On startup, `main.go` calls `printNetworkHint`, which enumerates local interface addresses via `net.InterfaceAddrs()`, filters out loopback and link-local addresses, and prints a bordered box listing the DNS server address and Admin UI URL for each LAN-facing IPv4 address. This removes the need for the operator to manually discover the machine's IP when configuring the router's DHCP DNS field. The same information is printed by `deploy/install-linux.sh` at the end of installation using `hostname -I`.

### Configuration (`internal/config/`)

All configuration lives in a single YAML file. The struct uses `yaml` tags and applies safe defaults in `applyDefaults()` so the minimal valid config is an empty file. Duration fields are stored as strings and parsed at startup; invalid durations are fatal errors rather than silently ignored.

A `Validate()` method runs after `Load()` and rejects unrecognised values for the enumerated fields (`block_mode`, `log_queries`). A typo such as `block_mode: "NXDOMAIN"` is now a fatal startup error instead of a silent fallback to the default — operator misconfiguration is surfaced immediately at the source.

### Packaging and Deployment (`internal/service/`, `deploy/`, `Dockerfile`)

Three deployment targets are supported:

**Windows Service** — `internal/service/svc_windows.go` (build tag `windows`) integrates with the Windows Service Control Manager via `golang.org/x/sys/windows/svc`. The binary accepts `-service install|uninstall|start|stop` flags. When launched by the SCM, `svc.IsWindowsService()` is detected and the process enters the SCM event loop; a stop control from the SCM calls the same `doStop` function as a Ctrl+C in interactive mode. `internal/service/svc_other.go` (build tag `!windows`) provides no-op stubs with the same function signatures so `main.go` requires no build tags.

**Linux systemd** — `deploy/s-hole.service` runs as a dedicated `s-hole` system user. `AmbientCapabilities=CAP_NET_BIND_SERVICE` allows binding port 53 without root. `ProtectSystem=strict` and `NoNewPrivileges` limit the blast radius of any exploit. `deploy/install-linux.sh` automates the full installation; the systemd unit is embedded as a heredoc inside the script, so only the script itself (plus the binary and config) needs to be copied to the target machine.

**Docker** — a multi-stage `Dockerfile` builds a statically linked binary (`CGO_ENABLED=0`) in a `golang:alpine` stage and copies it into an `alpine` runtime image for SSL certificate access (needed for HTTPS blocklist downloads). The `/app` directory is declared a `VOLUME` for config and database persistence.

**Cross-compilation** — a `Makefile` provides `make pi` (arm64), `make pi32` (armv7), and `make linux` (amd64) targets. All produce stripped binaries (~10–17 MB) with no host toolchain requirements beyond the Go compiler.

---

## Alternatives Considered

### Use Pi-Hole directly

Pi-Hole solves this problem well for Raspberry Pi / Debian deployments. We ruled it out because: it requires a full Linux install, cannot be deployed as a single binary on Windows or macOS, and the codebase (a PHP web UI + a C DNS daemon fork) is not easily auditable or modified.

### Use CoreDNS with a blocklist plugin

CoreDNS is production-grade and has a plugin ecosystem. The `ads` plugin does DNS sinkholing. We ruled this out because the goal is also to learn by building: using CoreDNS would replace the implementation with configuration. CoreDNS also pulls in a large dependency tree.

### Use `NXDOMAIN` as the default sinkhole response

`NXDOMAIN` is semantically correct ("this domain does not exist") and is what Pi-Hole uses in some modes. We chose `0.0.0.0` as the default because some client applications (notably Windows Update, certain game launchers) interpret `NXDOMAIN` as a network error and surface it to the user, while a connection to `0.0.0.0` fails silently at the socket layer. Both modes are available via `block_mode`.

### In-process blocklist update via a signal

On Unix, `SIGHUP` is the convention for "reload config." We initially included a `SIGHUP` handler but removed it because the code targets Windows as a first-class platform and `SIGHUP` is not available there. Blocklist refresh on a configurable timer covers the primary use case; the REST API `POST /api/reload` covers on-demand refreshes.

### LRU eviction for the DNS cache

LRU eviction would make better use of cache capacity by removing the least-recently-used entries when full. We chose simple drop-on-full because: (a) home DNS traffic is dominated by a small hot set of domains that will be re-cached quickly, (b) the cache is sized generously (default 2000 entries) relative to typical household domain diversity, and (c) LRU adds locking complexity. This can be revisited if cache thrashing is observed in practice.

### `kardianos/service` for cross-platform service management

`kardianos/service` provides a unified API for Windows, systemd, and launchd service registration. We chose to implement only Windows SCM integration (using `golang.org/x/sys/windows/svc`) and provide a static systemd unit file for Linux, because: the library adds a dependency, the systemd unit gives more control over hardening flags, and launchd (macOS) is not a target deployment platform.

---

## Security Considerations

- **DNS amplification:** s-hole listens on a LAN-facing address. It should not be exposed on a public IP. No rate-limiting or source validation is implemented; this is accepted scope for a LAN deployment.
- **Blocklist URLs:** URLs come from operator-controlled config, not from user input. The downloader follows HTTP redirects without restriction; operators should use HTTPS URLs from trusted sources.
- **SQLite file permissions:** The query log database is created with mode `0644`. On a shared machine, other local users can read query history. Operators requiring confidentiality should use filesystem-level access controls.
- **Port 53 binding:** Binding to port 53 requires elevated privileges (root / Administrator) or `CAP_NET_BIND_SERVICE`. The systemd unit grants the capability without running as root. On Windows, the binary runs as the LocalSystem account when installed as a service.
- **Admin UI:** The HTTP server has no authentication. It should be firewalled or restricted to `127.0.0.1` on multi-user machines.

## Privacy Considerations

The query log records client IP addresses and all queried domain names. On a home network this constitutes a detailed browsing history for all devices. The SQLite file and flat log file should be treated as sensitive data. Operators should consider setting `log_queries: blocked` or `log_queries: none` if a full query log is not needed.

---

## Testing Strategy

- **Unit tests:** Every implementation package under `internal/` ships a `*_test.go` file. Coverage includes `blocklist.Store` lookup and whitelist precedence, `blocklist.parseHostsFormat` against both hosts-file and plain-domain inputs, `blocklist.Update` preserving the store on full-failure refresh, `cache.Cache` TTL decrement / drop-on-full / Qclass-aware keying / Close shutdown, `config.Load` with empty/partial/invalid YAML plus `Validate` rejecting bogus enums, `stats.Counter` concurrent invariants (block rate never exceeds 100% under parallel writers), `querylog.FileLogger` filtering modes, `querylog.DBLogger` round-trip and final-flush-on-Close, `dns.Handler` sinkhole / cache-hit / whitelist / empty-question paths, and the `api` HTTP handlers including reload single-flight and the 64 KiB body cap. Several tests are regression tests for specific bug numbers (b/005, b/007, b/010, b/017, b/018, b/021, b/022, b/024, b/026, b/028).
- **DNS handler tests** use a `fakeWriter` implementing `dns.ResponseWriter`; the cache-hit path is exercised by pre-populating the in-memory cache with a known response, bypassing the upstream resolver entirely.
- **Integration test (planned):** Spin up an in-process `dns.Server` on a random port; send A/AAAA queries via the network. The component-level coverage above already exercises the same handler code paths without binding a port.
- **Manual smoke test:** Configure a single device's DNS to the running instance; browse to an ad-heavy site; verify blocked domains return `0.0.0.0` in `nslookup` and ads do not render. Check admin UI reflects live query counts.

---

## Open Questions

| # | Question | Owner | Status |
|---|----------|-------|--------|
| 1 | Should we support DNS-over-HTTPS upstream forwarding? Some ISPs intercept plain DNS on port 53. | — | Open |
| 2 | Is there a use case for per-client whitelists (e.g., unblocking streaming services for one device)? | — | Open |
| 3 | Should the SQLite DB have a max-size or TTL-based retention policy to prevent unbounded growth? | — | Open |
| 4 | Should the binary register itself as a Windows Service via `golang.org/x/sys/windows/svc`? | — | **Resolved** — implemented in Phase 6 |
| 5 | Should the DNS cache use LRU eviction instead of drop-on-full? | — | Open — see Alternatives Considered |
| 6 | Should the admin UI require authentication (e.g., a configurable API key)? | — | Open |
