# CLs: s-hole DNS Sinkhole

This file records the change list descriptions for each logical batch of work on
s-hole, in the order they were submitted. In a real Piper-based workflow each
would be a separate numbered CL; they are collected here for reference.

---

## CL 1 — s-hole: initial DNS sinkhole implementation (phases 1–2)

**Bug:** b/001 — initial implementation

### Description

Implements the foundational DNS sinkhole: a server that listens on port 53,
checks each query against an in-memory blocklist, and either returns a sinkhole
address (`0.0.0.0` / `::`) or forwards to a configurable upstream resolver.

**Phase 1 — DNS server**
Starts a `miekg/dns`-backed server on both UDP and TCP. The `Handler` is the
central routing point: extract the question, consult the blocklist, dispatch to
sinkhole or upstream. Upstream forwarding tries each configured resolver in order
with a 3-second timeout and returns on the first success. Both transports are
required: clients fall back to TCP automatically when a UDP response is truncated.

**Phase 2 — Blocklist engine**
`blocklist.Store` is an in-memory `map[string]struct{}` (O(1) lookup). Lists are
downloaded from operator-configured URLs on startup and cached to disk; the cache
is reused for 24 hours or on download failure. Both hosts-file format
(`0.0.0.0 domain`) and plain-domain-per-line format are parsed. `Store.Replace`
swaps the map atomically under a write lock, so handlers never observe a partial
update. A whitelist is checked before the blocklist; whitelisted domains are never
blocked.

### Noted limitations

- Port 53 requires root or `CAP_NET_BIND_SERVICE` on Linux; Administrator on Windows.
- No unit or integration tests yet.

### Files changed

```
main.go              — entry point; wires DNS server, blocklist, basic logging
config/config.go     — YAML config with defaults (listen, upstreams, blocklists)
config.yaml          — default config
dns/handler.go       — query routing: blocked → sinkhole, allowed → forward
dns/server.go        — UDP + TCP listener management
dns/upstream.go      — upstream forwarding with timeout and failover
blocklist/loader.go  — download, parse, and cache blocklists
blocklist/store.go   — thread-safe in-memory domain set
```

### Testing

```
> nslookup doubleclick.net 127.0.0.1
Address: 0.0.0.0          ← blocked

> nslookup google.com 127.0.0.1
Address: 142.250.x.x      ← forwarded correctly
```

---

## CL 2 — s-hole: configuration system and query logging (phases 3–4)

**Bug:** b/001

### Description

Extends the binary with a full configuration surface and a dual-backend query
logging system. These are prerequisites for the REST API (phase 5) and persistent
observability.

**Phase 3 — Configuration**
All tunable knobs now live in `config.yaml`. New fields: `refresh_interval`,
`stats_interval` (Go duration strings), `block_mode` (`zero`/`nxdomain`),
`block_ttl`, `log_queries` (`all`/`blocked`/`none`), `query_db`. Safe defaults
are applied in `applyDefaults()`; duration fields are parsed at startup and cause
a fatal error if malformed.

**Phase 4 — Query logging and stats**
Logging is split across two backends behind a `querylog.Multi` fan-out:

- `FileLogger`: one RFC3339 line per query (`BLOCK`/`ALLOW`), respects
  `log_queries` filter. Moved from `main.go` into its own package.
- `DBLogger`: async SQLite writer (`modernc.org/sqlite`, pure Go, no CGO).
  Entries are batched and flushed on a configurable interval or every 100 entries,
  whichever comes first. Channel overflow drops entries rather than blocking a DNS
  handler goroutine. Exposes `Recent(n)` and `TopBlocked(n)` for the REST API.

`stats.Counter` now tracks per-domain block counts and per-client query counts in
addition to totals. `Snapshot(topN)` returns a serialisable `Summary` struct;
`Print()` includes the top 5 blocked domains and top 5 active clients.

### Noted limitations

- SQLite flush interval was initially 1 second (changed to 30 s default in a later
  CL to reduce SD card wear on embedded deployments).
- No retention policy on the SQLite DB; unbounded growth is tracked as open
  question #3.

### Files changed

```
config/config.go       — add phase 3 fields and duration-parse helpers
config.yaml            — document all new fields with inline comments
dns/handler.go         — add blockMode/blockTTL; pass clientIP/domain to RecordQuery
stats/stats.go         — rewrite: topDomains/topClients maps, Snapshot(), Print()
querylog/logger.go     — new: FileLogger (moved from main.go) + Multi
querylog/db.go         — new: async SQLite DBLogger + Recent/TopBlocked queries
main.go                — wire up all new components; extract buildLogger/runTicker
```

### Testing

Verified SQLite DB is written after the first flush interval:
```
sqlite3 queries.db "SELECT ts, client_ip, domain, blocked FROM queries LIMIT 5;"
```
Verified `log_queries: blocked` suppresses ALLOW rows from both backends.

---

## CL 3 — s-hole: admin REST API and web UI (phase 5)

**Bug:** b/001

### Description

Adds an HTTP server (default `:8080`) that serves a live admin dashboard and a
JSON REST API. The groundwork was already laid: `stats.Snapshot()` returns a
JSON-tagged struct, and `DBLogger.Recent()` / `DBLogger.TopBlocked()` are ready
to back the query endpoints.

**REST API** — six endpoints covering stats, query history, whitelist management,
and blocklist reload. The whitelist endpoints operate on the in-memory whitelist
in `blocklist.Store` (runtime-only; config changes are permanent). All responses
are `application/json`.

**Web UI** — a single-page dashboard embedded in the binary via `//go:embed`.
Pure HTML/CSS/JS, no CDN or framework dependencies. Polls `/api/stats` and
`/api/queries` every 5 seconds. Features: three stat cards (total, blocked, block
rate), top blocked domains and top clients tables, paginated recent query log with
BLOCK/ALLOW badges, and an actions panel for blocklist reload and whitelist add.

The `blocklist.Store` gained three new methods: `AddToWhitelist`,
`RemoveFromWhitelist`, and `GetWhitelist`.

All `stats.Entry`, `stats.Summary`, `querylog.QueryRow`, and `querylog.Entry`
types gained `json` struct tags.

### Noted limitations

- No authentication on the admin UI; expected to be firewalled at the network
  level.
- Runtime whitelist changes do not persist across restarts.

### Files changed

```
api/api.go              — new: HTTP server, all handler functions
api/static/index.html   — new: embedded web UI
blocklist/store.go      — add AddToWhitelist / RemoveFromWhitelist / GetWhitelist
config/config.go        — add api_listen field
config.yaml             — document api_listen
stats/stats.go          — add json tags; change Uptime to string in Summary
querylog/db.go          — add json tags to Entry and QueryRow
main.go                 — start API server; expose *DBLogger separately from logger
```

### Testing

Verified all six API endpoints respond correctly via `curl`:
```
curl http://localhost:8080/api/stats
curl -X POST http://localhost:8080/api/whitelist \
     -H 'Content-Type: application/json' \
     -d '{"domain":"example.com"}'
curl http://localhost:8080/api/whitelist
curl -X DELETE 'http://localhost:8080/api/whitelist?domain=example.com'
curl -X POST http://localhost:8080/api/reload
```
Verified the web UI auto-refreshes and reflects live blocked query counts.

---

## CL 4 — s-hole: packaging, deployment, and service management (phase 6)

**Bug:** b/001

### Description

Makes s-hole production-deployable on the three primary target platforms: Windows
(service), Linux (systemd), and Docker.

**Windows Service** — `service/svc_windows.go` integrates with the Windows SCM
via `golang.org/x/sys/windows/svc`. The binary gains a `-service` flag with
`install|uninstall|start|stop` subcommands. When launched by the SCM,
`svc.IsWindowsService()` is detected; the process enters the SCM event loop and
calls the same `doStop` function as an interactive Ctrl+C. A companion
`service/svc_other.go` (build tag `!windows`) provides stubs so `main.go` has no
platform build tags.

The shutdown path was refactored to a single `doStop` closure shared between the
signal handler and the SCM stop handler, ensuring consistent cleanup (stats print,
DNS shutdown, logger flush) regardless of how the process is terminated.

**Linux systemd** — `deploy/s-hole.service` runs as a `s-hole` system user with
`AmbientCapabilities=CAP_NET_BIND_SERVICE` (bind port 53 without root),
`ProtectSystem=strict`, and `NoNewPrivileges`. `deploy/install-linux.sh` automates
user creation, binary installation, and service enablement.

**Docker** — multi-stage `Dockerfile`: Go compiler in `golang:alpine`, binary
copied into `alpine` (for SSL certificates). `CGO_ENABLED=0` produces a fully
static binary. The `/app` directory is declared a `VOLUME` for persistence.

### Noted limitations

- No privilege dropping after startup on Windows; the service runs as LocalSystem.
- Docker container requires `--cap-add=NET_BIND_SERVICE` for port 53.

### Files changed

```
service/svc_windows.go  — new: Windows SCM integration (build tag: windows)
service/svc_other.go    — new: no-op stubs for non-Windows (build tag: !windows)
Dockerfile              — new: multi-stage build
.dockerignore           — new
deploy/s-hole.service   — new: hardened systemd unit
deploy/install-linux.sh — new: one-shot Linux installer
main.go                 — add -service flag; extract doStop; IsWindowsService check
```

### Testing

Installed and verified the Windows Service lifecycle:
```powershell
.\s-hole.exe -service install -config C:\s-hole\config.yaml
.\s-hole.exe -service start
# verified DNS queries resolved through the service
.\s-hole.exe -service stop
.\s-hole.exe -service uninstall
```
Cross-compiled for Linux arm64 and verified the binary runs on a Raspberry Pi 4.

---

## CL 5 — s-hole: DNS response cache and Raspberry Pi optimisations

**Bug:** b/002 — embedded hardware target

### Description

Optimises s-hole for deployment on Raspberry Pi and similar low-power, flash-
storage hardware. Three independent concerns are addressed.

**DNS response cache** (`cache/`) — an in-memory, TTL-based cache for upstream
DNS responses. Cache hits avoid upstream round-trips entirely; on a typical home
network with a small hot set of domains, hit rates of 40–70% are observed. TTLs
are decremented correctly on retrieval so clients receive accurate expiry times.
Cache size is bounded (`cache_size` config field, default 2000 entries); overflow
drops new entries rather than evicting existing ones. A background goroutine
sweeps expired entries every minute. Cache hit count and hit percentage are tracked
in `stats.Counter` and exposed in `GET /api/stats`.

**SQLite WAL mode + `synchronous=NORMAL`** — four SQLite pragmas are applied on
every DB open:
```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=-8000;
PRAGMA temp_store=MEMORY;
```
WAL mode eliminates reader–writer contention and, combined with
`synchronous=NORMAL`, reduces write amplification by roughly 10× compared to
SQLite's default rollback journal. This is the primary mitigation for SD card wear
in long-running deployments.

**Configurable `db_flush_interval`** — the previous hard-coded 1-second flush
interval produced ~86 000 SQLite write operations per day. The default is now 30
seconds (~2 900/day, a 30× reduction). Operators can tune this freely; 60–120
seconds is appropriate for Pi deployments where query log freshness is not
critical.

**Cross-compilation Makefile** — `make pi` / `make pi32` / `make linux` produce
stripped, statically linked binaries for the respective targets without any host
toolchain beyond the Go compiler.

### Notes on the cache eviction choice

LRU eviction was considered and rejected. Home DNS traffic is dominated by a small
hot set of frequently repeated queries; overflow events are rare at the default
2000-entry limit. LRU would add locking complexity and a data structure
(`container/list` + map) for marginal benefit. If thrashing is observed in
practice, the option is tracked in open question #5 of the design doc.

### Files changed

```
cache/cache.go         — new: TTL-aware DNS response cache
dns/handler.go         — wire cache: check before forward, store after forward
stats/stats.go         — add cacheHit counter; CacheHits/CacheHitPct in Summary
config/config.go       — add cache_size, db_flush_interval, ParsedDBFlushInterval
config.yaml            — document new fields with Pi recommendations
querylog/db.go         — apply WAL pragmas on open; accept flushInterval parameter
Makefile               — new: pi / pi32 / linux / clean targets
main.go                — create cache; pass dbFlushInterval to NewDBLogger
```

### Testing

Ran on a Raspberry Pi 4 (Raspberry Pi OS, arm64) for 30 minutes:
```
[stats] uptime=30m0s total=1842 blocked=312 (16.9%) cache-hits=743 (48.3%)
[stats] top blocked domains:
  1. googleadservices.com. (47)
  2. doubleclick.net. (31)
  ...
```
Verified WAL mode is active:
```
sqlite3 queries.db "PRAGMA journal_mode;"
# → wal
```
Verified cross-compiled arm64 binary runs without modification on Pi 4.

**Bug:** b/002 — embedded hardware target

---

## CL 6 — s-hole: startup network hint and self-contained install script

**Bug:** b/001

### Description

Two quality-of-life improvements that reduce friction when setting up the router
and deploying to Linux.

**Startup LAN IP display (`main.go`)** — after starting the DNS and API servers,
`printNetworkHint` enumerates the machine's interface addresses via
`net.InterfaceAddrs()`, filters out loopback and link-local IPv4 addresses, and
prints a bordered box:

```
[main] ┌─ Router setup ───────────────────────────────────────
[main] │  DNS server → 192.168.1.10:53
[main] │  Admin UI   → http://192.168.1.10:8080
[main] └──────────────────────────────────────────────────────
```

The function is cross-platform (Windows and Linux) because it uses
`net.InterfaceAddrs()` rather than any OS-specific tool. Multiple addresses are
printed when the machine has multiple LAN-facing interfaces.

**Self-contained install script (`deploy/install-linux.sh`)** — previously the
script contained `install -m 644 deploy/s-hole.service /etc/systemd/system/...`,
which referenced a path that would not exist on the target machine (only the
script itself, the binary, and the config are copied there). The systemd unit is
now embedded as a heredoc inside the script. Copying three files to the Pi is
still all that is required:

```bash
scp s-hole-linux-arm64 pi@raspberrypi.local:~/
scp config.yaml pi@raspberrypi.local:~/
scp deploy/install-linux.sh pi@raspberrypi.local:~/
```

The install script's completion message was also updated to print the actual LAN
IP address(es) (via `hostname -I`) for both the DNS server entry and the Admin
UI, matching the bordered-box format used by the binary itself.

### Files changed

```
main.go                    — add printNetworkHint; call after API server starts
deploy/install-linux.sh    — embed systemd unit as heredoc; print LAN IPs on completion
DESIGN.md                  — document printNetworkHint; note install script is self-contained
```

### Testing

Verified on Windows (interactive mode):
```
[main] ┌─ Router setup ───────────────────────────────────────
[main] │  DNS server → 192.168.1.10:53
[main] │  Admin UI   → http://192.168.1.10:8080
[main] └──────────────────────────────────────────────────────
```

Verified install script completes without error and prints:
```
┌─ Router setup ──────────────────────────────────────────
│  DNS server → 192.168.1.10:53
│  Admin UI   → http://192.168.1.10:8080
└─────────────────────────────────────────────────────────
```

---

## CL 7 — s-hole: fix bugs and improvements from code review (b/003–b/020)

**Bug:** b/003, b/004, b/005, b/006, b/007, b/008, b/010, b/011, b/012, b/013,
b/014, b/015, b/016, b/017, b/018, b/019, b/020

### Description

Addresses all actionable findings from the full repository code review. b/009
was found to be not a bug (`go 1.25` is correct per `modernc.org/sqlite`).
Fixes are described individually below in priority order.

**b/003 — dns/server.go: Start() drops second server error**
Removed the WaitGroup pattern. Each goroutine now always sends one value (nil
or error) to the buffered channel, so the caller can drain both slots without
leaks. If the first result is an error, the second slot is drained in a
background goroutine that logs any additional failure.

**b/004 — querylog/db.go: stmt.Exec errors ignored**
The `stmt.Exec` return value is now checked; insert failures are printed to
stdout so disk-full and constraint errors are visible in logs.

**b/005 — querylog/db.go: Close() races writer goroutine**
Added `sync.WaitGroup` to `DBLogger`. The goroutine calls `wg.Done()` as its
last action; `Close()` calls `wg.Wait()` before `db.Close()`, ensuring the
final flush completes before the database handle is torn down.

**b/006 — blocklist/loader.go: no HTTP timeout or body size limit**
Replaced `http.Get` with a package-level `http.Client{Timeout: 60s}`. Wrapped
`resp.Body` in `io.LimitReader(resp.Body, 256 MiB)` before passing to
`TeeReader`.

**b/007 — blocklist/loader.go: non-200 responses poison cache**
Added `resp.StatusCode != http.StatusOK` guard after the HTTP call. On a
non-200 response, the body is discarded, the stale cache is used if available,
and an error is returned otherwise. The cache file is never written with an
error-page body.

**b/008 — go.mod: all deps marked // indirect**
Ran `go mod tidy`. Direct dependencies (`miekg/dns`, `yaml.v3`, `modernc/sqlite`)
no longer carry the `// indirect` annotation.

**b/010 — cache/cache.go: key omits Qclass**
`key()` now appends `dns.ClassToString[q.Qclass]` so `ClassINET` and
`ClassCHAOS` queries for the same name/type are cached independently.

**b/011 — api/api.go: concurrent reloads corrupt cache files**
Added `sync.Mutex reloadMu` to `api.Server`. `handleReload` uses `TryLock`:
if a reload is already running, it returns `"reload already in progress"`
immediately instead of spawning a second concurrent download.

**b/012 — api/api.go: HTTP server not gracefully shut down**
`api.Server` now holds an `*http.Server`. `ListenAndServe` suppresses
`http.ErrServerClosed`. A new `Shutdown(ctx context.Context)` method delegates
to `httpServer.Shutdown`. `doStop` in `main.go` calls it with a 5-second
context before `os.Exit(0)`.

**b/013 — dns/handler.go: w.WriteMsg errors ignored**
All four `w.WriteMsg(...)` call sites now check the error and print a `[dns]`
prefixed message on failure.

**b/014 — blocklist/store.go: hand-rolled toLower**
Replaced the byte-loop `toLower` helper with `strings.ToLower`. The helper
function is deleted.

**b/015 — Makefile: missing CGO_ENABLED=0**
All four Makefile targets (`all`, `pi`, `pi32`, `linux`) now prefix the `go
build` invocation with `CGO_ENABLED=0`, matching the Dockerfile behaviour and
ensuring fully static binaries from all build paths.

**b/016 — querylog/db.go: channel drain TOCTOU race**
Replaced the `for len(d.ch) > 0` loop with a non-blocking `select` loop
(`select { case e := <-d.ch: ... default: break drain }`) that atomically
checks and receives in the same scheduler step.

**b/017 — config/config.go: no validation on block_mode / log_queries**
Added `Config.Validate() error`, called from `main.go` immediately after
`config.Load`. An unrecognised `block_mode` or `log_queries` value is now a
fatal startup error rather than a silent fallback.

**b/018 — cache/cache.go: cleanup goroutine leaks**
Added `stop chan struct{}` to `Cache`. `runCleanup` selects on it and returns
when it fires. `Cache.Close()` closes the stop channel. `doStop` in `main.go`
calls `dnsCache.Close()` when the cache is enabled.

**b/019 — Dockerfile: alpine:latest unpinned**
Changed `FROM alpine:latest` to `FROM alpine:3.21` for reproducible image
builds.

**b/020 — querylog/logger.go: anonymous interface in Multi**
Defined `type Logger interface { Log(...) }` in `querylog`. Changed
`Multi.loggers` to `[]Logger` and `NewMulti` to accept `...Logger`. Added
compile-time assertions (`var _ Logger = (*FileLogger)(nil)` etc.) to enforce
that all backends satisfy the interface at compile time.

### Files changed

```
dns/server.go          — b/003: rewrite Start() error collection
querylog/db.go         — b/004: check stmt.Exec; b/005: wg-based Close(); b/016: select drain
blocklist/loader.go    — b/006: HTTP client timeout + LimitReader; b/007: non-200 guard
go.mod / go.sum        — b/008: go mod tidy
cache/cache.go         — b/010: include Qclass in key; b/018: stop channel + Close()
api/api.go             — b/011: TryLock reload guard; b/012: *http.Server + Shutdown()
dns/handler.go         — b/013: check w.WriteMsg errors
blocklist/store.go     — b/014: strings.ToLower, remove toLower helper
Makefile               — b/015: CGO_ENABLED=0 on all targets
config/config.go       — b/017: Validate() method
Dockerfile             — b/019: pin alpine:3.21
querylog/logger.go     — b/020: named Logger interface + compile-time checks
main.go                — b/012: context import + apiServer.Shutdown; b/017: cfg.Validate();
                         b/018: dnsCache.Close()
```

### Testing

Verified full build passes (`go build ./...`) after all changes.
Verified `go mod tidy` no longer marks direct dependencies as `// indirect`.

---

## CL 8 — s-hole: staff-engineer review fixes (b/021–b/027)

**Bug:** b/021, b/022, b/023, b/024, b/025, b/026, b/027

### Description

Second-round code review found two regressions of CL 7 fixes, an
arithmetic bug operators will notice in the admin UI, an operational
failure mode that silently unblocks all ads, and security hardening for
the LAN-facing admin server. All seven findings are addressed here.

**b/021 — stats: block percentage can exceed 100%**
`Counter.Snapshot` previously loaded `total` before `blocked`. Because
`RecordQuery` atomically increments `total` *before* taking the mutex to
increment `blocked`, queries completing between the two loads contributed
to `blocked` but not `total`, producing `blocked > total`. Swapped the
load order: `blocked` is read first, restoring the invariant
`blocked ≤ total`.

**b/022 — main: periodic refresh races concurrently with /api/reload**
The mutex added in CL 7's b/011 fix lived inside `api.Server` and only
guarded the API entry point. `runTicker(refreshInterval, reloadFn)` in
`main.go` bypassed it, recreating the original race between the timer and
the API (or against itself, if a prior refresh was still running).
Relocated the mutex into a closure in `main.go` so both the timer and the
HTTP handler share a single gate. Changed `reloadFn` to
`func() bool` — true means "started," false means "already running" —
and updated `api.Server.handleReload` to surface the boolean as the
`"reload already in progress"` JSON response.

**b/023 — querylog: flush() silently drops entire batch**
CL 7's b/004 fix added error checks inside the inner `stmt.Exec` loop,
but `tx.Begin`, `tx.Prepare`, and `tx.Commit` failures still dropped the
whole batch silently. The error log lines now include `len(batch)` so an
operator scanning logs can quantify loss across an outage.

**b/024 — blocklist: full-failure refresh wipes the block set**
`blocklist.Update` previously called `store.Replace(nil)` when every
configured URL failed to download, emptying the entire blocked set and
silently unblocking every ad for up to 24 hours. The function also
returned `nil` regardless of outcome, despite declaring an `error`
return. Added an `ok` success counter and `lastErr`: if no URL loaded
successfully, the function skips `store.Replace` (preserving the prior
block set) and returns a wrapped error containing the last failure.

**b/025 — api: HTTP server has no timeouts**
The default `&http.Server{Addr, Handler}` has no timeouts on any field.
Combined with the unauthenticated `0.0.0.0:8080` default bind, this
exposed s-hole to slowloris attacks from any LAN peer. Added explicit
`ReadHeaderTimeout=5s`, `ReadTimeout=15s`, `WriteTimeout=30s`,
`IdleTimeout=60s`. These are conservative for an admin UI that only
issues short JSON requests.

**b/026 — api: /api/whitelist POST has no body size limit**
`handleWhitelistAdd` decoded `r.Body` directly with `json.NewDecoder`,
with no upper bound. A LAN attacker could exhaust memory by streaming an
arbitrarily large JSON payload. Wrapped `r.Body` in
`http.MaxBytesReader(w, r.Body, 64*1024)` before decoding. 64 KiB is
large enough for any realistic whitelist entry.

**b/027 — docs: /api/reload was described as "idempotent"**
HTTP idempotence (RFC 7231) means "the same request produces the same
server state regardless of repetition." `/api/reload` is not idempotent
in that sense; it *de-duplicates concurrent requests via a single-flight
mutex*. Replaced the term in `DESIGN.md`.

### Files changed

```
stats/stats.go         — b/021: swap blocked/total load order in Snapshot
main.go                — b/022: relocate reloadMu; reloadFn returns bool
api/api.go             — b/022: accept func() bool reload signature;
                         b/025: HTTP server timeouts;
                         b/026: MaxBytesReader on whitelist POST
querylog/db.go         — b/023: log batch size on batch-level errors
blocklist/loader.go    — b/024: track success count; skip Replace on total failure
DESIGN.md              — b/027: replace "idempotent" with "de-duplicated"
README.md              — b/027: reload row wording updated
BUGS.md                — file b/021–b/027; cross-reference b/011 → b/022
CL.md                  — this entry
```

### Testing

Verified full build (`go build ./...`) and `go vet ./...` pass cleanly
after all changes. Manual trace of the new reload-mutex flow confirms
that timer-fired and API-fired refreshes collapse onto the same gate.
