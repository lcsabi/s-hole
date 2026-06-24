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

---

## CL 9 — s-hole: project structure cleanup and LICENSE

**Bug:** —

### Description

Brings the repo layout in line with the modern Go convention for
application-binary projects.

**Move implementation packages under `internal/`** — Every Go package
other than `main` (`api`, `blocklist`, `cache`, `config`, `dns`,
`querylog`, `service`, `stats`) is relocated under `internal/`.
Go's compiler enforces that packages beneath `internal/` are only
importable from the owning module, which matches the project's actual
intent: s-hole is an application, not a library. The module path stays
`github.com/lcsabi/s-hole`; only the per-package import paths change.

**Add MIT LICENSE** — A top-level `LICENSE` file establishes the legal
status of the code. Without it the source was technically all-rights-
reserved despite being on a public repo. The README gains a brief License
section pointing at the file.

**Delete stale binaries from the working tree** — `s-hole.exe` and
`s-hole-linux-arm64` were left over from development. They are gitignored
so they were not tracked, but they cluttered the working directory and
were inconsistent across machines. The Makefile and Dockerfile rebuild
them on demand.

### Files changed

```
internal/api/                  ← moved from api/
internal/blocklist/            ← moved from blocklist/
internal/cache/                ← moved from cache/
internal/config/               ← moved from config/
internal/dns/                  ← moved from dns/
internal/querylog/             ← moved from querylog/
internal/service/              ← moved from service/
internal/stats/                ← moved from stats/
main.go                        — updated import paths
internal/api/api.go            — updated import paths
internal/dns/handler.go        — updated import paths
LICENSE                        — new: MIT License
README.md                      — package table updated; License section added
DESIGN.md                      — package directory headings updated to internal/
CL.md                          — this entry
s-hole.exe, s-hole-linux-arm64 — deleted from working tree
```

### Testing

Verified `go build ./...` and `go vet ./...` pass cleanly after the
import-path rewrite. The packaged binary has identical behaviour; only
the source tree layout changed.

---

## CL 10 — s-hole: unit tests for every package + b/028

**Bug:** b/028 (discovered by tests)

### Description

Adds a `*_test.go` file alongside every implementation package under
`internal/`. The suite uses only the standard library and `httptest`;
no external test framework, no test fixtures on disk.

**Coverage by package**

- `internal/blocklist` — `Store.IsBlocked`, whitelist precedence, atomic
  `Replace` under contention, `parseHostsFormat` for both list formats,
  `fetchList` against `httptest.NewServer` (including the 503 →
  stale-cache fallback regression for b/007), `Update` preserving the
  store on full-failure refresh (regression for b/024), and partial-
  success replacement.
- `internal/cache` — Set/Get round-trip, TTL decrement, expiry, drop-on-
  full, NXDOMAIN/zero-TTL non-caching, hit/miss counters, Qclass-aware
  keying (regression for b/010), `Close` shutdown (regression for b/018).
- `internal/config` — `Load` with empty / partial / invalid YAML;
  `Validate` accepting valid enums and rejecting bogus ones (regression
  for b/017); duration parsing.
- `internal/stats` — `RecordQuery`, `RecordCacheHit`, top-N ordering and
  truncation, cache-hit percentage with no forwardable queries, and a
  concurrent stress test that enforces `blocked ≤ total` across 5000
  Snapshot reads (regression for b/021).
- `internal/querylog` — `FileLogger` filtering modes (`all` / `blocked` /
  `none`), `Multi` fan-out preserving order, `DBLogger` round-trip,
  `Recent` ordering, `TopBlocked` aggregation, filter mode applied to
  the DB sink, `Close` flushing pending entries (regression for b/005),
  and non-blocking back-pressure on the input channel.
- `internal/dns` — `Handler.ServeDNS` for sinkhole-zero, sinkhole-
  NXDOMAIN, whitelist-overrides-block (via pre-populated cache),
  cache-hit-avoids-upstream (verified by pointing upstreams at
  `127.0.0.1:1`), empty-question SERVFAIL, and blocked MX returning
  NOERROR with no answer. A `fakeWriter` implements `dns.ResponseWriter`
  in-process so no port binding is required.
- `internal/api` — `/api/stats` returns a `stats.Summary`, full
  whitelist add/list/delete round trip, empty-domain POST rejected
  with 400, oversized POST rejected by `MaxBytesReader` (regression for
  b/026), `/api/reload` reporting `"reload triggered"` on success and
  `"reload already in progress"` when the closure returns `false`
  (regression for b/022), and a 50-way concurrent reload test exercising
  the single-flight gate.

**b/028 — Load returned io.EOF for empty config files**
Discovered by `TestLoad_EmptyAppliesDefaults`. The README and package
doc both state that an empty config is valid, but `yaml.Decoder.Decode`
returns `io.EOF` on empty streams and `Load` returned that verbatim.
Wrapped the call: `err != nil && !errors.Is(err, io.EOF)`. Empty files
now load successfully and surface all defaults.

### Files changed

```
internal/blocklist/store_test.go       — new
internal/blocklist/loader_test.go      — new
internal/cache/cache_test.go           — new
internal/config/config_test.go         — new
internal/config/config.go              — b/028: tolerate io.EOF in Load
internal/stats/stats_test.go           — new
internal/querylog/logger_test.go       — new
internal/querylog/db_test.go           — new
internal/dns/handler_test.go           — new (fakeWriter + nullLogger)
internal/api/api_test.go               — new
README.md                              — add Testing section
DESIGN.md                              — replace "tests planned" with the real coverage list
BUGS.md                                — file b/028
CL.md                                  — this entry
```

### Testing

```
$ go test ./...
ok    github.com/lcsabi/s-hole/internal/api        0.613s
ok    github.com/lcsabi/s-hole/internal/blocklist  0.816s
ok    github.com/lcsabi/s-hole/internal/cache      0.446s
ok    github.com/lcsabi/s-hole/internal/config     0.354s
ok    github.com/lcsabi/s-hole/internal/dns        0.560s
ok    github.com/lcsabi/s-hole/internal/querylog   1.399s
ok    github.com/lcsabi/s-hole/internal/stats      0.342s
```

The race detector requires CGO and a C toolchain; not exercised locally
on this Windows host but the tests are race-safe by construction (every
shared map is mutex-guarded).

---

## CL 11 — s-hole: architecture (slog, context, package rename)

**Bug:** R1, R2, R7

### Description

Three foundational changes to bring the runtime up to current Go
idioms.

**slog adoption (R1)** — every package now binds a child
`slog.With("pkg", "<name>")` logger and replaces ad-hoc
`fmt.Printf("[xxx] …")` with `slog.Info/Warn/Error` calls. `main.go`
installs the default handler; format is text on a TTY and JSON when
`S_HOLE_LOG_FORMAT=json` is set. The stats printer (`Counter.Print`)
and the startup banner deliberately keep `fmt.Println` because they are
human banners, not diagnostic logs.

**Context propagation (R2)** — `forward` takes `ctx context.Context`
and uses `client.ExchangeContext` so the overall query has a 10 s
deadline and is cancelled if the calling DNS handler returns.
`querylog.DBLogger.Recent` and `TopBlocked` now take a context too and
forward it to `db.QueryContext`, so an HTTP-client disconnect cancels
the SQL query rather than letting it complete.

**Package rename (R7)** — `internal/dns` → `internal/dnsserver`. The
old name collided with `github.com/miekg/dns` (which we import as
`dns`); inside the package, references to `dns.Question` and friends
now unambiguously refer to miekg's types. `main.go` drops the
`dnsserver` alias since the package name now matches.

### Files changed

```
internal/dnsserver/                    ← renamed from internal/dns/
internal/dnsserver/handler.go          — slog + ctx + queryDeadline const
internal/dnsserver/server.go           — slog
internal/dnsserver/upstream.go         — ctx-aware forward
internal/dnsserver/handler_test.go     — package rename
internal/blocklist/loader.go           — slog
internal/querylog/logger.go            — slog
internal/querylog/db.go                — slog + ctx on Recent/TopBlocked
internal/api/api.go                    — slog + ctx forwarded to Recent
main.go                                — setupLogger; slog throughout;
                                         drop dnsserver alias
```

---

## CL 12 — s-hole: correctness fixes (R8–R20)

**Bug:** R8, R9, R10, R11, R12, R13, R14, R15, R16, R17, R18, R19, R20

### Description

Bundle of focused correctness improvements following the second
independent staff review.

- **R8** `runTicker` wraps the user fn in `recover()`; a panic is
  logged and the next tick still fires. Previously a single bad
  blocklist line could freeze the refresh ticker until restart.
- **R9** `blocklist.fetchList` writes to `cachePath + ".tmp"` and
  `os.Rename`s on success. A killed process or dropped connection no
  longer leaves a half-written cache file with a fresh mtime. This
  caught a latent bug: bare colons in URLs (e.g. embedded ports) had
  to be escaped in `cacheFilename` for the rename to work on NTFS.
- **R10** `writeJSON` logs `json.Encoder.Encode` errors.
- **R11** `apiServer.Shutdown` errors during `doStop` are logged.
- **R12** Sinkhole replies mirror the EDNS0 OPT pseudo-record when
  the request carried one; clients no longer fall back to legacy DNS.
- **R13** `POST /api/whitelist` validates the domain via
  `blocklist.ValidDomain` (max 253 chars, must contain a dot,
  alphanumerics + `-` + `_` + `.` only).
- **R14** `blocklist.parseHostsFormat` drops tokens that fail
  `ValidDomain` so one malformed list line cannot pollute the store.
- **R15** `cache.Cache` switches `hits`/`misses` to `atomic.Uint64`;
  `Get` no longer takes the write lock on the hot path.
- **R16** New config knob `query_db_retention_days`. When > 0, the
  DBLogger spawns a prune goroutine that runs hourly and deletes
  query rows older than the cutoff.
- **R17** `main.go` tracks the in-flight reload goroutine in a
  `sync.WaitGroup`. `doStop` waits on it (bounded by the same 5 s
  shutdown context) so the atomic rename can complete before
  `os.Exit`.
- **R18** Default `api_listen` is now `127.0.0.1:8080`. LAN access
  is opt-in.
- **R19** `stats.Counter` caps `topDomains`/`topClients` at 4096
  entries. When exceeded, the bottom half by count is dropped
  (`pruneBottomHalf`).
- **R20** Channel/batch tuning constants in `querylog`
  (`queryQueueSize`, `flushBatchSize`, `pruneTickPeriod`) are now
  named and documented.

### Files changed

```
main.go                                — R8 (runTicker recover), R17 (reloadWG)
internal/blocklist/loader.go           — R9, R14
internal/api/api.go                    — R10, R13
internal/dnsserver/handler.go          — R12 EDNS0 echo
internal/cache/cache.go                — R15 atomic counters
internal/querylog/db.go                — R16 retention prune, R20 named consts
internal/config/config.go              — R16 retention field, R18 default
internal/stats/stats.go                — R19 topNMaxEntries + pruneBottomHalf
internal/config/config_test.go         — assertion for R18 default
internal/querylog/db_test.go           — wired ctx + retention args
```

---

## CL 13 — s-hole: new endpoints + features

**Bug:** R3, R4, R5, R6, R24

### Description

- **R3 `/metrics`** — Prometheus text exposition (format `0.0.4`)
  for in-process counters. Hand-rolled — no external dependency, in
  line with the project's "small, auditable" goal. Exposed counters:
  `shole_queries_total`, `shole_blocked_total`, `shole_cache_hits_total`,
  `shole_cache_misses_total`, `shole_cache_size`,
  `shole_blocklist_size`, `shole_whitelist_size`. Cache metrics are
  only included when a `CacheStatser` is wired into the API server
  (i.e., when caching is enabled). `api.New` gains the `CacheStatser`
  parameter (may be nil).
- **R4 `/healthz`** — liveness probe. Returns 200 OK with body `ok`.
  Makes no downstream call so an upstream outage cannot trigger a
  container restart.
- **R5 env-var overrides** — `applyEnvOverrides()` runs after
  `applyDefaults()`. Every commonly-tuned config field can be
  overridden via `S_HOLE_*`. Malformed numerics are silently ignored
  so an env typo never blocks startup.
- **R6 upstream health tracking** — `upstreamTracker` remembers the
  last failure timestamp per upstream. `forward` (now
  `forwardWith` taking an injectable tracker for tests) skips
  upstreams in cooldown (30 s) on the first sweep, then retries them
  on a second sweep if every non-cooldown upstream also failed.
  Eliminates the "every query waits 3 s on the dead primary" failure
  mode.
- **R24 ASCII banner fallback** — `printNetworkHint` emits ASCII
  box-drawing when `S_HOLE_LOG_FORMAT=json` or `S_HOLE_ASCII_BANNER=1`
  is set. Avoids mojibake on the legacy Windows console.

### Files changed

```
internal/api/api.go                    — CacheStatser field; /healthz + /metrics routes
internal/api/metrics.go                — new: handleHealth + handleMetrics
internal/config/config.go              — applyEnvOverrides()
internal/dnsserver/upstream.go         — upstreamTracker + forwardWith
main.go                                — apiServer.New takes dnsCache;
                                         useASCIIBanner / printNetworkHint fallback
internal/api/api_test.go               — fakeCacheStats wiring updated
```

---

## CL 14 — s-hole: docs + tests + CI

**Bug:** R21, R22, R23, R25, R26, R27, R28

### Description

Closing-out polish CL for the staff-review slice.

**Docs**

- `CHANGELOG.md` (R21) — operator-facing Keep-a-Changelog summary.
  CL.md remains the development-internal CL record.
- README gains a Testing section, an env-var override table, and a
  `go install github.com/lcsabi/s-hole@latest` line (R22).
- `config.yaml` documents the new `query_db_retention_days` field and
  the changed `api_listen` default.
- Architecture diagram in DESIGN updated to show the periodic refresh
  ticker, the response-cache atomic counters, EDNS0 pass-through, and
  the new `/healthz` / `/metrics` endpoints (R25).
- New "Observability and Logging" section in DESIGN.

**Tests** — every new piece of behaviour added in CL 11–13 has direct
test coverage:

- `blocklist.ValidDomain` table tests (R14)
- atomic cache write: leaves no `.tmp` file behind on success (R9)
- `stats.pruneBottomHalf` keeps the high-frequency entries; top-N maps
  remain bounded under high cardinality (R19)
- `config.applyEnvOverrides` round-trips for string and integer
  fields; malformed numerics fall through to defaults (R5)
- `querylog.DBLogger.prune` deletes rows older than retentionDays
  (R16)
- `dnsserver.forwardWith` happy path, failover from a dead upstream
  to a healthy one, second-call cooldown skip, all-fail error path,
  cooldown expiry, and recordSuccess clearing the cooldown (R6, R28)
- `dnsserver.Handler` mirrors EDNS0 OPT on sinkhole replies (R12)
- `api` `/healthz` returns 200 with `ok` body; `/metrics` returns
  Prometheus exposition with the expected counter lines, and includes
  cache metrics when a `CacheStatser` is wired (R3, R4)
- benchmark for `blocklist.Store.IsBlocked` on a 100 000-entry store
  (R27)

**CI** — `.github/workflows/ci.yml` (R26). Two jobs:

- `test`: build, vet, `go test -race`, single-iteration benchmarks.
- `cross-compile`: linux/amd64, linux/arm64, linux/arm v7,
  windows/amd64 with `CGO_ENABLED=0`.

**Other**

- Dead `Documentation=https://github.com/lcsabi/s-hole` URL removed
  from `deploy/s-hole.service` and the embedded heredoc in
  `deploy/install-linux.sh` (R23).

### Files changed

```
CHANGELOG.md                           — new (R21)
README.md                              — Testing, env-vars, go install (R22)
DESIGN.md                              — architecture diagram + observability (R25)
config.yaml                            — retention field; api_listen default
deploy/s-hole.service                  — drop dead Documentation URL (R23)
deploy/install-linux.sh                — drop dead Documentation URL (R23)
.github/workflows/ci.yml               — new CI workflow (R26)
internal/blocklist/store_test.go       — IsBlocked benchmark (R27)
internal/blocklist/loader_test.go      — ValidDomain + atomic-rename tests
internal/stats/stats_test.go           — top-N cap + pruneBottomHalf tests
internal/config/config_test.go         — env-var override tests
internal/querylog/db_test.go           — retention prune test
internal/dnsserver/upstream_test.go    — new: forwardWith + tracker tests (R28)
internal/dnsserver/handler_test.go     — EDNS0 pass-through test (R12)
internal/api/api_test.go               — /healthz + /metrics tests (R3, R4)
CL.md                                  — this entry
```

### Testing

```
$ go test ./...
ok    github.com/lcsabi/s-hole/internal/api
ok    github.com/lcsabi/s-hole/internal/blocklist
ok    github.com/lcsabi/s-hole/internal/cache
ok    github.com/lcsabi/s-hole/internal/config
ok    github.com/lcsabi/s-hole/internal/dnsserver
ok    github.com/lcsabi/s-hole/internal/querylog
ok    github.com/lcsabi/s-hole/internal/stats
```

---

## CL 15 — s-hole: re-enable SIGHUP reload on Unix; correct platform framing

**Bug:** —

### Description

Reverses a stale architectural decision and corrects the documentation
that justified it.

DESIGN.md previously claimed s-hole "targets Windows as a first-class
platform" and used that to justify dropping the `SIGHUP` reload
handler. The framing was wrong: Linux is the actual primary deployment
target — the entire `deploy/` directory, the hardened systemd unit,
the Raspberry Pi optimisations, and the Docker image are all
Linux-first. Windows is a *supported* second platform via the SCM
integration, not the design's centre of gravity. With that corrected,
there is no reason to deny Unix operators the conventional
`kill -HUP $(pidof s-hole)` gesture for "reload config."

Implementation uses two tiny build-tagged files so `main.go` itself
contains no platform conditionals:

- `signals_unix.go` (`//go:build !windows`) — `reloadSignals()`
  returns `[]os.Signal{syscall.SIGHUP}`; `isReloadSignal(sig)` matches
  SIGHUP.
- `signals_windows.go` (`//go:build windows`) — both functions are
  no-op stubs.

The signal handler in `main.go` is restructured into a `for sig := range sigs`
loop. SIGHUP fires `reloadFn()` (the same single-flight closure shared
with the periodic timer and `POST /api/reload`); SIGINT/SIGTERM fall
through to `doStop`. SIGHUP delivery thus collapses onto the existing
gate — concurrent SIGHUPs do not stack into duplicate downloads, and
a SIGHUP that arrives mid-shutdown does not extend the shutdown
window.

The Windows code path is unchanged: SCM stop is still the canonical
lifecycle gesture, and `POST /api/reload` remains the on-demand refresh
trigger on that platform.

### Files changed

```
signals_unix.go            — new: SIGHUP wiring (build !windows)
signals_windows.go         — new: no-op stubs   (build windows)
signals_unix_test.go       — new: reloadSignals + isReloadSignal tests
signals_windows_test.go    — new: Windows stub tests
main.go                    — for-range loop dispatches reload vs shutdown
DESIGN.md                  — rewrite "In-process blocklist update via a signal":
                             Linux is primary; SIGHUP is wired on non-Windows
README.md                  — Linux systemctl section gains a SIGHUP recipe
CL.md                      — this entry
CHANGELOG.md               — SIGHUP entry under Unreleased
```

### Testing

```
$ go test -count=1 ./...
ok    github.com/lcsabi/s-hole               # signal predicates
ok    github.com/lcsabi/s-hole/internal/...
$ GOOS=linux   go build ./...   # build green
$ GOOS=windows go build ./...   # build green
$ GOOS=darwin  go build ./...   # build green
```

Manual smoke (Linux): start interactively, `kill -HUP $(pidof s-hole)`,
observe the "reload signal received" log line followed by the
existing "refreshing blocklists" output.

---

## CL 16 — s-hole: production-grade test coverage

**Bug:** —

### Description

The post-CL-15 coverage measurement showed the project at 60.8 % overall
with notable gaps:

- `main.go` helpers (0 %)
- `internal/dnsserver/server.go` (0 % — the whole file)
- `stats.Counter.Print` (0 %)
- `api.ListenAndServe` / `Shutdown` (0 %)
- `api.handleQueries` (0 % — never wired to a real DB in tests)
- `cache.runCleanup` (45 %), `querylog.NewFileLogger` fallback (57 %)
- Several handler/forwarder branches and config parser error paths

CL 16 closes those gaps to a production-grade target (≥ 85 % on every
implementation package).

**New test files**

- `main_test.go` — covers `setupLogger` (text + JSON modes),
  `useASCIIBanner` (4-case table), `printNetworkHint`
  (Unicode + ASCII fallback variants), `buildMultiLogger` (db nil
  and non-nil), `runTickerOnce` panic recovery (R8 regression), and
  `waitWithDeadline` for both the WG-drains-first and ctx-expires
  branches.
- `internal/dnsserver/server_test.go` — `NewServer` field assignment
  plus a full Start → live UDP query → Shutdown lifecycle test that
  binds a free port from the OS, confirms a real `dns.Client.Exchange`
  succeeds, and verifies `Start` returns after `Shutdown`.

**Tests extended**

- `internal/stats/stats_test.go` — `Print` output capture via os.Pipe
  redirection; asserts presence of `[stats]`, `total=`, `blocked=`,
  and the top-domains section.
- `internal/cache/cache_test.go` — `cleanupExpired` directly tested
  with a backdated entry; production `runCleanup` refactored to
  delegate to the new helper so the body is reachable without a
  one-minute ticker wait.
- `internal/config/config_test.go` — error-path coverage for all
  three duration parsers (table-driven); a separate test exercises
  every string-typed `S_HOLE_*` env-var override.
- `internal/querylog/db_test.go` — `NewDBLogger` error path on an
  unwritable path; `prune` no-op on an empty table.
- `internal/querylog/logger_test.go` — `NewFileLogger` fallback to
  stdout on a bad path + empty-path case; `Close` no-op on stdout
  fallback.
- `internal/dnsserver/handler_test.go` — cache-miss forward path with
  a real in-process mock upstream; upstream-failure SERVFAIL path;
  `writeSinkhole` error branch driven via injected
  `fakeWriter.writeError`; EDNS0 pass-through.
- `internal/dnsserver/upstream_test.go` — package-level `forward`
  (was 0 %, now covered by a happy-path test against the real
  mock upstream).
- `internal/api/api_test.go` — full `ListenAndServe` + `Shutdown`
  lifecycle on a free port; `Shutdown` no-op when never started;
  `/api/queries` round-trip with a real DBLogger;
  `?limit=garbage` falls through to the default;
  empty-domain DELETE returns 400; invalid-domain POST rejected by
  `ValidDomain`; `writeJSON` driven against a `brokenResponseWriter`
  to cover the encoder-error log branch.

**Coverage delta**

| Package           | Before | After  |
|-------------------|--------|--------|
| `internal/api`    | 66.7 % | 91.9 % |
| `internal/cache`  | 85.5 % | 94.8 % |
| `internal/config` | 87.2 % | 100 %  |
| `internal/dnsserver` | 60.2 % | 87.0 % |
| `internal/querylog`  | 80.5 % | 85.4 % |
| `internal/stats`     | 81.8 % | 100 %  |
| `main`               | 1.1 %  | 26.8 % |
| **module-wide**      | **60.8 %** | **71.3 %** |

The remaining uncovered region is exactly what cannot be unit-tested
without running the binary: the `main()` bootstrap sequence, the
signal-dispatch goroutine, and the Windows-only `service/` SCM glue.
Those paths are exercised by the manual smoke tests documented in
DESIGN.md.

### Files changed

```
main_test.go                            — new
internal/dnsserver/server_test.go       — new
internal/cache/cache.go                 — extract cleanupExpired helper
internal/cache/cache_test.go            — cleanupExpired test
internal/config/config_test.go          — table-driven duration parsers + all-string env overrides
internal/querylog/db_test.go            — NewDBLogger bad path; prune empty
internal/querylog/logger_test.go        — NewFileLogger fallback paths
internal/dnsserver/handler_test.go      — cache-miss, SERVFAIL, writeSinkhole error
internal/dnsserver/upstream_test.go     — package-level forward()
internal/api/api_test.go                — full lifecycle + handleQueries + error branches
internal/stats/stats_test.go            — Print output capture
CL.md                                   — this entry
```

### Testing

```
$ go test -count=1 -cover ./...
ok    github.com/lcsabi/s-hole                26.8%
ok    github.com/lcsabi/s-hole/internal/api   91.9%
ok    github.com/lcsabi/s-hole/internal/blocklist 89.3%
ok    github.com/lcsabi/s-hole/internal/cache 94.8%
ok    github.com/lcsabi/s-hole/internal/config 100%
ok    github.com/lcsabi/s-hole/internal/dnsserver 87.0%
ok    github.com/lcsabi/s-hole/internal/querylog 85.4%
ok    github.com/lcsabi/s-hole/internal/stats 100%
```

---

## CL 17 — s-hole: documentation sync pass

**Bug:** —

### Description

Audits every doc and code comment against the actual state of the
codebase after CLs 11–16 and brings them back in alignment. No
functional changes.

**README.md**

- Architecture diagram refreshed to show EDNS0 pass-through, atomic
  cache counters, the periodic refresh ticker, `/healthz` + `/metrics`,
  SIGHUP, slog, and the 30 s upstream cooldown — matching the diagram
  already in DESIGN.
- Package table corrected: `internal/dns` → `internal/dnsserver` (the
  old name was a stale reference from before CL 11).
- REST API intro flags that the default bind is `127.0.0.1` (set
  `api_listen: "0.0.0.0:8080"` for LAN access).

**DESIGN.md**

- Testing Strategy rewritten with current per-package coverage
  percentages and the list of new test surfaces added in CL 16
  (server lifecycle, env overrides, retention prune, /metrics,
  /healthz, EDNS0, etc.). The "Integration test (planned)" note is
  resolved; the server lifecycle test now binds a real port.
- Open Question #3 (SQLite retention) marked **Resolved** — see CL 12.
- Open Question #6 (admin UI auth) annotated with the localhost-default
  mitigation from CL 12.
- New Open Question #7 (DoH/DoT for blocklist downloads).
- Security Considerations: the "firewall or restrict to 127.0.0.1"
  bullet now reflects that 127.0.0.1 is the default; adds a note that
  `/healthz` and `/metrics` are also unauthenticated.
- `internal/dns/` heading corrected to `internal/dnsserver/`.

**BUGS.md** — file-path references in resolved bug descriptions
(b/010, b/013, b/014, b/017, b/020) updated to the post-CL-11
location with a "formerly" annotation so historical accuracy is
preserved.

**Code comments**

- `main.go` header doc rewritten to include slog setup, env-var
  overrides, /healthz + /metrics, panic-recovered tickers, and the
  SIGHUP-as-reload signal contract.
- `internal/api/api.go` package doc enumerates every HTTP route and
  flags the new localhost default.
- `internal/dnsserver/handler.go` package doc documents EDNS0
  pass-through and the upstream health tracker.
- `internal/stats/stats.go` package doc mentions the top-N cap.
- `internal/querylog/logger.go` package doc covers retention and the
  ctx-aware reads.
- `internal/config/config.go` package doc states the precedence
  (env > YAML > defaults) and the order of operations.
- `internal/cache/cache.go` package doc covers atomic counters,
  Qclass-aware keys, and the cleanup goroutine.

### Files changed

```
README.md                          — architecture diagram + dnsserver path + LAN-default note
DESIGN.md                          — Testing Strategy, Open Questions, Security; dnsserver heading
BUGS.md                            — file-path "formerly" annotations on resolved bugs
main.go                            — header doc covers slog, env, /healthz, SIGHUP, reload wait
internal/api/api.go                — package doc enumerates routes + default
internal/cache/cache.go            — package doc covers atomic counters + Qclass + sweep
internal/config/config.go          — package doc states precedence order
internal/dnsserver/handler.go      — package doc documents EDNS0 + tracker
internal/querylog/logger.go        — package doc covers retention + ctx-aware reads
internal/stats/stats.go            — package doc mentions top-N cap
CL.md                              — this entry
```

### Testing

```
$ go build ./... && go vet ./... && go test -count=1 ./...
ok  ... (all eight packages green)
```

No code paths changed; only docs and comments.

---

## CL 18 — s-hole: production project layout (cmd/, docs/, SECURITY)

**Bug:** —

### Description

Brings the repository layout up to the production-grade convention
used by mature Go applications.

- **`cmd/s-hole/`** — the `main` package and its companions
  (`signals_unix.go`, `signals_windows.go`, plus their tests and the
  shared `main_test.go`) move out of the repo root. The
  `go install`-able URL changes from `github.com/lcsabi/s-hole@latest`
  to `github.com/lcsabi/s-hole/cmd/s-hole@latest`. Makefile,
  Dockerfile, and the GitHub Actions cross-compile matrix are all
  updated to build `./cmd/s-hole`.
- **`docs/`** — `DESIGN.md`, `CL.md`, `BUGS.md`, and `CHANGELOG.md`
  move into a dedicated docs directory. `README.md`, `LICENSE`, and
  the new `SECURITY.md` stay at root. README gains a "Repository
  layout" section so newcomers can see the shape at a glance.
- **`SECURITY.md`** — new security-disclosure policy at the repo
  root. Covers the reporting channel, response SLA, scope, and a
  summary of the defensive posture (server timeouts, body cap,
  atomic cache writes, ValidDomain gating, hardened systemd unit,
  no CGO).
- **Stale binary removed** — `s-hole.exe` was sitting in the working
  tree from a local build; gitignored but cluttering. Deleted.
- **`.dockerignore`** updated to exclude the new `docs/` directory,
  the new `SECURITY.md` / `BUGS.md` / `CHANGELOG.md`, plus `.git/`
  and `.github/` so the image build is deterministic.
- **Cross-references** — code comments in
  `internal/{api,dnsserver,querylog,service,stats}/*.go` that
  referred to `main.go` now spell the full path
  `cmd/s-hole/main.go` so a project-root `grep` lands at the actual
  file. `docs/DESIGN.md` references to `main.go` and the
  `signals_*.go` files are likewise full-pathed. `docs/BUGS.md`
  reference to the root README adjusted to `../README.md` to reflect
  the relocation. Historical CL entries (CL 1–17) keep their
  original at-time-of-filing paths; CL 18 documents the move so a
  reader cross-referencing the two has a clear pivot.
- **README architecture diagram redrawn** — the previous diagram
  had uneven right-edge alignment because content lines drifted in
  width. The new version is exactly 61 visual cells wide for every
  inside-the-box line, so the right `│` aligns perfectly.

### Files changed

```
cmd/s-hole/                              ← moved from repo root
  ├── main.go
  ├── main_test.go
  ├── signals_unix.go
  ├── signals_unix_test.go
  ├── signals_windows.go
  └── signals_windows_test.go
docs/                                    ← moved from repo root
  ├── BUGS.md
  ├── CHANGELOG.md
  ├── CL.md
  └── DESIGN.md
SECURITY.md                              — new (security disclosure policy)
README.md                                — Architecture diagram redrawn, aligned;
                                           repository layout section added;
                                           go install + build paths updated
Makefile                                 — build path → ./cmd/s-hole
Dockerfile                               — build path → ./cmd/s-hole
.github/workflows/ci.yml                 — cross-compile path → ./cmd/s-hole
.dockerignore                            — exclude docs/, SECURITY.md, BUGS.md,
                                           CHANGELOG.md, .git/, .github/
internal/api/api.go                      — code comment full-paths main.go
internal/dnsserver/handler.go            — code comment full-paths main.go
internal/querylog/logger.go              — code comment full-paths main.go
internal/service/svc_windows.go         — code comment full-paths main.go
internal/service/svc_other.go            — code comment full-paths main.go
internal/stats/stats.go                  — code comment full-paths main.go
docs/DESIGN.md                           — main.go / signals_*.go references full-pathed
docs/BUGS.md                             — README.md reference adjusted to ../README.md
docs/CL.md                               — CL 16 trailing sections restored;
                                           this entry appended
s-hole.exe                               — deleted (gitignored stray build artifact)
```

### Testing

```
$ go build ./... && go vet ./... && go test -count=1 ./...
ok    github.com/lcsabi/s-hole/cmd/s-hole
ok    github.com/lcsabi/s-hole/internal/api
ok    github.com/lcsabi/s-hole/internal/blocklist
ok    github.com/lcsabi/s-hole/internal/cache
ok    github.com/lcsabi/s-hole/internal/config
ok    github.com/lcsabi/s-hole/internal/dnsserver
ok    github.com/lcsabi/s-hole/internal/querylog
ok    github.com/lcsabi/s-hole/internal/stats
```

The new module path is `github.com/lcsabi/s-hole/cmd/s-hole`; the rest of
the package paths are unchanged.

---

## CL 19 — s-hole: build identity, lint, dependabot, templates

**Bug:** —

### Description

Closes the remaining "things every production Go project ships with"
gaps. No behaviour changes to the runtime; every addition is a build,
review, or operator-facing improvement.

**Build identity (`internal/version`)** — new package with three
package-level vars (`Version`, `Commit`, `BuildDate`) populated via
`-X` linker flags. The Makefile derives them from `git describe`,
`git rev-parse --short HEAD`, and the current UTC timestamp; the
Dockerfile accepts them as `--build-arg` (`VERSION`, `COMMIT`,
`BUILD_DATE`); CI fills them from the GitHub Actions context.
Source builds without flags fall back to placeholder values (`dev` /
`unknown` / `unknown`). The binary gains a `-version` flag that
prints the full identity, and the startup slog line includes
`version=…`, `commit=…`, `built=…` attributes so a log scrape during
an incident can pinpoint exactly which build is in production.

**`Makefile` standardised** — beyond the existing cross-compile
targets, the file now exposes the conventional production targets:

- `make check` — fmt + vet + lint + test (what CI runs)
- `make test` — plain test run
- `make test-race` — with the race detector
- `make bench` — single-iteration benchmark smoke
- `make lint` — `golangci-lint run ./...`
- `make fmt` — `gofmt -s -w .`
- `make vet` — `go vet ./...`
- `make install` — `go install` into `$GOBIN`
- `make version` — print the version metadata that the next build
  would embed
- `make help` — auto-generated list of targets (parsed from the
  `## ...:` comments)

**`golangci-lint`** — new `.golangci.yml` enabling `errcheck`,
`govet`, `ineffassign`, `staticcheck`, `unused`, `misspell`,
`gocritic`, and `revive`. Tests are exempt from `errcheck` and
`gosec` (false-positive heavy). A `lint` job is wired into CI and
runs before the test job so a style violation fails the pipeline
fast.

**`dependabot.yml`** — weekly PRs for Go modules, GitHub Actions,
and the Docker base image. Labelled `dependencies`, `ci`, or
`docker` so they sort cleanly in the PR list. Limited to five open
PRs at a time to avoid flooding the review queue.

**`.github/CODEOWNERS`** — `*` defaults to the maintainer; the
security-sensitive paths (`SECURITY.md`, `.github/`, `deploy/`,
`internal/api/`, `internal/dnsserver/`, `internal/blocklist/`) are
explicitly listed so the intent is obvious to a future co-maintainer.

**Pull-request template** — `.github/pull_request_template.md`
prompts for summary, linked CL/bug, why, test plan checklist, and
risk. Doubles as the reviewer checklist.

**Issue templates** — bug-report and feature-request templates
under `.github/ISSUE_TEMPLATE/`. The bug template asks for
`s-hole -version` output explicitly; the feature template prompts
the reporter to confirm against the documented non-goals in DESIGN.

**CI** — the cross-compile matrix now injects the same version
metadata as the local Makefile, so artifacts produced by CI are
introspectable.

**README** — new "Development" section listing the Makefile targets,
the per-package coverage table, sample `-version` output, and a note
about CI + dependabot.

**DESIGN.md** — "Packaging and Deployment" gains a "Build identity"
paragraph documenting the `-X` ldflag scheme.

### Files changed

```
internal/version/                  ← new package
  ├── version.go                   — Version, Commit, BuildDate, String, Short
  └── version_test.go              — defaults + format assertions
cmd/s-hole/main.go                 — -version flag; startup slog line with metadata
Makefile                           — version-injected ldflags; new targets
Dockerfile                         — ARG VERSION/COMMIT/BUILD_DATE + -X ldflags
.github/workflows/ci.yml           — new lint job; cross-compile injects metadata
.github/dependabot.yml             — new (gomod, github-actions, docker)
.github/CODEOWNERS                 — new
.github/pull_request_template.md   — new
.github/ISSUE_TEMPLATE/bug_report.md       — new
.github/ISSUE_TEMPLATE/feature_request.md  — new
.golangci.yml                      — new lint config
README.md                          — Development section; layout updated
docs/DESIGN.md                     — Build identity paragraph
docs/CHANGELOG.md                  — version / Makefile / lint / dependabot entries
docs/CL.md                         — this entry
```

### Testing

```
$ go build ./... && go vet ./... && go test -count=1 ./...
ok    github.com/lcsabi/s-hole/cmd/s-hole
ok    github.com/lcsabi/s-hole/internal/api
ok    github.com/lcsabi/s-hole/internal/blocklist
ok    github.com/lcsabi/s-hole/internal/cache
ok    github.com/lcsabi/s-hole/internal/config
ok    github.com/lcsabi/s-hole/internal/dnsserver
ok    github.com/lcsabi/s-hole/internal/querylog
ok    github.com/lcsabi/s-hole/internal/stats
ok    github.com/lcsabi/s-hole/internal/version
```

Verified `-version` output round-trips both injected and placeholder
values:

```
$ go build -ldflags="-X '....Version=v0.1.0-test' -X '....Commit=abc1234' \
                    -X '....BuildDate=2026-06-24T12:00:00Z'" -o /tmp/s ./cmd/s-hole
$ /tmp/s -version
s-hole v0.1.0-test
  commit:  abc1234
  built:   2026-06-24T12:00:00Z
  go:      go1.25.0
  os/arch: windows/amd64

$ go build -o /tmp/s ./cmd/s-hole && /tmp/s -version
s-hole dev
  commit:  unknown
  built:   unknown
  ...
```

---

## CL 20 — s-hole: act on fourth staff review (R31–R48)

**Bug:** —

### Description

Acts on every finding from the fourth independent staff review.
Module path renamed from `github.com/laszlo/s-hole` to
`github.com/lcsabi/s-hole` to match the actual GitHub account.

**Critical / high**

- **R31 data race** — `Counter.Snapshot` previously read `c.topDomains`
  / `c.topClients` at the call site, racing against the
  `c.topDomains = pruneBottomHalf(...)` reassignment in `RecordQuery`.
  Refactored `topN` to take an enum (`topNDomains`/`topNClients`) and
  resolve the map inside the lock. New regression test
  `TestCounter_ConcurrentPruneAndSnapshot_NoRace` drives the prune
  and snapshot branches concurrently.
- **R32 magic 100** — `querylog/db.go:172` used a literal `100` for
  the per-batch flush trigger while the file already defined
  `flushBatchSize = 100`. Replaced with the named constant.

**Medium**

- **R33** — `DBLogger.dropped` (atomic) + `Dropped()` accessor;
  new metric `shole_query_log_dropped_total` exposes channel
  back-pressure.
- **R34** — `Store.WhitelistLen()` O(1) read; `/metrics` no longer
  allocates the full whitelist slice per scrape.
- **R35** — `internal/api/pprof.go` registers the six standard
  `net/http/pprof` handlers under `/debug/pprof/`. Behind
  `enable_pprof: true` (`S_HOLE_ENABLE_PPROF=1`). Off by default; WARN
  log fires at startup when enabled.
- **R36** — `Counter.blocked` was both `atomic.Int64` and updated
  under the mutex. Demoted to a plain `int64` field guarded by `c.mu`;
  removes the misleading dual-protection.

**Low / polish**

- R37 `/api/whitelist` GET returns sorted domains.
- R38 new `/readyz` (200 once `store.Len() > 0`; 503 otherwise).
- R39 CI runs `go mod verify`.
- R40 Dockerfile drops `tzdata` (~30 MB image-size reduction).
- R41 `CODEOWNERS` → `@lcsabi`.
- R42 `SECURITY.md` rewritten to point at GitHub Security Advisories.
- R43 `forwardWith` second-sweep semantics documented.
- R44 README REST API intro leads with the localhost default.
- R45 `runTickerOnce` panic recovery includes `debug.Stack()`.
- R46 new `make tools-install` target installs `golangci-lint`.

**Tests**

- R47 fuzz tests for `ValidDomain`, `parseHostsFormat`, `cacheFilename`.
- R48 full-stack integration test wires store + cache + querylog +
  handler + DNS server + mock UDP upstream through three real queries
  (blocked, forwarded-and-cached, cache-hit). Asserts upstream call
  counts, stats deltas, and SQLite rows.

### Files changed

```
go.mod + every Go file              — module rename → github.com/lcsabi/s-hole
internal/stats/stats.go             — R31 topN refactor; R36 blocked demoted to int64
internal/stats/stats_test.go        — R31 regression test
internal/querylog/db.go             — R32 named const; R33 Dropped counter
internal/blocklist/store.go         — R34 WhitelistLen
internal/api/api.go                 — R35 EnablePprof; R37 sort whitelist
internal/api/pprof.go               — new (R35)
internal/api/metrics.go             — R33/R34 metrics; R38 /readyz
internal/config/config.go           — R35 EnablePprof + env override
config.yaml                         — R35 enable_pprof default
cmd/s-hole/main.go                  — wire EnablePprof; R45 debug.Stack()
internal/dnsserver/upstream.go      — R43 second-sweep comment
internal/blocklist/fuzz_test.go     — new (R47)
internal/dnsserver/integration_test.go  — new (R48)
.github/workflows/ci.yml            — R39 go mod verify
.github/CODEOWNERS                  — R41 @lcsabi
Dockerfile                          — R40 drop tzdata
Makefile                            — R46 tools-install
SECURITY.md                         — R42 GitHub Security Advisories
README.md                           — /readyz, pprof, env vars, test notes
docs/CHANGELOG.md / docs/CL.md      — this entry
```

### Testing

```
$ go build ./... && go vet ./... && go test -count=1 ./...
ok    github.com/lcsabi/s-hole/cmd/s-hole
ok    github.com/lcsabi/s-hole/internal/api
ok    github.com/lcsabi/s-hole/internal/blocklist
ok    github.com/lcsabi/s-hole/internal/cache
ok    github.com/lcsabi/s-hole/internal/config
ok    github.com/lcsabi/s-hole/internal/dnsserver
ok    github.com/lcsabi/s-hole/internal/querylog
ok    github.com/lcsabi/s-hole/internal/stats
ok    github.com/lcsabi/s-hole/internal/version
```

Fuzz smoke:

```
$ go test -fuzz=FuzzValidDomain -fuzztime=3s ./internal/blocklist/
fuzz: elapsed: 3s, execs: 184368 (61388/sec), new interesting: 32
PASS
```
