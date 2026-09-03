# Changelog

All notable changes to s-hole are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project loosely
tracks [Semantic Versioning](https://semver.org/), starting from the first
tagged release, `v0.1.0`. Detailed per-CL descriptions live under `cls/`, indexed by
`CL.md`; this file is the operator-facing summary.

## [Unreleased]

## [0.2.1] - 2026-09-03

### Added
- **`s-hole -check-config -config <path>`** loads and validates a config the way
  startup does, then exits (`0` and a `config OK` line when valid, non-zero with
  the failing field otherwise). Use it to check an edit before restarting the
  service. (CL 66)
- **The Linux installer is hardened against silent failures.** It validates its
  arguments (a swapped binary/config pair is now rejected, not written over each
  other), dry-runs the config before starting, warns when `systemd-resolved`
  holds port 53 (and frees it under `--free-port-53`), and health-checks the
  service after starting: a unit that does not come up prints the last log lines
  and fails the install, so a dead service no longer looks green. It also gained
  `-h`/`--help`. (CL 66)

### Changed
- **The Linux installer's safety checks are tighter.** It now rejects a binary
  that runs but does not identify as s-hole; before, any file that ran was
  accepted. It also detects the `systemd-resolved` stub on TCP port 53 as well
  as UDP. (CL 67)

### Fixed
- **A non-positive `refresh_interval` or `stats_interval` is now rejected at
  startup.** Like `db_flush_interval`, a value such as `0s` or `-5s` used to pass
  validation (and `-check-config`) and then crash a background timer once the
  service was up. All three interval fields now fail cleanly with a clear error
  instead. (CL 68)
- **A failed admin-server bind is now surfaced at startup.** If `api_listen` is
  misconfigured or its port is taken, s-hole logs a clear WARN, keeps serving
  DNS, and the startup banner reports the admin UI as unavailable instead of
  advertising a URL that refuses connections. Previously the failure was a single
  easy-to-miss log line and the banner still advertised the UI. (CL 63)
- **Blocklist source cache files no longer collide.** Cache filenames are now
  derived from a hash of the source URL, so two similar URLs cannot map to one
  file and clobber each other's cached copy. (CL 62)
- **An over-size blocklist source is no longer silently truncated.** If a source
  exceeds the 256 MiB per-source cap, s-hole now logs a WARN and keeps the
  previous cached copy (marked stale) instead of caching the truncated download
  as fresh. (CL 62)
- **`/api/stats` reports `sources` as `[]`, never `null`,** before the first
  blocklist refresh completes. (CL 62)
- **A non-positive `db_flush_interval` now fails cleanly at startup.** A value
  like `0s` or `-5s` used to crash the daemon from a background goroutine after
  the database was already open. It is now rejected with a clear config error,
  the same as a malformed duration string. (CL 61)
- **Boolean env overrides are case-insensitive and fail safe.**
  `S_HOLE_LOCAL_PTR` and `S_HOLE_ENABLE_PPROF` now accept `1`/`true`/`yes` and
  `0`/`false`/`no` in any case, and leave the setting at its default on an
  unrecognised value. Previously a value such as `TRUE` or an empty string turned
  local PTR answering (on by default) off, leaking LAN reverse-DNS upstream. (CL 61)
- **Upstream failover no longer doubles work during an outage.** When every
  upstream is failing, s-hole now contacts each configured resolver at most once
  per query. A retry-sweep bug re-contacted the resolvers that had just failed,
  which doubled failure-path latency and upstream load during an outage (the
  client result, SERVFAIL, was unaffected). (CL 60)
- **Clean shutdown no longer loses data.** On `systemctl stop`, restart, or
  Ctrl+C, s-hole now completes its ordered teardown before the process exits: it
  drains in-flight admin requests, waits for an in-flight blocklist refresh to
  finish its atomic rename, and flushes the query-log database. A race let the
  process exit early and skip these steps, which could drop the final batch of
  logged queries or cut off a refresh mid-write. The in-flight reload wait also
  gets its own timeout so a slow HTTP drain cannot shorten it. (CL 59)

## [0.2.0] - 2026-08-28

### Added
- **Windows service logging.** When launched by the Windows SCM (which gives the
  process no console), s-hole routes its application log to the Windows Event Log
  (source `s-hole`, mapping INFO/WARN/ERROR to the three Event Log severities)
  instead of a discarded stdout. `-service install` registers the event source
  and `-service uninstall` removes it. Startup errors, blocklist-refresh
  failures, and admin audit lines are now visible in Event Viewer. Linux and
  interactive runs are unchanged. (CL 57)
- **"Why is this blocked?" endpoint.** `GET /api/check?domain=NAME` returns the
  block decision (blocked, whitelisted, or allowed) and the full suffix walk that
  produced it: which parent entry matched the block set, and which whitelist
  entry overrode it. The dashboard Actions panel gets a matching "check a domain"
  box that shows the decision and the full walk. It is a read-only diagnostic: it
  bumps no counter and writes no query-log row. (CL 56)
- **Per-source blocklist health.** `/api/stats` now carries a `sources` array
  (URL, domain count, last-refresh time, and a stale flag) for each configured
  blocklist, the dashboard renders it as a "Blocklist Sources" panel with an
  OK/STALE badge, and `/metrics` adds `shole_blocklist_source_size` and
  `shole_blocklist_source_stale` gauges. When one source silently returns an
  empty or truncated list, the operator now sees which one, instead of only a
  drop in the aggregate size. (CL 55)
- **Cache drop metric and expired-slot reclaim.** A new
  `shole_cache_dropped_total` counter on `/metrics` reports entries the cache
  refused because it was full of unexpired entries, the signal that `cache_size`
  is too small for the working set. When the cache is full, `Set` now reclaims a
  slot from an expired entry (a bounded scan) before dropping, so a cache full
  of not-yet-swept expired entries no longer refuses new inserts until the
  once-a-minute sweep. Reclaimed inserts are not counted as drops, so the metric
  reports real capacity pressure rather than sweep-timing noise. (CL 54)
- **Audit logging for admin actions.** A whitelist add or remove now logs the
  domain and the requester address at `Info`, and each blocklist reload logs its
  trigger source, so a `POST /api/reload` is distinguishable from the periodic
  timer and a SIGHUP. The admin API is unauthenticated on the LAN, so these
  state changes previously left no trace in the log. (CL 45)

### Changed
- **`enable_pprof` now also enables mutex and block profiling.** With pprof on,
  `/debug/pprof/mutex` and `/debug/pprof/block` report lock contention and
  blocking events, which the Go runtime leaves off (and those endpoints empty)
  by default. Both sample rather than record every event, so the cost is small
  and is paid only while pprof is enabled, which stays off by default and should
  be bound to localhost. (CL 53)

## [0.1.0] - 2026-08-24

### Added
- **Pre-built releases.** Pushing a `v*` tag now runs
  `.github/workflows/release.yml`, which builds the four targets
  (linux/amd64, linux/arm64, linux/armv7, windows/amd64) with the version
  ldflags and attaches a per-target archive (`tar.gz` for Linux, `zip` for
  Windows, each bundling the binary, `config.yaml`, `LICENSE`, `README.md`,
  and the Linux deploy scripts) plus a `SHA256SUMS` file to a GitHub Release.
  The same tag publishes a multi-arch (amd64 + arm64) image to
  `ghcr.io/lcsabi/s-hole`. `s-hole -version` on a released build reports the
  tag instead of `dev`. (CL 43)
- **A Linux uninstaller, `deploy/uninstall-linux.sh`.** Reverses
  `install-linux.sh`. It stops and disables the service, removes the unit,
  binary, config, and the `s-hole` system user/group, and prints a summary of
  what it removed and kept. Operator data in `/var/lib/s-hole` (query log +
  blocklist caches) is preserved unless you pass `--purge`; `--restore-resolved`
  removes a `DNSStubListener=no` drop-in and restarts `systemd-resolved`; `-y`
  skips the confirmation prompt. (CL 40)
- **All-time top-blocked domains on the dashboard.** The "Top Blocked Domains"
  panel now has a "Since start / All time" toggle. "Since start" is the
  existing in-memory tally (resets when s-hole restarts); "All time" is a new
  persistent tally read from the SQLite query log, so it survives restarts and
  is not capped. It is served by a new `GET /api/top-blocked?limit=N` endpoint
  (default 50, max 1000), which returns an empty list when `query_db` is not
  configured. (CL 33)
- s-hole now logs a loud `WARN` whenever a blocklist update leaves the block
  set empty: a fresh run that could reach no source, or a source that
  responded but parsed to zero domains. Previously an empty result after a
  reachable source looked like a normal refresh in the logs, so "running but
  blocking nothing" could go unnoticed. (CL 29)
- Two standing CI safety nets: goroutine-leak detection (`go.uber.org/goleak`,
  test-only) across the cache, querylog, and DNS-server packages, and
  `govulncheck` scanning for known CVEs (also available locally via
  `make vuln`). (CL 29)
- The current number of blocked domains is now included in the `/api/stats`
  JSON response as `blocklist_size` and displayed as a "Blocklist Size" card
  on the dashboard. This confirms at a glance that the blocklist downloaded
  and parsed successfully after each refresh. (CL 28)
- PTR queries for RFC 6303 private-range reverse zones (10/8, 172.16/12,
  192.168/16, fc00::/7, fe80::/10) are now answered locally with authoritative
  NXDOMAIN instead of being forwarded upstream. No public resolver holds records
  for these addresses; forwarding only wastes a round-trip and leaks internal LAN
  addressing to the upstream resolver. Controlled by `local_ptr` (default `true`;
  set to `false` if you run a private reverse DNS zone on your LAN). The counter
  appears as `local_ptr_count` in `/api/stats` and `shole_local_ptr_total` in
  `/metrics`. The `S_HOLE_LOCAL_PTR` environment variable overrides the config.
- The dashboard shows a fourth stat card, **Cache Hit Rate**, bound to
  the `cache_hit_pct` value the UI already polls from `/api/stats`,
  the number that tells you whether `cache_size` fits your network.
- `CLAUDE.md` at the repo root gives AI coding assistants the
  canonical commands, hot-path architecture, concurrency invariants,
  and process conventions up front.
- `docs/ROADMAP.md` collects planned work (release workflow, subdomain
  blocking, DoH upstreams, hardening batch), pending decisions, and,
  equally deliberately, the non-goals, so future reviews don't
  re-propose them.
- `CONTRIBUTING.md` documents a seven-step manual smoke-test workflow
  (probes → DNS behaviour → dashboard → whitelist round-trip → reload
  → stats/metrics cross-check → persistence + shutdown) for release
  verification.
- `runTicker` now honors a context for clean shutdown: background
  tickers (stats print, blocklist refresh) exit when `doStop` cancels
  the application-wide context instead of being implicitly reclaimed
  by `os.Exit`. New `TestRunTicker_StopsOnContextCancel` regression.
- `internal/version.Info` struct + `Short()` now returns it. The
  startup-log line uses it, and the API has a real caller instead of
  being dead exported code.
- `CONTRIBUTING.md` at the repo root documents the Makefile entry
  points, fuzz-run instructions, project layout, ID conventions
  (`b/NNN`, `R NN`), coverage targets, and the doc-sync rule.
- New tests close coverage gaps the fifth review found: `Dropped()`
  actually increments under overflow + stays 0 under healthy load
  (S5); `/debug/pprof/*` is 404 by default and 200 only when
  `EnablePprof(true)` (S6); the panic-recovery log line includes the
  goroutine stack (S7 / R45 regression).
- `/readyz` readiness endpoint (200 once the blocklist has loaded; 503
  otherwise). Pairs with `/healthz` for Kubernetes-style probes.
- `/debug/pprof/*` endpoints behind `enable_pprof: true` (or
  `S_HOLE_ENABLE_PPROF=1`). Off by default. Required for live CPU/heap
  profiling during incident response.
- `shole_query_log_dropped_total` metric and `DBLogger.Dropped()`;
  operators now see when the query log channel overflows under load.
- `Store.WhitelistLen()`, an O(1) counterpart to `Len()` for the
  `/metrics` scrape path.
- Full-stack integration test wiring store + cache + querylog + handler
  + DNS server + mock upstream through three real queries.
- Fuzz tests for `ValidDomain`, `parseHostsFormat`, and `cacheFilename`.
- `make tools-install` installs `golangci-lint` into `$GOBIN`.
- CI runs `go mod verify` to catch supply-chain integrity issues.
- Build-time version identity: `internal/version` holds `Version`,
  `Commit`, and `BuildDate` vars written at link time via `-X` ldflags.
  `s-hole -version` prints the full identity; startup logs include it.
  Makefile and Dockerfile populate the values from git and the current
  UTC timestamp; CI does the same via GitHub Actions context.
- `Makefile` gains the conventional production targets: `make check`
  (fmt + vet + lint + test), `test`, `test-race`, `bench`, `lint`,
  `fmt`, `vet`, `install`, `version`, and `help`.
- `golangci-lint` integrated: `.golangci.yml` config + a lint job in
  CI that runs before the test job.
- Dependabot keeps Go modules, GitHub Actions, and the Docker base
  image up to date with weekly PRs.
- `.github/CODEOWNERS` declares review ownership.
- Pull-request template and issue templates (bug + feature) under
  `.github/`.
- Production-grade project layout: the `main` package now lives under
  `cmd/s-hole/`; `DESIGN.md`, `CL.md`, `BUGS.md`, and `CHANGELOG.md`
  live under `docs/`. The `go install` path is now
  `github.com/lcsabi/s-hole/cmd/s-hole@latest`.
- `SECURITY.md` security-disclosure policy at the repo root.
- Comprehensive test coverage round: every implementation package now
  at ≥ 85 % line coverage (`config` and `stats` at 100 %). Module-wide
  coverage went from 60.8 % to 71.3 %, with the residual being the
  `main()` bootstrap and Windows SCM glue that cannot be unit-tested.
- `SIGHUP` triggers a blocklist refresh on every non-Windows build.
  Operators can run `kill -HUP $(pidof s-hole)` or
  `systemctl kill -s HUP s-hole` to refresh without enabling the
  admin API. SIGHUP shares the single-flight gate with the timer and
  `POST /api/reload`.
- `/healthz` liveness endpoint (R4).
- `/metrics` Prometheus exposition with counters for queries, blocks,
  cache hits/misses, cache size, blocklist size, whitelist size (R3).
  Hand-rolled exposition format, no new dependencies.
- Environment-variable overrides for every commonly-tuned config field
  via `S_HOLE_*` (R5). See README for the full list.
- Upstream health tracking with a 30-second cooldown for failing
  resolvers, eliminating the "every query waits 3s on the dead primary"
  failure mode (R6).
- SQLite query-log retention via `query_db_retention_days` (R16).
- Structured logging via `log/slog` throughout the codebase. JSON
  format opt-in via `S_HOLE_LOG_FORMAT=json` (R1).
- Context propagation: forward upstream calls and SQLite reads now
  honor cancellation and deadlines (R2).
- EDNS0 OPT pseudo-record is mirrored on sinkhole replies so clients
  do not fall back to legacy DNS (R12).
- Per-domain validator (`blocklist.ValidDomain`) used both by the
  loader and by the whitelist POST endpoint (R13, R14).
- Atomic blocklist cache writes via `.tmp` + rename: torn writes
  during a network drop or process kill no longer leave a half-written
  cache file (R9).
- Top-N maps in `stats.Counter` are capped at 4096 entries; the bottom
  half is pruned when the cap is exceeded (R19).
- Recovery from `runTicker` panics: a panicking ticker function is
  logged and the next tick still fires (R8).
- ASCII fallback for the startup banner when `S_HOLE_LOG_FORMAT=json` or
  `S_HOLE_ASCII_BANNER=1` is set (R24).
- Benchmark for `blocklist.Store.IsBlocked` (R27).
- Tests for upstream forwarder with a real in-process mock UDP server,
  EDNS0 pass-through, atomic cache write, ValidDomain, top-N map cap,
  SQLite retention prune, /metrics, /healthz, env-var overrides (R27,
  R28, plus coverage for everything new in this release).

### Changed
- **Dashboard panel order.** The Actions panel (reload blocklists, whitelist a
  domain) now sits above the Recent Queries log instead of below it. Actions
  keeps a stable, reachable position, and the always-growing query log moves to
  the bottom of the page. (CL 41)
- **Blocking now matches subdomains.** A blocklist (or whitelist) entry now
  covers the whole subtree beneath it: `ads.example.com` blocks
  `x.ads.example.com` as well, so trackers can no longer sidestep a list
  entry by rotating subdomains. Lookups walk a domain's parent labels
  (`a.b.example.com → b.example.com → example.com`) instead of requiring an
  exact match. The whitelist is matched the same way and still wins at every
  level, so it remains the escape hatch for an over-broad block entry:
  whitelist `safe.doubleclick.net` (or a parent domain) to let a subtree
  through while the rest of the blocked domain stays sinkholed. There is no
  new configuration; the behaviour is unconditional. (CL 30)
- **Invalid `whitelist` entries are now dropped with a `WARN`.** Because
  whitelist matching is suffix-based (CL 30), a bare label such as a TLD
  would silently exempt its whole subtree. At startup, `config.Load` now
  drops any `whitelist` entry that is not a valid domain name (the same
  `ValidDomain` check the REST `/api/whitelist` endpoint applies) and logs
  each dropped entry at `WARN`. A typo is surfaced loudly instead of quietly
  disabling blocking for an entire suffix, and it does not abort startup: a
  dropped entry fails safe (the domain stays blockable) and one bad line
  cannot take DNS down for the LAN. (CL 31)
- **The Linux installer now prints the installed build.** `deploy/install-linux.sh`
  ends with an "Installed build" box showing the version, commit, and build date
  of the binary it just placed (`s-hole -version`). A stale `scp` was previously
  silent: the operator had no signal that the running service predated the fix
  they meant to ship. (CL 35)
- Dependency refresh via Dependabot: `alpine` 3.24 base image,
  `golang.org/x/sys` v0.47.0, and CI action majors (checkout v7,
  cache v6, setup-go v6, golangci-lint-action v9).
- The default `listen` is now `":53"` (dual-stack wildcard, IPv4 +
  IPv6) instead of the IPv4-only `"0.0.0.0:53"`, so clients querying
  over IPv6 on dual-stack LANs are served instead of silently ignored.
  Set `listen: "0.0.0.0:53"` explicitly to restore IPv4-only binding.
  The README also documents the RA/RDNSS bypass trap on IPv6 networks.
- The admin dashboard polls `/api/stats` and `/api/queries` every 3
  seconds (was 5) for a snappier live view.
- `/api/queries` clamps `?limit=` to 1000 so one request cannot
  marshal the entire history table into a single JSON response (T3).
- DESIGN's "Alternatives Considered" no longer claims Windows is the
  first-class platform. Linux is the primary deployment target; the
  Windows SCM path is the secondary supported platform.
- Default `api_listen` is now `127.0.0.1:8080`; operators who want
  LAN access must opt in explicitly (R18). Pre-existing configs that
  set `api_listen: "0.0.0.0:8080"` are unaffected.
- Implementation package `internal/dns` renamed to `internal/dnsserver`
  to disambiguate from `github.com/miekg/dns` (R7).
- HTTP server error responses no longer leak internal error strings to
  the client; the message is logged server-side and the client sees a
  generic 500.
- `querylog.DBLogger.Recent` and `TopBlocked` now take a `context.Context`
  argument so HTTP handlers can propagate request cancellation.
- `querylog.NewDBLogger` now takes a fourth argument: `retentionDays`.
- `api.New` now takes a `CacheStatser` argument (may be `nil`) so the
  `/metrics` endpoint can surface cache statistics.

### Fixed
- **A whitelist typo can no longer disable a whole TLD.** `ValidDomain` accepted
  a bare TLD written with a trailing root dot (`"com."`), which normalized to the
  bare label `"com"` and, through subtree matching, exempted every `.com` domain
  from blocking. The validator now requires an interior dot, so `"com."` (and
  `"."`, `"a."`, `".com"`) is rejected at the config, API, and dashboard entry
  points; a real FQDN like `"example.com."` stays valid. (b/040, CL 42)
- **The Docker container starts again when a data volume is mounted.** The
  binary lived at `/app/s-hole`, but `/app` is the declared volume and the
  documented `-v "$(pwd)/data:/app"` bind mount shadowed it, so the container
  died at start with `exec: "./s-hole": ... no such file or directory`, i.e.
  the recommended deployment was broken. The binary now lives on `PATH`
  (`/usr/local/bin/s-hole`), outside the `/app` data volume; every documented
  `docker run` command is unchanged. (CL 39)
- **The query-log retention prune no longer intermittently skips under
  concurrent writes.** The SQLite connection pool is now pinned to a single
  connection (with a `busy_timeout` as a backstop), so the async writer and the
  hourly prune can't collide with `SQLITE_BUSY`, which previously made the
  prune silently skip a tick and, under the race detector, flaked a CI test. No
  operator-facing behaviour change beyond retention now pruning reliably. (CL 38)
- **`/api/stats` can no longer momentarily report a cache hit rate above 100 %.**
  `Snapshot` read the cache-hit counter after the total-queries counter, so a
  concurrent cache hit slipping between the two reads could push the ratio over
  100 % on the dashboard's Cache Hit Rate card. It now reads the later-incremented
  counter first, the same fix already applied to blocked-vs-total (b/021) and
  local-PTR-vs-total (b/033). (CL 37)
- **The Linux installer now restarts the service instead of starting it**, so
  re-running `install-linux.sh` to upgrade actually swaps the running binary.
  `systemctl start` is a no-op on an already-active unit, so an upgrade would
  otherwise keep running the old build while the new "Installed build" banner
  advertised the new one, the exact stale-deploy the banner exists to catch. (CL 36)
- **Mixed-case private-range PTR queries are now answered locally.** The RFC 6303
  intercept matched names case-sensitively, so a query such as
  `1.1.168.192.IN-ADDR.ARPA.` (as produced by dns-0x20 forwarders) slipped past
  it and leaked upstream. DNS names are case-insensitive; the intercept now folds
  case before matching, like the blocklist already did. (CL 36)
- **`/api/stats` can no longer momentarily report `local_ptr_count` greater than
  `total_queries`.** `Snapshot` read the two atomic counters in an order that let
  a concurrent PTR query slip between them; it now reads the later-incremented
  counter first (the same fix already applied to blocked-vs-total, b/021). (CL 36)
- **`/debug/pprof/symbol` now accepts POST**, so `go tool pprof` can symbolize a
  remote profile against a running instance (it POSTs the program-counter list).
  The route had been registered GET-only, which answered POST with 405. Only
  relevant when `enable_pprof` is on. (CL 36)
- **The installer's admin-UI hint no longer misreports a LAN bind as
  localhost-only.** It matched only the literal `0.0.0.0`; binding to a specific
  LAN IP, a bare `:8080`, or the IPv6 wildcard now correctly prints the LAN URL,
  mirroring the in-binary banner's loopback check. (CL 36)
- The dashboard no longer displays the DNS trailing dot on domain names. The
  Top Blocked Domains and Recent Queries panels stripped it for display
  (`sub.doubleclick.net.` now renders as `sub.doubleclick.net`). Queries are
  still recorded and served over the API as the exact wire-format name; the
  change is presentation-only, so it also cleans up rows already stored in the
  query log. (CL 34)
- The shipped sample `config.yaml` is back to conservative defaults:
  `query_db: "queries.db"` (SQLite logging on) and `api_listen:
  "127.0.0.1:8080"` (localhost only). A first-hardware deployment's
  `""` / `0.0.0.0:8080` working values had been committed by accident,
  which would have exposed the unauthenticated admin UI to the LAN out
  of the box.
- The CI lint job passes again after two stacked problems: the
  `golangci-lint-action@v6` pin installs golangci-lint v1, which
  cannot even load a `version: "2"` config targeting Go 1.25 (bumped
  to `@v8`, which installs v2); and once v2 actually runs, it lacks
  the v1-era default errcheck exclusions, flagging 40+ idiomatic
  best-effort calls. Restored a documented exclusion subset in
  `.golangci.yml`, made `Server.Shutdown` log listener errors instead
  of discarding them, and fixed `make tools-install` to install
  golangci-lint v2.
- `deploy/install-linux.sh` no longer advertises `http://<lan-ip>:8080`
  for the admin UI when `api_listen` is left at the localhost-only
  default; the shell-script counterpart of the T4 banner fix. It now
  reads `api_listen` from the installed config and prints either the
  LAN URLs or a localhost note with the opt-in instruction.
- README's Docker port-conflict note no longer recommends disabling
  `systemd-resolved` entirely (which kills host DNS resolution on
  distros where `resolv.conf` points at the stub); it now shows the
  `DNSStubListener=no` drop-in that releases port 53 while keeping the
  host resolver working.
- `cache_size: 0` in the YAML file now actually disables the DNS
  response cache, as documented. Previously the post-decode default
  silently turned 0 back into 2000; only the `S_HOLE_CACHE_SIZE=0` env
  override worked (T1). `block_ttl: 0` is likewise honored now: it
  tells clients not to cache sinkhole replies.
- Truncated upstream replies (TC bit) are retried over TCP against the
  same upstream before being returned, so large answers (DNSSEC, big
  TXT/CDN RRsets) resolve instead of dead-ending the client's TCP
  fallback at the forwarder. Truncated responses are also no longer
  cached (T2).
- The DNS response cache keys unknown record types as `TYPE1234`
  instead of an empty string, so two distinct unknown qtypes can no
  longer collide on one cache entry (T6).
- One overlong blocklist line (past bufio's default 64 KiB token cap)
  no longer aborts parsing of the entire list; the parser tolerates
  lines up to 1 MiB and keeps dropping garbage per-line as before (T5).
- The startup banner no longer advertises `http://<lan-ip>:8080` for
  the admin UI when `api_listen` is bound to localhost (the default);
  it prints `http://127.0.0.1:8080 (this machine only)` instead (T4).
- Integration test no longer relies on a hardcoded 150 ms sleep to
  wait for the SQLite flush tick; it polls for up to 2 s. Fast on
  healthy CI, robust under load.
- `reloadFn` defer order collapsed into a single closure so the
  mutex is released before the WaitGroup signals done, matching
  reader expectations.
- Counter.Snapshot data race: `topN` now reads the map pointer under
  the same mutex that protects the prune-and-reassign in
  `RecordQuery`. The race detector previously fired when prune and
  snapshot collided.
- `querylog.DBLogger.run()` no longer uses a magic literal `100` for
  the per-batch flush trigger; both the cap *and* the trigger now
  reference the same `flushBatchSize` constant.
- `panic` recovery in `runTickerOnce` now logs the full goroutine stack
  via `debug.Stack()` so a panic in the field is diagnosable from
  logs alone.
- `Dockerfile` no longer installs `tzdata` (~30 MB removed). Container
  logs default to UTC, which is what production wants.
- `SECURITY.md` now points reporters at the GitHub Security Advisories
  flow rather than a personal email.
- `CODEOWNERS` and `SECURITY.md` updated for the actual GitHub handle
  (`@lcsabi`).
- Module path renamed to `github.com/lcsabi/s-hole` to match the
  GitHub account. `go install` URL changed accordingly.
- `/api/whitelist` GET now returns domains in sorted order so the UI
  doesn't shuffle between refreshes.
- `json.Encoder.Encode` errors in `/api/*` responses are now logged
  rather than discarded (R10).
- `apiServer.Shutdown` errors during `doStop` are now logged (R11).
- `blocklist.fetchList` now escapes colons in cache filenames; the prior
  scheme could not be written or renamed on NTFS for URLs with embedded
  ports.

## [Initial implementation]

See the per-CL files under `cls/CL-01.md` through `cls/CL-10.md` for the
pre-changelog development log. `CL.md` is the index.
