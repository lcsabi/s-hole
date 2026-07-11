# Changelog

All notable changes to s-hole are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project loosely
tracks [Semantic Versioning](https://semver.org/) once the first tagged
release ships. Detailed per-CL descriptions live under `cls/`, indexed by
`CL.md`; this file is the operator-facing summary.

## [Unreleased]

### Fixed
- `deploy/install-linux.sh` no longer advertises `http://<lan-ip>:8080`
  for the admin UI when `api_listen` is left at the localhost-only
  default — the shell-script counterpart of the T4 banner fix. It now
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
  override worked (T1). `block_ttl: 0` is likewise honored now — it
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
  the admin UI when `api_listen` is bound to localhost (the default) —
  it prints `http://127.0.0.1:8080 (this machine only)` instead (T4).

### Changed
- The admin dashboard polls `/api/stats` and `/api/queries` every 3
  seconds (was 5) for a snappier live view.
- `/api/queries` clamps `?limit=` to 1000 so one request cannot
  marshal the entire history table into a single JSON response (T3).

### Added
- `CONTRIBUTING.md` documents a seven-step manual smoke-test workflow
  (probes → DNS behaviour → dashboard → whitelist round-trip → reload
  → stats/metrics cross-check → persistence + shutdown) for release
  verification.
- `runTicker` now honors a context for clean shutdown — background
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
- `shole_query_log_dropped_total` metric and `DBLogger.Dropped()` —
  operators now see when the query log channel overflows under load.
- `Store.WhitelistLen()` — O(1) counterpart to `Len()` for the
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
  Hand-rolled exposition format — no new dependencies.
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
- Atomic blocklist cache writes via `.tmp` + rename — torn writes
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
- DESIGN's "Alternatives Considered" no longer claims Windows is the
  first-class platform. Linux is the primary deployment target; the
  Windows SCM path is the secondary supported platform.
- Default `api_listen` is now `127.0.0.1:8080` — operators who want
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
- Integration test no longer relies on a hardcoded 150 ms sleep to
  wait for the SQLite flush tick — it polls for up to 2 s. Fast on
  healthy CI, robust under load.
- `reloadFn` defer order collapsed into a single closure so the
  mutex is released before the WaitGroup signals done, matching
  reader expectations.
- Counter.Snapshot data race: `topN` now reads the map pointer under
  the same mutex that protects the prune-and-reassign in
  `RecordQuery`. The race detector previously fired when prune and
  snapshot collided.
- `querylog.DBLogger.run()` no longer uses a magic literal `100` for
  the per-batch flush trigger — both the cap *and* the trigger now
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
