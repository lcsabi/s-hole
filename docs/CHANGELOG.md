# Changelog

All notable changes to s-hole are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project loosely
tracks [Semantic Versioning](https://semver.org/) once the first tagged
release ships. Detailed CL descriptions live in `CL.md`; this file is the
operator-facing summary.

## [Unreleased]

### Added
- Production-grade project layout: the `main` package now lives under
  `cmd/s-hole/`; `DESIGN.md`, `CL.md`, `BUGS.md`, and `CHANGELOG.md`
  live under `docs/`. The `go install` path is now
  `github.com/laszlo/s-hole/cmd/s-hole@latest`.
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
- `json.Encoder.Encode` errors in `/api/*` responses are now logged
  rather than discarded (R10).
- `apiServer.Shutdown` errors during `doStop` are now logged (R11).
- `blocklist.fetchList` now escapes colons in cache filenames; the prior
  scheme could not be written or renamed on NTFS for URLs with embedded
  ports.

## [Initial implementation]

See `CL.md` for CL 1 through CL 10 — the pre-changelog development log.
