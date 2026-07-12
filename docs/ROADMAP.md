# Roadmap

Forward-looking collection of recommended improvements, additions, and
pending decisions. Items came out of the staff-review rounds (R/S/T)
and working sessions; each should land as a CL when picked up. This
file records *intent and rationale* — the durable record of what
actually changed stays in `CL.md` / `CHANGELOG.md`.

Impact gauges the value delivered, not the effort required — effort
estimates are deliberately omitted. **High** = user-visible filtering,
distribution, or validation wins; **Medium** = robustness,
observability, or niche-deployment wins; **Low** = hygiene and guard
rails.

| # | Item | Impact | Status |
|--:|---|---|---|
| 1 | Deploy to real hardware (Raspberry Pi) | High | procedure validated in a VM; awaiting hardware |
| 2 | Tag `v0.1.0` + release workflow | High | not started |
| 3 | Wildcard / subdomain blocking | High | not started |
| 4 | Wire up or delete `DBLogger.TopBlocked` | Medium | not started |
| 5 | DNS-over-HTTPS upstream support | Medium | not started |
| 6 | Hardening batch: goleak, govulncheck, embedded fallback blocklist | Medium | not started |
| 7 | Windows service logging (slog is lost under the SCM) | Low | not started |
| 8 | Benchmark companions for the hot path | Low | blocked on #3 |

## 1. Deploy to real hardware

Not a code change — the validation step everything else feeds on.
Cross-compile (`make pi` / `make pi32`), `scp` binary + config +
`deploy/install-linux.sh`, run the installer, verify with the
CONTRIBUTING smoke test, then point the router's DHCP DNS at it (see
the README's IPv6-networks note for the RA/RDNSS bypass trap). Give
the machine a static IP / DHCP reservation first. A few days of real
LAN traffic is the qualification gate for #2.

**2026-07-12:** the full procedure was rehearsed on a VirtualBox
Debian 12 VM (amd64 build, bridged networking) — installer, systemd
unit, blocklist load (78 469 domains), LAN probes, block/allow/cache
verification from another machine, SIGHUP reload, and
restart-from-cached-blocklists all passed; SQLite layer deliberately
disabled (`query_db: ""`). What remains is a replay on ARM hardware
(`make pi`) plus the router cut-over and the multi-day soak, so the
item stays open until a Raspberry Pi is available.

## 2. Tag `v0.1.0` + release workflow

CI already cross-compiles all four targets and throws the binaries
away. Add `.github/workflows/release.yml` triggered on tag push:
build the matrix with the version-injecting ldflags, attach the
binaries to a GitHub Release, optionally push a Docker image to
ghcr.io. Then cut `v0.1.0` — ideally pointing at a commit that has
survived #1. Unlocks versioned bug reports (`s-hole -version` stops
saying `dev`) and graduates the CHANGELOG's `[Unreleased]` section.

## 3. Wildcard / subdomain blocking

The biggest real filtering gap: blocking `ads.example.com` does not
block `x.ads.example.com` (the test suite pins this as intended
behaviour today). Trackers rotate subdomains to exploit exact-match
blockers. Sketch: in `Store.IsBlocked`, walk the parent labels
(`a.b.c.com` → `b.c.com` → `c.com`) — O(labels) map lookups, no new
data structure. `BenchmarkStore_IsBlocked` exists precisely to prove
the walk doesn't regress the hot path. Design decision to settle in
the CL: the whitelist should get the same suffix semantics, with
whitelist-wins at every level.

## 4. Wire up or delete `DBLogger.TopBlocked`

`TopBlocked` has been exported, context-aware, and unit-tested since
CL 2 — and no handler has ever called it. Meanwhile the dashboard's
"Top Blocked Domains" panel uses the in-memory stats counter, which
resets on restart and prunes at 4 096 entries. Either add
`GET /api/top-blocked?limit=N` plus a dashboard toggle ("since start"
vs "all time"), or delete the method — the same dead-exported-code
reasoning S1 applied to `version.Short`. Current limbo is the worst
option.

## 5. DNS-over-HTTPS upstream support

DESIGN open question #1; the answer to ISPs that intercept plain
port-53 traffic. Needs **zero new dependencies**: DoH is POSTing the
wire-format query (miekg/dns already packs it) over `net/http`. Slots
into the `exchange()` helper as a third transport; the upstream
cooldown tracker works unchanged because upstreams are just strings
(`https://…` alongside `1.1.1.1:53`). The complexity hides in the
details: timeout semantics, connection reuse, bootstrap resolution of
the DoH hostname itself. Impact is Medium rather than High because
plain-DNS interception is an ISP-specific problem — many home LANs
never hit it.

## 6. Hardening batch (one CL)

- `go.uber.org/goleak` in `TestMain` for the goroutine-heavy packages
  (cache, querylog, dnsserver). The one new dependency worth waving
  through.
- `govulncheck` as a CI step.
- Embedded fallback blocklist (`//go:embed`, ~1 000 core ad domains)
  so a first run with no network still filters something and
  `/readyz` can go green offline.

## 7. Windows service logging

A Windows service process has no console, so the stdout-bound slog
stream vanishes under the SCM — startup errors and refresh failures
are simply lost. The query log survives only if `log_file` is set.
Route slog to a file (or the Windows Event Log) when
`service.IsWindowsService()` is true. Linux/systemd is unaffected
(journald captures stdout). Rated Low while the primary deployment
target is a Linux/Pi box; promote it if the Windows service becomes a
first-class use case.

## 8. Benchmark companions

Deliberately deferred until #3 lands: `BenchmarkCache_Get` and
`BenchmarkHandler_ServeDNS` (stub ResponseWriter) alongside the
existing `BenchmarkStore_IsBlocked`. Benchmarks nobody watches are
suite weight; these earn their place the day the hot path changes.

## Pending decisions

- **Sample config `query_db`** — an uncommitted working-tree edit sets
  `query_db: ""` (SQLite logging off) while the committed sample and
  README table say `queries.db` (on). Decide which the sample ships
  with and sync the README row. Note: with it off, the dashboard's
  recent-queries panel is empty by default.

## Deliberately not planned

Recorded so future reviews don't re-propose them; each trades the
"auditable in an afternoon" identity for features better served by
Pi-hole/AdGuard Home:

- **Admin API authentication** — LAN-trust is a documented scope
  decision (SECURITY.md, DESIGN open question #6). Half-hearted auth
  would imply a security property the unauthenticated design doesn't
  have; the localhost-only default is the mitigation.
- **Per-client policies / client groups.**
- **LRU cache eviction** — drop-on-full is a documented simplicity
  trade-off, fine at home-network scale.
- **Pluggable blocklist formats/backends.**
- **Web UI redesign / SPA framework.**
- **Config-exposed dashboard poll rate** — the UI is a static
  `go:embed` file; plumbing config into it costs more than the knob
  is worth. If a knob is ever wanted: a `?refresh=` URL parameter in
  the JS, client-side only.
- **Tuning knobs for `flushBatchSize` / `queryQueueSize`** — per the
  in-code rationale: changing them without a benchmark is unlikely to
  help.
- **Deduplicating the on-disk blocklist caches** — per-URL verbatim
  snapshots are load-bearing: the stale-fallback contract is per-list,
  and an untransformed copy is inspectable evidence when a source
  misbehaves. The in-memory set already deduplicates for free; disk
  savings would be a few hundred KB once per day.
