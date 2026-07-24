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
| 6 | Hardening batch: goleak, govulncheck, empty-blocklist alarm | Medium | done (CL 29) |
| 7 | Windows service logging (slog is lost under the SCM) | Low | not started |
| 8 | Benchmark companions for the hot path | Low | blocked on #3 |
| 9 | Answer private-range PTR queries locally (RFC 6303) | Low | done (CL 27) |
| 10 | Blocklist size in `/api/stats` + dashboard | Medium | done (CL 28) |

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

## 6. Hardening batch (one CL) — done (CL 29)

- `go.uber.org/goleak` in `TestMain` for the goroutine-heavy packages
  (cache, querylog, dnsserver). The one new dependency worth waving
  through. **Done** — test-only dep; all three packages pass clean.
- `govulncheck` as a CI step. **Done** — standalone CI job plus a
  `make vuln` target.
- ~~Embedded fallback blocklist (`//go:embed`, ~1 000 core ad domains)
  so a first run with no network still filters something and
  `/readyz` can go green offline.~~ **Dropped in favor of an
  empty-blocklist alarm.** The offline-first-run scenario is vanishingly
  narrow — s-hole already needs network to forward queries at all, and
  the on-disk cache covers every restart after one successful download.
  A vendored list is stale on commit, carries licensing/provenance
  baggage, bloats the binary, and *masks* the "nothing loaded" problem
  instead of surfacing it. `blocklist.Update` now emits a loud WARN
  whenever the block set ends up empty (covering both the all-sources-
  failed path and the source-returned-200-but-parsed-to-zero path,
  which previously logged `total=0` at Info like a healthy refresh).

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

## 9. Answer private-range PTR queries locally

Observed during the 2026-07-12 VM deployment test: `nslookup` produces
three log entries per lookup, and the first is a **PTR** (reverse)
query for the *server's own* private IP (`18.100.168.192.in-addr.arpa`)
— nslookup resolves the server name for its output header before
asking the actual question. This is not tool-specific noise: OSes,
mail servers, and network monitors reverse-look-up private LAN
addresses constantly on a real network.

Today s-hole forwards these upstream like any other query. Three
reasons to answer them locally instead:

- **Privacy** — reverse queries for `192.168.x.x`/`10.x.x.x` leak the
  LAN's internal addressing to the upstream resolver for zero benefit;
  no public server can ever answer them.
- **Wasted round-trips** — the upstream answer is always NXDOMAIN, and
  the cache deliberately stores only NOERROR-with-answers responses
  (DESIGN.md, negative-caching note), so *every* private PTR pays a
  full upstream round-trip, forever.
- **Standard practice** — RFC 6303 (*Locally Served DNS Zones*) says
  resolvers SHOULD answer these zones locally; unbound, dnsmasq, and
  systemd-resolved all do.

Sketch: in the handler, before the blocklist check, match PTR queries
whose name falls under the RFC 6303 zones (`10.in-addr.arpa`,
`16.172.in-addr.arpa`–`31.172.in-addr.arpa`, `168.192.in-addr.arpa`,
plus IPv6 ULA `d.f.ip6.arpa` and link-local) and return authoritative
NXDOMAIN immediately — a static suffix match, no config, no new
dependencies, hot-path cost one label comparison for non-PTR queries.

Decisions to settle in the CL: NXDOMAIN vs NODATA; whether the reply
counts as "blocked" in stats (probably neither — a third "local"
outcome, or simply uncounted); whether a config escape hatch is needed
for LANs that *do* run an internal reverse zone (likely
`local_ptr: true` default with opt-out, or defer the knob until
someone asks). Rated Low: invisible to the user, but removes constant
upstream chatter and an information leak.

## 10. Blocklist size in `/api/stats` + dashboard

Companion to the Cache Hit Rate card (CL 25), which was free because
the field already rode in the stats payload. Blocklist size is the
next most useful number the dashboard cannot show: "78 469 domains" is
the at-a-glance trust signal that the lists downloaded, parsed, and
survived the last refresh — today it is visible only in `/metrics`
(`shole_blocklist_size`) and the startup log line.

Unlike CL 25 this touches Go: `store.Len()` must join the
`/api/stats` response (either plumbed into `stats.Snapshot` or added
in the API handler, which already holds the `*blocklist.Store` for
`/readyz` — the handler is the lighter touch). Then a fifth display
element in the UI; five stat cards may crowd the row, so consider a
header chip next to uptime instead. Sync the `/api/stats` description
in README/DESIGN if the payload shape is documented at the time.
Rated Medium by the impact rubric (observability win): the number
builds operator trust but changes no filtering behaviour.

## Pending decisions

- **Sample config `query_db` / `api_listen`** — uncommitted
  working-tree edits (deliberate, for the first-hardware deployment)
  set `query_db: ""` (SQLite logging off) and
  `api_listen: "0.0.0.0:8080"` (LAN dashboard) while the committed
  sample says `queries.db` / `127.0.0.1:8080`. Decide which values the
  sample ships with and sync the README rows. Notes: with the DB off,
  the dashboard's recent-queries panel is empty; the localhost
  `api_listen` default is a security posture (unauthenticated UI), so
  shipping `0.0.0.0` would need a SECURITY.md-consistent justification.

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
- **Live application-log panel in the web UI** — ~90 % redundant with
  the recent-queries panel, which already renders the
  timestamp/client/domain/blocked content of the `ALLOW`/`BLOCK`
  stream once `query_db` is enabled. The remainder is operational slog
  lines (refresh results, upstream errors), which matter during
  incidents where `journalctl` is the better tool. Building it would
  require an in-memory log ring buffer plus a new `/api/logs` endpoint
  (the process does not retain its own stdout — journald owns it), and
  exposing operational internals on the unauthenticated UI sits on the
  pprof end of the disclosure gradient: if ever revisited, it must be
  opt-in like `enable_pprof`.
