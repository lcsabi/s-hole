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
| 3 | Wildcard / subdomain blocking | High | done (CL 30) |
| 4 | Wire up or delete `DBLogger.TopBlocked` | Medium | done (CL 33) |
| 5 | DNS-over-HTTPS upstream support | Medium | not started |
| 6 | Hardening batch: goleak, govulncheck, empty-blocklist alarm | Medium | done (CL 29) |
| 7 | Windows service logging (slog is lost under the SCM) | Low | not started |
| 8 | Benchmark companions for the hot path | Low | done (CL 32) |
| 9 | Answer private-range PTR queries locally (RFC 6303) | Low | done (CL 27) |
| 10 | Blocklist size in `/api/stats` + dashboard | Medium | done (CL 28) |
| 11 | Install script prints the installed version/commit | Low | done (CL 35) |
| 12 | `uninstall-linux.sh` companion to the installer | Low | not started |
| 13 | Persist runtime whitelist across restarts | Medium | not started |

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

## 3. Wildcard / subdomain blocking — done (CL 30)

The biggest real filtering gap: blocking `ads.example.com` did not
block `x.ads.example.com`. Trackers rotate subdomains to exploit
exact-match blockers. **Shipped in CL 30:** `Store.IsBlocked` now walks
the parent labels (`a.b.c.com` → `b.c.com` → `c.com`) — O(labels) map
lookups, no new data structure, no per-query allocation.
`BenchmarkStore_IsBlocked` proved the walk doesn't regress the hot path
and gained a `_Miss` companion for the allowed-query worst case.

Design decisions settled in the CL:

- **Whitelist gets the same suffix semantics, whitelist-wins at every
  level** (global precedence, not most-specific-wins): if the queried
  name or any parent is whitelisted, the query is allowed even past a
  more specific blocked parent. This is what makes the whitelist a
  clean escape hatch for an over-broad block entry.
- **No config knob to restore exact-match.** Exact-match was a
  documented *gap*, not a feature; a global switch would only preserve
  the subdomain-rotation hole. The suffix-aware whitelist is the
  per-domain escape hatch, so no `config.yaml` change was needed.

## 4. Wire up or delete `DBLogger.TopBlocked` — done (CL 33)

`TopBlocked` had been exported, context-aware, and unit-tested since
CL 2 — and no handler ever called it. Meanwhile the dashboard's "Top
Blocked Domains" panel used the in-memory stats counter, which resets on
restart and prunes at 4 096 entries. **CL 33 chose wire-up over
deletion:** `GET /api/top-blocked?limit=N` serves the persistent SQLite
tally, and the panel gained a "Since start / All time" toggle (default
"Since start", so the `query_db`-off deployment is unchanged). The
db-disabled path returns an empty list, matching `/api/queries`.

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

## 8. Benchmark companions — done (CL 32)

Was deferred until #3 lands; #3 landed (CL 30) and added
`BenchmarkStore_IsBlocked_Miss` — the suffix walk's worst case (a deep
allowed query that walks every label). **CL 32 closed the rest:**
`BenchmarkCache_Get` (the hit path — the `msg.Copy` + `decrementTTLs`
cost that `ReportAllocs` guards) and `BenchmarkHandler_ServeDNS` with
`Blocked`/`Cached` sub-benchmarks driven through the stub
`ResponseWriter`. The forwarding path is left unbenchmarked on purpose:
it is bounded by the upstream round-trip, not handler code, and cannot
be measured without a network stub. The four hot-path benchmarks now
cover the whole in-process chain — blocklist decision → cache lookup →
request routing — and `make bench` runs each once as a regression
smoke.

## 9. Answer private-range PTR queries locally — done (CL 27)

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

**Shipped in CL 27:** `Handler.ServeDNS` matches PTR queries whose name
falls under the RFC 6303 zones (`10.in-addr.arpa`,
`16.172.in-addr.arpa`–`31.172.in-addr.arpa`, `168.192.in-addr.arpa`,
plus IPv6 ULA and link-local) *before* the blocklist check and returns
authoritative NXDOMAIN immediately — a static suffix match
(`privateReverseZones`/`isPrivatePTR`), no new dependency, hot-path cost
one label comparison for non-PTR queries.

Decisions settled in the CL:

- **NXDOMAIN, not NODATA** — the authoritative "no such name" answer.
- **Counted as a distinct "local" outcome, never "blocked"** —
  `Counter.RecordLocalPTR` feeds `local_ptr_count` in `/api/stats` and
  `shole_local_ptr_total` in `/metrics`, and the reply is excluded from
  the cache-hit denominator.
- **`local_ptr` config flag, default `true` with opt-out** (env
  `S_HOLE_LOCAL_PTR`) for LANs that run their own internal reverse zone.

Rated Low: invisible to the user, but removes constant upstream chatter
and an information leak.

## 10. Blocklist size in `/api/stats` + dashboard — done (CL 28)

Companion to the Cache Hit Rate card (CL 25), which was free because
the field already rode in the stats payload. Blocklist size is the
next most useful number the dashboard could not show: "78 469 domains"
is the at-a-glance trust signal that the lists downloaded, parsed, and
survived the last refresh — before CL 28 it was visible only in
`/metrics` (`shole_blocklist_size`) and the startup log line.

**Shipped in CL 28:** `store.Len()` joins the `/api/stats` response via
the API handler (`handleStats` sets `snap.BlocklistSize` — the lighter
touch, since the handler already holds the `*blocklist.Store` for
`/readyz`, so `stats.Snapshot` stayed untouched), surfaced as a fifth
"Blocklist Size" stat card on the dashboard. The `/api/stats`
descriptions in README/DESIGN were synced with the new payload field.
Rated Medium by the impact rubric (observability win): the number
builds operator trust but changes no filtering behaviour.

## 11. Install script prints the installed version/commit — done (CL 35)

`deploy/install-linux.sh` never echoed which build it just installed, so a
stale-binary deploy was silent: the operator `scp`s a binary, runs the
installer, and has no signal that the running service predates the fix they
meant to ship. This bit a real deployment — a pre-CL-30 binary was live on a
VM, so subdomain blocking (CL 30) appeared broken until `s-hole -version`
revealed the old commit.

**Shipped in CL 35:** the installer captures `"$INSTALL_BIN" -version` right
after `install`-ing the binary (before `systemctl start`) and prints an
"Installed build" box — version, commit, build date — as its final
confirmation, above the router-setup block. The identity is already embedded
via the `make` ldflags (`internal/version`); a plain `go build` without them
prints the `dev`/`unknown` placeholders, and a binary that produces no
`-version` output falls back to a "could not read version" line. No runtime
behaviour changed — pure deploy-time guard rail — but it turns an invisible
class of mistake into an obvious one. The README install section now points
the operator at the printed build to confirm.

## 12. `uninstall-linux.sh` companion to the installer

`deploy/install-linux.sh` has no counterpart, so removing s-hole is a manual,
error-prone sequence: stop and disable the unit, delete the unit file and
`daemon-reload`, remove the binary, `/etc/s-hole`, `/var/lib/s-hole`, and the
`s-hole` system user/group. A shipped installer with no uninstaller is an
asymmetry an operator (and a reviewer) notices. Add `deploy/uninstall-linux.sh`
that reverses the install in the correct order, with:

- **A `--purge` flag** that also removes `/var/lib/s-hole` (blocklist caches and
  the query DB). Without it, leave operator data in place.
- **Optional restoration of stock DNS resolution.** If s-hole's deployment (or
  the operator) disabled the `systemd-resolved` stub listener to free port 53
  (the `DNSStubListener=no` drop-in), offer to remove that drop-in and restart
  `systemd-resolved` — but only when the drop-in is actually present, and behind
  a prompt/flag, since it is a system-wide change the operator may have made
  independently of s-hole.
- **The same reporting courtesy as the installer** — print what was removed.

Rated Low: deploy-time hygiene, no runtime behaviour. It closes the
install/uninstall asymmetry and heads off a real confusion the installer can
cause — because it never overwrites an existing `/etc/s-hole/config.yaml`, a
stale config left behind by a prior install silently shadows a freshly copied
one until it is removed (documented in the README deployment notes).

## 13. Persist runtime whitelist across restarts

The whitelist is two-tier today: declarative entries in `config.yaml` (re-read
on every startup) and runtime entries added via the dashboard or
`POST /api/whitelist` (in-memory only, lost on restart — see
`store.AddToWhitelist`). An operator who whitelists a domain from the UI and
later restarts the service is surprised when it re-blocks. Persist runtime
additions so they survive a restart.

Design decisions to settle in the CL:

- **A separate store, not a `config.yaml` rewrite.** The API must not edit
  `config.yaml` — it carries comments, formatting, and is frequently managed by
  version control or config management. Persist runtime entries to a dedicated
  file in the data dir (e.g. `/var/lib/s-hole/whitelist.json`, atomic
  temp-and-rename like the blocklist cache), **independent of `query_db`** so
  whitelist persistence never depends on the query log being enabled. A plain,
  inspectable, hand-editable file also keeps the "auditable in an afternoon"
  property.
- **Effective whitelist = config entries ∪ persisted runtime entries**, merged
  into the store at startup.
- **Removal must be persistent, and its semantics differ by source.**
  `DELETE /api/whitelist` has to remove the entry from the *persistent* runtime
  store, not just the in-memory map — otherwise a deleted entry reappears on the
  next restart, which is a broken half-feature. A **config-sourced** entry,
  however, cannot be removed via the API without rewriting `config.yaml` (which
  we won't do): a `DELETE` on such an entry should be **rejected with a clear
  message** ("defined in config.yaml — edit the config to remove it") rather
  than silently no-op'ing or resurrecting on restart. The whitelist list
  responses should expose each entry's source (config vs runtime) so the UI can
  disable delete on config entries.
- **Blocklist precedence is unchanged** — the whitelist still wins globally and
  suffix-aware (CL 30).

Rated Medium: a user-visible robustness win (the whitelist behaves the way
operators expect across restarts) that changes no filtering semantics.

## Pending decisions

- _None open._ (Resolved: the shipped sample `config.yaml` was restored
  to the conservative `query_db: "queries.db"` / `api_listen:
  "127.0.0.1:8080"` after `0.0.0.0`/SQLite-off values were accidentally
  committed with CL 27 — the unauthenticated admin UI should not ship
  LAN-exposed. The README config table documents the *code* defaults,
  which are `api_listen` `127.0.0.1:8080` and `query_db` off.)

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
