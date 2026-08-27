# Roadmap

Forward-looking collection of recommended improvements, additions, and
pending decisions. Items came out of the staff-review rounds (R/S/T)
and working sessions; each should land as a CL when picked up. This
file records *intent and rationale*; the durable record of what
actually changed stays in `CL.md` / `CHANGELOG.md`.

Impact gauges the value delivered, not the effort required; effort
estimates are deliberately omitted. **High** = user-visible filtering,
distribution, or validation wins; **Medium** = robustness,
observability, or niche-deployment wins; **Low** = hygiene and guard
rails.

| # | Item | Impact | Status |
|--:|---|---|---|
| 1 | Deploy to real hardware (Raspberry Pi) | High | procedure validated in a VM; awaiting hardware |
| 2 | Tag `v0.1.0` + release workflow | High | done (CL 43, CL 44); v0.1.0 tagged 2026-08-24 |
| 3 | Wildcard / subdomain blocking | High | done (CL 30) |
| 4 | Wire up or delete `DBLogger.TopBlocked` | Medium | done (CL 33) |
| 5 | DNS-over-HTTPS upstream support | Medium | not started |
| 6 | Hardening batch: goleak, govulncheck, empty-blocklist alarm | Medium | done (CL 29) |
| 7 | Windows service logging (slog is lost under the SCM) | Low | not started |
| 8 | Benchmark companions for the hot path | Low | done (CL 32) |
| 9 | Answer private-range PTR queries locally (RFC 6303) | Low | done (CL 27) |
| 10 | Blocklist size in `/api/stats` + dashboard | Medium | done (CL 28) |
| 11 | Install script prints the installed version/commit | Low | done (CL 35) |
| 12 | `uninstall-linux.sh` companion to the installer | Low | done (CL 40) |
| 13 | Persist runtime whitelist across restarts | Medium | not started |
| 14 | CNAME deep-inspection (block cloaked trackers) | Medium | not started |
| 15 | Local DNS records (host overrides) | High | not started |
| 16 | Conditional / split-horizon forwarding | Medium | not started |
| 17 | Per-source blocklist health in `/api/stats` + dashboard | Medium | done (CL 55) |
| 18 | "Why is this blocked?" diagnostic endpoint (`/api/check`) | Low | done (CL 56) |
| 19 | Temporary "pause blocking" (timed bypass, auto-resume) | High | not started |
| 20 | Query-volume-over-time graph on the dashboard | Medium | not started |
| 21 | Query-log privacy modes (write-time client anonymization) | Medium | not started |
| 22 | Client name attribution in the log and dashboard | Medium | not started |
| 23 | Query-log search / filter | Medium | not started |
| 24 | Query-log export (CSV / JSON) | Medium | not started |
| 25 | Regex / pattern blocking | High | not started |
| 26 | Grafana dashboard + Prometheus scrape/alert examples | Low | not started |

Items 19-26 came out of a 2026-08-24 feature-ideas session. Items 21-24 are a
dependent group: #21 (privacy) sets the write-time masked row that #22, #23, and
#24 all read, so #21 must land first. The order below is the recommended
implementation order, not the item-number order.

## 1. Deploy to real hardware

Not a code change, but the validation step everything else feeds on.
Cross-compile (`make pi` / `make pi32`), `scp` binary + config +
`deploy/install-linux.sh`, run the installer, verify with the
CONTRIBUTING smoke test, then point the router's DHCP DNS at it (see
the README's IPv6-networks note for the RA/RDNSS bypass trap). Give
the machine a static IP / DHCP reservation first. A few days of real
LAN traffic is the confidence gate for running a release on real hardware.
(`v0.1.0` was tagged ahead of this soak on 2026-08-24, on the strength of the
release dry-runs under #2; the soak stays open here until a Raspberry Pi is
available.)

**2026-07-12:** the full procedure was rehearsed on a VirtualBox
Debian 12 VM (amd64 build, bridged networking): installer, systemd
unit, blocklist load (78 469 domains), LAN probes, block/allow/cache
verification from another machine, SIGHUP reload, and
restart-from-cached-blocklists all passed; SQLite layer deliberately
disabled (`query_db: ""`). What remains is a replay on ARM hardware
(`make pi`) plus the router cut-over and the multi-day soak, so the
item stays open until a Raspberry Pi is available.

## 2. Tag `v0.1.0` + release workflow (done, CL 43 and CL 44)

CI already cross-compiled all four targets and threw the binaries away.
**Shipped in CL 43:** `.github/workflows/release.yml` triggers on a `v*`
tag push and builds the matrix with the version-injecting ldflags (the
tag name is the version, so no `dev` placeholder). It attaches a
per-target archive (`tar.gz` for Linux, `zip` for Windows, each bundling
the binary, `config.yaml`, `LICENSE`, `README.md`, and the Linux deploy
scripts) plus a `SHA256SUMS` file to a GitHub Release, and pushes a
multi-arch (amd64 + arm64) image to `ghcr.io/lcsabi/s-hole`.

Design decisions settled in the CL:

- **`gh release create`, not a third-party release action.** The `gh`
  CLI is preinstalled on the runner, so the release step needs no new
  action dependency, matching the project's dependency-minimalism.
- **`:latest` moves only for final tags.** A pre-release tag (one with a
  `-` suffix, e.g. `v0.1.0-rc1`) is published with `--prerelease` and
  does not move the `:latest` image, so an rc can be validated without
  becoming the default pull.

The CL also graduated the CHANGELOG's `[Unreleased]` section to `[0.1.0]`.

**2026-08-24:** `v0.1.0` was tagged and pushed (commit `59c5212`). The workflow
produced the first GitHub Release (four archives plus `SHA256SUMS`, notes drawn
from the `[0.1.0]` CHANGELOG section) and the first multi-arch
`ghcr.io/lcsabi/s-hole` image, and moved `:latest` to it. A `v0.1.0-rc1`
dry-run first surfaced a bug in the release-notes extractor (a pre-release tag
did not resolve its base CHANGELOG section, so the notes fell back to a
placeholder); CL 44 fixed it and a `v0.1.0-rc2` dry-run confirmed the fix before
the final tag. The tag was cut ahead of the #1 hardware soak. The release
machinery was validated on its own through the rc dry-runs, so any issue the
soak surfaces later ships as `v0.1.1`.

## 3. Wildcard / subdomain blocking (done, CL 30)

The biggest real filtering gap: blocking `ads.example.com` did not
block `x.ads.example.com`. Trackers rotate subdomains to exploit
exact-match blockers. **Shipped in CL 30:** `Store.IsBlocked` now walks
the parent labels (`a.b.c.com` → `b.c.com` → `c.com`), with O(labels) map
lookups, no new data structure, and no per-query allocation.
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

## 4. Wire up or delete `DBLogger.TopBlocked` (done, CL 33)

`TopBlocked` had been exported, context-aware, and unit-tested since
CL 2, and no handler ever called it. Meanwhile the dashboard's "Top
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
plain-DNS interception is an ISP-specific problem; many home LANs
never hit it.

## 6. Hardening batch, one CL (done, CL 29)

- `go.uber.org/goleak` in `TestMain` for the goroutine-heavy packages
  (cache, querylog, dnsserver). The one new dependency worth waving
  through. **Done.** Test-only dep; all three packages pass clean.
- `govulncheck` as a CI step. **Done.** Standalone CI job plus a
  `make vuln` target.
- ~~Embedded fallback blocklist (`//go:embed`, ~1 000 core ad domains)
  so a first run with no network still filters something and
  `/readyz` can go green offline.~~ **Dropped in favor of an
  empty-blocklist alarm.** The offline-first-run scenario is vanishingly
  narrow: s-hole already needs network to forward queries at all, and
  the on-disk cache covers every restart after one successful download.
  A vendored list is stale on commit, carries licensing/provenance
  baggage, bloats the binary, and *masks* the "nothing loaded" problem
  instead of surfacing it. `blocklist.Update` now emits a loud WARN
  whenever the block set ends up empty (covering both the all-sources-
  failed path and the source-returned-200-but-parsed-to-zero path,
  which previously logged `total=0` at Info like a healthy refresh).

## 7. Windows service logging

A Windows service process has no console, so the stdout-bound slog
stream vanishes under the SCM, so startup errors and refresh failures
are simply lost. The query log survives only if `log_file` is set.
Route slog to a file (or the Windows Event Log) when
`service.IsWindowsService()` is true. Linux/systemd is unaffected
(journald captures stdout). Rated Low while the primary deployment
target is a Linux/Pi box; promote it if the Windows service becomes a
first-class use case.

## 8. Benchmark companions (done, CL 32)

Was deferred until #3 lands; #3 landed (CL 30) and added
`BenchmarkStore_IsBlocked_Miss`, the suffix walk's worst case (a deep
allowed query that walks every label). **CL 32 closed the rest:**
`BenchmarkCache_Get` (the hit path, the `msg.Copy` + `decrementTTLs`
cost that `ReportAllocs` guards) and `BenchmarkHandler_ServeDNS` with
`Blocked`/`Cached` sub-benchmarks driven through the stub
`ResponseWriter`. The forwarding path is left unbenchmarked on purpose:
it is bounded by the upstream round-trip, not handler code, and cannot
be measured without a network stub. The four hot-path benchmarks now
cover the whole in-process chain (blocklist decision → cache lookup →
request routing), and `make bench` runs each once as a regression
smoke.

## 9. Answer private-range PTR queries locally (done, CL 27)

Observed during the 2026-07-12 VM deployment test: `nslookup` produces
three log entries per lookup, and the first is a **PTR** (reverse)
query for the *server's own* private IP (`18.100.168.192.in-addr.arpa`),
because nslookup resolves the server name for its output header before
asking the actual question. This is not tool-specific noise: OSes,
mail servers, and network monitors reverse-look-up private LAN
addresses constantly on a real network.

Today s-hole forwards these upstream like any other query. Three
reasons to answer them locally instead:

- **Privacy.** Reverse queries for `192.168.x.x`/`10.x.x.x` leak the
  LAN's internal addressing to the upstream resolver for zero benefit;
  no public server can ever answer them.
- **Wasted round-trips.** The upstream answer is always NXDOMAIN, and
  the cache deliberately stores only NOERROR-with-answers responses
  (DESIGN.md, negative-caching note), so *every* private PTR pays a
  full upstream round-trip, forever.
- **Standard practice.** RFC 6303 (*Locally Served DNS Zones*) says
  resolvers SHOULD answer these zones locally; unbound, dnsmasq, and
  systemd-resolved all do.

**Shipped in CL 27:** `Handler.ServeDNS` matches PTR queries whose name
falls under the RFC 6303 zones (`10.in-addr.arpa`,
`16.172.in-addr.arpa`–`31.172.in-addr.arpa`, `168.192.in-addr.arpa`,
plus IPv6 ULA and link-local) *before* the blocklist check and returns
authoritative NXDOMAIN immediately via a static suffix match
(`privateReverseZones`/`isPrivatePTR`), no new dependency, hot-path cost
one label comparison for non-PTR queries.

Decisions settled in the CL:

- **NXDOMAIN, not NODATA.** The authoritative "no such name" answer.
- **Counted as a distinct "local" outcome, never "blocked".**
  `Counter.RecordLocalPTR` feeds `local_ptr_count` in `/api/stats` and
  `shole_local_ptr_total` in `/metrics`, and the reply is excluded from
  the cache-hit denominator.
- **`local_ptr` config flag, default `true` with opt-out** (env
  `S_HOLE_LOCAL_PTR`) for LANs that run their own internal reverse zone.

Rated Low: invisible to the user, but removes constant upstream chatter
and an information leak.

## 10. Blocklist size in `/api/stats` + dashboard (done, CL 28)

Companion to the Cache Hit Rate card (CL 25), which was free because
the field already rode in the stats payload. Blocklist size is the
next most useful number the dashboard could not show: "78 469 domains"
is the at-a-glance trust signal that the lists downloaded, parsed, and
survived the last refresh; before CL 28 it was visible only in
`/metrics` (`shole_blocklist_size`) and the startup log line.

**Shipped in CL 28:** `store.Len()` joins the `/api/stats` response via
the API handler (`handleStats` sets `snap.BlocklistSize`, the lighter
touch, since the handler already holds the `*blocklist.Store` for
`/readyz`, so `stats.Snapshot` stayed untouched), surfaced as a fifth
"Blocklist Size" stat card on the dashboard. The `/api/stats`
descriptions in README/DESIGN were synced with the new payload field.
Rated Medium by the impact rubric (observability win): the number
builds operator trust but changes no filtering behaviour.

## 11. Install script prints the installed version/commit (done, CL 35)

`deploy/install-linux.sh` never echoed which build it just installed, so a
stale-binary deploy was silent: the operator `scp`s a binary, runs the
installer, and has no signal that the running service predates the fix they
meant to ship. This bit a real deployment: a pre-CL-30 binary was live on a
VM, so subdomain blocking (CL 30) appeared broken until `s-hole -version`
revealed the old commit.

**Shipped in CL 35:** the installer captures `"$INSTALL_BIN" -version` right
after `install`-ing the binary (before `systemctl start`) and prints an
"Installed build" box (version, commit, build date) as its final
confirmation, above the router-setup block. The identity is already embedded
via the `make` ldflags (`internal/version`); a plain `go build` without them
prints the `dev`/`unknown` placeholders, and a binary that produces no
`-version` output falls back to a "could not read version" line. No runtime
behaviour changed (it is a pure deploy-time guard rail), but it turns an invisible
class of mistake into an obvious one. The README install section now points
the operator at the printed build to confirm.

## 12. `uninstall-linux.sh` companion to the installer (done, CL 40)

`deploy/install-linux.sh` had no counterpart, so removing s-hole was a manual,
error-prone sequence: stop and disable the unit, delete the unit file and
`daemon-reload`, remove the binary, `/etc/s-hole`, `/var/lib/s-hole`, and the
`s-hole` system user/group. A shipped installer with no uninstaller is an
asymmetry an operator (and a reviewer) notices.

**Shipped in CL 40:** `deploy/uninstall-linux.sh` reverses the install in the
correct order and prints an "Uninstall summary" box of what it removed and kept,
mirroring the installer's reporting. Design decisions settled in the CL:

- **A `--purge` flag** that also removes `/var/lib/s-hole` (blocklist caches and
  the query DB). Without it, operator data is left in place (and the summary
  points at it), because destroying query history should be an explicit opt-in.
- **`--restore-resolved` for stock DNS resolution.** If the `DNSStubListener=no`
  drop-in is present (created to free port 53 for s-hole), the flag removes it
  and restarts `systemd-resolved`. Gated behind the flag rather than done
  automatically, since it is a system-wide change the operator may have made
  independently; without the flag the summary just notes the drop-in is still
  there and how to remove it.
- **A confirmation prompt** listing the destructive set before acting, with a
  `-y`/`--yes` bypass for non-interactive use, and every removal step guarded so
  a re-run (or a partial install) is idempotent rather than an error.

Rated Low: deploy-time hygiene, no runtime behaviour. It closes the
install/uninstall asymmetry and heads off a real confusion the installer can
cause: because it never overwrites an existing `/etc/s-hole/config.yaml`, a
stale config left behind by a prior install silently shadows a freshly copied
one until it is removed (the uninstaller now removes `/etc/s-hole` for you).

## 13. Persist runtime whitelist across restarts

The whitelist is two-tier today: declarative entries in `config.yaml` (re-read
on every startup) and runtime entries added via the dashboard or
`POST /api/whitelist` (in-memory only, lost on restart; see
`store.AddToWhitelist`). An operator who whitelists a domain from the UI and
later restarts the service is surprised when it re-blocks. Persist runtime
additions so they survive a restart.

Design decisions to settle in the CL:

- **A separate store, not a `config.yaml` rewrite.** The API must not edit
  `config.yaml`, since it carries comments, formatting, and is frequently managed by
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
  store, not just the in-memory map; otherwise a deleted entry reappears on the
  next restart, which is a broken half-feature. A **config-sourced** entry,
  however, cannot be removed via the API without rewriting `config.yaml` (which
  we won't do): a `DELETE` on such an entry should be **rejected with a clear
  message** ("defined in config.yaml; edit the config to remove it") rather
  than silently no-op'ing or resurrecting on restart. The whitelist list
  responses should expose each entry's source (config vs runtime) so the UI can
  disable delete on config entries.
- **Blocklist precedence is unchanged.** The whitelist still wins globally and
  suffix-aware (CL 30).
- **Companion: show the whitelist size on the dashboard.** Surface the current
  count near the whitelist controls in the actions panel: a small `(N)` label
  matching the `(N)` on the Top Blocked / Top Clients headers, not a full stat
  card (the number is usually 0–few). The count already exists via
  `store.WhitelistLen()` / `shole_whitelist_size` (R34); the work is adding a
  `whitelist_size` field to the `/api/stats` payload the way `blocklist_size`
  rides along (CL 28) and rendering it. Folded in here because #13 already
  reworks this panel for the config-vs-runtime source display, so it is nearly
  free, but it does not strictly depend on persistence and could land
  standalone earlier (mirroring the Blocklist Size card, CL 28) if wanted.

Rated Medium: a user-visible robustness win (the whitelist behaves the way
operators expect across restarts) that changes no filtering semantics.

## 14. CNAME deep-inspection

Trackers increasingly hide behind first-party subdomains. A name such as
`metrics.example.com` is CNAME'd to a tracker domain, so the client sees a
first-party name while the data still flows to the tracker. s-hole blocks on the
queried name today, so it misses these: the visible name is on no blocklist, and
the CNAME target in the upstream answer is never checked. Pi-hole added this
under the name "CNAME deep inspection".

The fix needs no new dependency (miekg/dns already parses the answer section)
and slots in after the forward step in the handler: read the returned records,
and if any CNAME target in the chain is on the block set, return a sinkhole reply
instead of the upstream answer.

Design points to settle in the CL:

- Whether to check only CNAME targets or also the final A/AAAA target.
- Whether a reply blocked by chain inspection counts as a "blocked" query in the
  stats, and whether the whitelist suffix walk applies to chain targets the same
  way it applies to the queried name.
- Cache interaction: a reply blocked this way must not enter the cache as a
  normal upstream answer.

Rated Medium. It closes a real and growing evasion, but only for the subset of
trackers that use cloaking. The third-party trackers s-hole already blocks still
dominate real traffic, so the practical reach is narrower than the subdomain
blocking of CL 30.

## 15. Local DNS records (host overrides)

s-hole answers LAN queries but cannot name anything on the LAN itself. An
operator who wants `nas.home` or `printer.home` to resolve has to run a second
resolver or edit every client's hosts file. Pi-hole and dnsmasq both answer
local A/AAAA records; s-hole forwards them upstream, where they NXDOMAIN.

Add a `local_records:` map to config (name to one or more A/AAAA addresses).
Answer a matching query authoritatively before the forward step, the same
short-circuit pattern the private-PTR handler already uses (CL 27): the match
runs before the blocklist check, costs one map lookup for a non-matching query,
and needs no new dependency.

Design decisions to settle in the CL:

- **Name normalization.** Case-fold and trailing-dot normalize the configured
  names, the way blocklist entries are matched, so `NAS.home` and `nas.home.`
  resolve the same record.
- **Exact vs wildcard.** Whether to answer only exact names or also a wildcard
  suffix (e.g. `*.home`). Exact-only is the simpler first cut and covers the
  common case; a wildcard can reuse the suffix walk (CL 30) later.
- **Reverse symmetry.** Whether a configured record also answers the matching
  PTR query, or PTR stays out of scope for the first cut. PTR slots next to
  `isPrivatePTR` if wanted.
- **Wrong-type response.** For a configured name whose query type has no record
  (an AAAA query for an A-only host), return authoritative NODATA, not NXDOMAIN,
  so the name still exists.
- **Blocklist interaction.** A local record wins, since the operator declared
  it. It is answered before the blocklist check, so a name that appears in both
  resolves locally. Record this so a later review does not read it as a bypass.

Rated High: a user-visible resolution feature that many home deployments want,
and one of the more commonly requested capabilities s-hole lacks today. It
changes no filtering behavior.

## 16. Conditional / split-horizon forwarding

s-hole sends every non-blocked, non-local query to the same upstream pool. An
operator who runs an internal domain (a corporate zone, or a `.lan` served by
the router) has no way to route just that suffix to an internal resolver while
everything else goes to the public upstreams. dnsmasq calls this a
server-for-domain rule.

Add a per-suffix upstream override to config (suffix to upstream address).
Select the upstream in the forward step by walking the query name the way the
blocklist suffix check walks it (CL 30): the most specific configured suffix
wins, and a query that matches none uses the default pool. Upstreams are already
plain strings, so an override entry reuses the same `exchange()` path and
cooldown tracker (this shares the transport plumbing with the DoH work, #5).

Design decisions to settle in the CL:

- **Precedence against local answers.** Local records (#15) and the private-PTR
  short-circuit (CL 27) both answer before any forward, so a conditional-forward
  suffix only affects queries that reach the forward step.
- **Single upstream vs pool.** Whether an override defines one upstream or its
  own small pool with the same failover and cooldown semantics as the default.
- **Cooldown keying.** Whether the cooldown tracker keys stay global (one
  string, one cooldown) or become per-pool. Global is simpler and stays correct,
  since an upstream is identified by its string.
- **Cache interaction.** An answer from a conditional upstream caches like any
  other upstream answer, keyed by name and type, so no special handling is
  needed.
- **Scope note.** This is domain-scoped routing, distinct from the per-client
  policies non-goal. Record that so a later review does not conflate the two.

Rated Medium: a niche-deployment win for LANs that run an internal domain
alongside s-hole. It changes no filtering behavior.

## 17. Per-source blocklist health in `/api/stats` and dashboard (done, CL 55)

The dashboard shows the aggregate blocklist size (CL 28) and the startup log
records each source, but the running service exposes nothing per-source over the
API: which URLs loaded, how many domains each contributed, when each last
refreshed, and whether any fell back to its stale on-disk cache. When one source
silently returns an empty or truncated list, the aggregate size drops but the
operator cannot see which source caused it. The empty-blocklist alarm (CL 29)
catches only the all-empty floor.

Expose a per-source array in the stats payload (URL, domain count, last-refresh
time, and a stale-fallback flag) and render it as a small per-source list near
the Blocklist Size card. The data already exists at refresh time in
`blocklist.Update`; the work is carrying it on the store and adding it to the
`/api/stats` response the way `blocklist_size` rides along (CL 28).

Design decisions to settle in the CL:

- **Where the status lives.** Whether to store per-source status on the `Store`
  or in a sibling struct the handler reads, keeping the hot-path `Store` lean.
- **Meaning of "last refresh" under fallback.** For a source served from stale
  cache, report the time of the cached snapshot with the stale flag set, not the
  time of the failed fetch.
- **Pre-dedup vs post-dedup counts.** Whether the per-source count is what the
  source returned (pre-dedup) or its unique contribution (post-dedup). Pre-dedup
  is the honest per-source signal and matches the on-disk snapshot; note the
  choice, since the sum will exceed `blocklist_size`.
- **Metrics parity.** Whether to add a labeled
  `shole_blocklist_source_size{url=...}` gauge alongside the existing
  `shole_blocklist_size`, or keep the breakdown API-only.

Rated Medium: an observability win that turns a silent per-source failure into a
visible one. It changes no filtering behavior.

## 18. "Why is this domain blocked?" diagnostic endpoint (done, CL 56)

A false-positive report ("site X is broken") sends the operator digging through
blocklists to find which entry matched and whether a whitelist entry should
override it. s-hole holds all of that in memory but exposes no way to ask it.
The suffix walk (CL 30) is the exact logic an operator needs to see, and it is
invisible today.

Add `GET /api/check?domain=NAME` that runs the name through the same decision
path and returns the outcome plus the reason: blocked (and which suffix
matched), allowed by whitelist (and which entry), a local record or private-PTR
short-circuit, or a plain forward. It reuses `IsBlocked` and the whitelist walk,
adds no new dependency, and reads nothing the UI could not already infer, so it
does not widen the unauthenticated read surface.

Design decisions to settle in the CL:

- **First match vs full walk.** Return the first matching suffix or the whole
  walk. The first match is the decision; the full walk is better for debugging
  an over-broad entry, and it is cheap, so return the full walk.
- **UI surfacing.** Whether to add a small "check a domain" box in the actions
  panel or keep the endpoint API-only for the first cut.
- **Stats exclusion.** The check must not count in stats: it is a diagnostic,
  not a served query, so it bumps no counter and writes no query-log row.

Rated Low: a diagnostic guard rail with no runtime behavior change. It
reinforces the "auditable in an afternoon" identity by making the block decision
inspectable without reading Go.

## 19. Temporary "pause blocking"

The most-used control in comparable sinkholes. An operator hits a false positive
and wants the site now, without hunting for the list entry that matched. Add a
timed bypass that turns the block decision into pass-through for a set duration,
then re-enables itself.

`POST /api/disable?duration=5m` flips the store into pass-through and arms a timer
that restores blocking when the duration expires. `POST /api/enable` restores it
immediately. The dashboard shows a countdown pill and quick-duration buttons
(30s, 5m, indefinite). The store already swaps its map pointer under lock (CL 30),
so a bypass flag reuses the same read path with one atomic check.

Design decisions to settle in the CL:

- **Where the bypass lives.** A single atomic flag read at the top of `IsBlocked`,
  or a separate resolver state. The flag is simpler and adds one branch to the hot
  path.
- **Indefinite vs bounded.** Whether to allow an unbounded disable, or cap it and
  require re-arming. An unbounded disable that outlives the operator's memory is
  its own foot-gun; the visible countdown mitigates it.
- **Restart behavior.** Whether a pause survives a restart. Forward-only (a
  restart re-enables blocking) is the safe default. Record it so a later review
  does not read it as a lost timer.
- **Counter and metric.** A `shole_blocking_disabled` gauge (1 while paused) so
  the pause shows in `/metrics`, and a dropped block count is not a mystery.

Rated High: a user-visible control that many deployments reach for daily. It
changes no filtering rules, only whether they apply right now.

## 20. Query-volume-over-time graph

The dashboard shows current totals but not the shape of the day. Comparable tools
lead with a queries-over-time graph, and the data already sits in the query DB
with timestamps. A short history turns "current numbers" into "what happened
today".

`GET /api/history?window=24h&bucket=1h` aggregates total and blocked counts per
time bucket in SQL. The UI draws it with a small inline canvas, no chart library,
so the dependency graph and the static `go:embed` UI both stay as they are.

Design decisions to settle in the CL:

- **Bucketing in SQL vs Go.** Group by a time expression in the query, or scan
  rows and bucket in the handler. SQL grouping keeps the payload small and the
  handler thin.
- **Window and bucket bounds.** Which windows to offer (24h, 7d) and how to clamp
  the bucket count, reusing the `?limit=` clamp pattern so a crafted request
  cannot ask for millions of buckets.
- **db-disabled path.** With `query_db` off, return an empty series the way
  `/api/queries` returns an empty list, so the panel renders empty instead of
  erroring.
- **Privacy interaction.** The series is aggregate counts only and needs no client
  field, so #21 does not affect it. Record this so the two are not read as
  coupled.

Rated Medium: an observability win with high visual value. It changes no filtering
behavior.

## 21. Query-log privacy modes (write-time client anonymization)

The query log stores the client IP for every request. An operator who wants block
and domain analysis without retaining per-device history has no way to ask for it
today. Add privacy levels that mask the client before it is stored.

The masking must happen at **write time**, at a single choke point. A
`privacyLogger` decorator wraps the `Multi` logger and transforms the client IP
once, upstream of the fan-out, so the SQLite log, the text `FileLogger`, and every
reader see the same masked value. Read-time masking would leave raw IPs in
`queries.db` and in the text log, so the setting would promise a property it does
not have.

Levels:

- `full` (default): the raw client IP, current behavior.
- `anonymize`: the client is dropped on the flat home LAN (the common case), with
  **opt-in prefix truncation** (a configurable prefix such as `/24`) for segmented
  or VLAN networks where the subnet is a meaningful group. On a single-`/24` LAN a
  truncated client is a constant that looks like data and is not, so dropping is
  the honest default there.
- off is the existing `query_db: ""`.

This item is the foundation for #22, #23, and #24. Each of those is a read-time
consumer of the stored row and must never reach behind the mask.

Design decisions to settle in the CL:

- **Truncate vs drop default.** Drop on the flat LAN; truncate only when the
  operator sets a prefix. The choice is topology, not searchability (a `/24`
  truncation on a single-`/24` LAN filters nothing).
- **Retroactivity.** Masking is forward-only: rows written at `full` keep their raw
  IPs, so a mixed-level DB shows both. Whether to offer an explicit one-shot scrub
  of existing rows, or document forward-only and add scrub later. A silent bulk
  `UPDATE` of operator data should not be automatic.
- **No de-anonymization path.** No API convenience may reverse the mask (for
  example hashing a query parameter to match a hashed store). That would build a
  de-anonymization oracle on the unauthenticated LAN endpoint and defeat the mode.
- **Config surface.** A `query_privacy:` setting and its `S_HOLE_*` override,
  validated in `config.Validate`.

Rated Medium: a user-visible trust and robustness win. It changes no filtering
behavior.

## 22. Client name attribution

The log and the Top Clients panel show raw IPs. A friendly device name
("kids-ipad") is easier to read and act on. Add a static name map that resolves at
display time.

A `client_names:` map in config (exact IP or CIDR to label) is joined on the way
out, in the API read path or the UI. It is a read-time cosmetic over the stored
row, so it keys off the **masked** client value once #21 lands, never a pre-mask
raw IP. Resolving from a raw IP before masking would re-identify the exact device
and defeat #21; the label is itself PII.

Label granularity then tracks the privacy level: a host label at `full`, a subnet
label only when #21 truncates on a segment, nothing when the client is dropped.

Design decisions to settle in the CL:

- **Match precedence.** Exact IP over CIDR when both match, so a named host wins
  over its segment label.
- **Where the join runs.** In the API handler (one place, feeds the UI and the
  export) or in the UI only. The handler keeps export (#24) consistent for free.
- **Optional reverse-lookup.** Whether to also resolve names from the local PTR
  data opportunistically, or keep it config-only for the first cut. Config-only is
  simpler and has no lookup cost.
- **Scope note.** This is read-only attribution, distinct from the per-client
  policies non-goal. Record it so a later review does not conflate the two.

Rated Medium: a usability win for reading the log. It changes no filtering
behavior.

## 23. Query-log search / filter

The recent-queries panel shows the stream but cannot answer a question about it.
Add filters so false-positive triage is a query, not a scroll.

`GET /api/queries` gains `?domain=`, `?blocked=`, and `?client=` parameters,
reusing the `?limit=` clamp machinery. The filter runs in SQL over the stored
columns, so it can only ever match what #21 left in the row. When the effective
privacy level makes the client filter meaningless (the client is dropped, or a
single-`/24` LAN collapses every client to one subnet), the UI hides or disables
the client control rather than offering a box that silently returns every row.

Design decisions to settle in the CL:

- **Match semantics.** Exact vs substring for `?domain=`, and whether `?client=`
  accepts a CIDR. Substring domain match is the useful default for "show me
  everything under this tracker".
- **Index cost.** Whether the filtered columns need an index, weighed against the
  async writer's single-connection pool (b/038). Home-scale row counts likely do
  not, but note the measurement.
- **Privacy-aware UI.** The client control shows only when the stored client is
  meaningful, driven by the active `query_privacy` level.

Rated Medium: a usability and observability win. It changes no filtering behavior.

## 24. Query-log export (CSV / JSON)

Data portability. An operator who wants to analyze history in another tool has no
bulk path out today. Add an export that streams the log.

`GET /api/queries/export` streams the stored rows, reusing the #23 filter
parameters so a filtered export is the filtered query in bulk. Because #21 masks
at write time, export cannot leak more than search: there is no richer copy of the
client for the bulk endpoint to expose. This item is also the forcing function
that validates #21's placement. If masking were ever done at read time, an export
of the raw DB would silently undo the privacy setting.

Design decisions to settle in the CL:

- **Format and streaming.** CSV and JSON, streamed row by row so a large log does
  not build a full response in memory.
- **Privacy stamp.** Record the active `query_privacy` level in the export
  metadata (a CSV comment header or a JSON envelope field) so a masked value reads
  as intentional, not a bug.
- **Resolved names.** Whether the export includes the #22 label column. It may, and
  stays safe precisely because the label resolves from the masked stored value.
- **Timeout interaction.** The 64 KiB body cap is a request limit and does not
  apply, but confirm the slowloris write timeouts suit a long streamed response.

Rated Medium: a data-portability win. It changes no filtering behavior.

## 25. Regex / pattern blocking

Suffix blocking (CL 30) covers the common cases, but some trackers need a pattern
(for example a family such as `ad[sx]?[0-9]*\.`). Add an optional pattern list
checked after the fast set lookups.

A `block_patterns:` list is compiled once at load. `IsBlocked` checks the two O(1)
sets and the suffix walk first, and falls through to the patterns only on a miss,
so a blocked or exact-allowed query pays no regex cost. Patterns are the
last-resort tool; suffix blocking stays the fast path.

Design decisions to settle in the CL:

- **Hot-path guard.** A benchmark companion (the pattern-miss worst case, which
  runs every pattern) so a large list cannot regress the hot path unseen. Add it
  the way `BenchmarkStore_IsBlocked_Miss` guards the suffix walk.
- **Whitelist interaction.** Whether the whitelist walk (CL 30) overrides a pattern
  match the way it overrides a suffix match. It should: whitelist-wins stays the
  single escape hatch.
- **Compile-time validation.** A bad pattern in config fails `config.Validate` with
  the offending line, not at the first query.
- **Stats attribution.** A pattern-blocked query counts as blocked like any other.
  Whether to distinguish the reason in the #18 `/api/check` output.

Rated High: a user-visible filtering win for the cases exact and suffix matching
miss. Narrower reach than CL 30, since most real traffic is already caught by
suffix blocking.

## 26. Grafana dashboard + Prometheus examples

s-hole already exposes `/metrics` in Prometheus format, so the hard part is done.
What is missing is a ready-made way to use it. Ship the assets that turn the
existing metrics into a working monitoring setup, with no code and no new
dependency.

Prometheus scrapes and stores the `/metrics` time series and evaluates alert
rules. Grafana draws dashboards on top of a Prometheus data source. They are
layers, not alternatives: Grafana cannot scrape `/metrics` on its own, and
Prometheus has no dashboards of its own. An operator who already runs that stack
for a homelab gets the most from this. An operator who does not is already served
by the built-in dashboard (#20) and does not need to adopt the stack just for
s-hole.

Ship:

- `deploy/grafana-dashboard.json`: a portable dashboard with panels for the
  `shole_*` metrics (blocklist size, query rate, block ratio, cache hit rate,
  query-log drops, and any gauge added by #19 or #21).
- A `prometheus.yml` scrape snippet for the s-hole target.
- A small set of example alert rules (blocklist empty, high query-log drop rate,
  upstream failure rate).

Build this last so the dashboard and alerts can include any metric added by the
earlier items.

Design decisions to settle in the CL:

- **Dashboard scope.** Which panels ship by default, kept to the metrics that
  already exist so the JSON does not reference absent series.
- **Where the assets live.** Under `deploy/` next to the install scripts, and
  whether the README gains a short "monitoring" section pointing at them.
- **Version pinning.** Which Grafana schema version the JSON targets, since the
  import format changes across major versions.

Rated Low: a distribution and documentation win that makes the existing metrics
immediately usable. It adds nothing to the binary.

## Pending decisions

- **Cache eviction beyond drop-on-full.** Now that `shole_cache_dropped_total`
  (CL 54) and expired-slot reclaim ship, watch the counter on real traffic. A
  sustained non-zero drop rate at a sensible `cache_size` is the trigger to add
  sampled TTL-aware eviction: sample K entries on a full insert, evict the one
  closest to expiry, keeping `Get` read-only. Not LRU (see "Deliberately not
  planned" and the DESIGN eviction rationale). No policy without that evidence.

- _None otherwise open._ (Resolved: the shipped sample `config.yaml` was restored
  to the conservative `query_db: "queries.db"` / `api_listen:
  "127.0.0.1:8080"` after `0.0.0.0`/SQLite-off values were accidentally
  committed with CL 27; the unauthenticated admin UI should not ship
  LAN-exposed. The README config table documents the *code* defaults,
  which are `api_listen` `127.0.0.1:8080` and `query_db` off.)

## Deliberately not planned

Recorded so future reviews don't re-propose them; each trades the
"auditable in an afternoon" identity for features better served by
Pi-hole/AdGuard Home:

- **Admin API authentication.** LAN-trust is a documented scope
  decision (SECURITY.md, DESIGN open question #6). Half-hearted auth
  would imply a security property the unauthenticated design doesn't
  have; the localhost-only default is the mitigation.
- **Per-client policies / client groups.**
- **LRU cache eviction.** Move-to-front on every hit is a write on the
  read path; `Get` is a bare `RLock` read today, so LRU would serialize
  readers on a read-dominated cache (the contention
  `BenchmarkCache_Get_Parallel` guards). Drop-on-full with expired-slot
  reclaim covers home-network scale. Any future recency scheme must keep
  `Get` read-only (CLOCK/SIEVE). See the eviction rationale in DESIGN.
- **Pluggable blocklist formats/backends.**
- **Web UI redesign / SPA framework.**
- **Config-exposed dashboard poll rate.** The UI is a static
  `go:embed` file; plumbing config into it costs more than the knob
  is worth. If a knob is ever wanted: a `?refresh=` URL parameter in
  the JS, client-side only.
- **Tuning knobs for `flushBatchSize` / `queryQueueSize`.** Per the
  in-code rationale: changing them without a benchmark is unlikely to
  help.
- **Deduplicating the on-disk blocklist caches.** Per-URL verbatim
  snapshots are kept on purpose: the stale-fallback contract is per-list,
  and an untransformed copy is inspectable evidence when a source
  misbehaves. The in-memory set already deduplicates for free; disk
  savings would be a few hundred KB once per day.
- **Live application-log panel in the web UI.** About 90 % redundant with
  the recent-queries panel, which already renders the
  timestamp/client/domain/blocked content of the `ALLOW`/`BLOCK`
  stream once `query_db` is enabled. The remainder is operational slog
  lines (refresh results, upstream errors), which matter during
  incidents where `journalctl` is the better tool. Building it would
  require an in-memory log ring buffer plus a new `/api/logs` endpoint
  (the process does not retain its own stdout; journald owns it), and
  exposing operational internals on the unauthenticated UI sits on the
  pprof end of the disclosure gradient: if ever revisited, it must be
  opt-in like `enable_pprof`.
- **Container-aware / advertised startup banner.** In Docker the "Router
  setup" banner prints the container's *internal* bridge IP (e.g.
  `172.17.0.2`), not the host's; s-hole cannot know the host LAN IP or the
  published port from inside the container. Two fixes were weighed and
  dropped: detecting the container (`/.dockerenv`, `/proc/1/cgroup`) and
  rewording the banner only *stops it misleading*; it still can't show the
  right address, and the detection is a runtime-specific heuristic; an
  `S_HOLE_ADVERTISE_IP` override is self-defeating, because an operator who
  can supply the host IP already knows it and is unlikely to be reading
  container startup logs at all. The README Docker section documents the
  behaviour (use the host IP you published, ignore the banner) instead.
