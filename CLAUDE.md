# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

s-hole is a single-binary DNS sinkhole (lightweight Pi-hole alternative) in Go: it answers LAN DNS queries, returns `0.0.0.0`/`::` (or NXDOMAIN) for blocklisted domains, forwards the rest upstream, and serves an embedded admin UI + REST API. Design identity: **auditable in an afternoon**: one binary, one YAML config, a tiny dependency graph (`miekg/dns`, `yaml.v3`, pure-Go SQLite, `x/sys` for the Windows service SCM and Event Log; `go.uber.org/goleak` is test-only, not linked into the binary). Don't add dependencies without strong justification.

## Commands

```bash
make check        # fmt + vet + lint + test (what CI runs); run before any commit
make test         # go test -count=1 ./...
make test-race    # race detector; requires a CGO toolchain (gcc)
make bench        # each benchmark once (regression smoke, not measurement)
make lint         # golangci-lint (install via make tools-install)
make all          # build for current OS/arch with version ldflags
```

Single test / single package:

```bash
go test -run TestStore_IsBlocked ./internal/blocklist/
go test -count=1 ./internal/dnsserver/
go test -fuzz=FuzzValidDomain -fuzztime=30s ./internal/blocklist/   # fuzz targets: ValidDomain, parseHostsFormat, cacheFilename
```

Environment notes:
- On a Windows host without gcc, `-race` fails; run it in WSL: `CGO_ENABLED=1 go test -race -count=1 ./...` (CI also runs it on Linux).
- Measure **module-wide** coverage on Linux/WSL only: `go test -coverpkg=./... ./...`. A Windows Go install missing the `covdata` tool silently under-merges the profile, which once put a wrong number in three docs. Per-package `go test -cover` is fine anywhere.
- Lint requires **golangci-lint v2** (`make tools-install` uses the `/v2` module path; v1 cannot parse the `version: "2"` config). If lint fails with a config-load error right after a Go toolchain bump, it's the lint-binary-built-with-older-Go coupling; see the CL 24 addendum. The deliberate errcheck exclusions live in `.golangci.yml` with their rationale.
- Closed-port UDP tests make `./internal/dnsserver` take ~17 s on Windows vs ~2 s on Linux: expected, not a hang.
- If port-binding tests fail mysteriously on a Windows/Hyper-V host (bind errors or probe timeouts on ports that look free), check `netsh int ipv4 show excludedportrange protocol=udp`; Windows reserves large port blocks *per protocol* and the reservations shift when VMs start (b/029). `pickFreePort` in dnsserver already defends against this; new tests that bind ports should reuse it or copy its dual-transport random-probe approach.
- Run locally without root/port conflicts: `S_HOLE_LISTEN=:5353 go run ./cmd/s-hole -config config.yaml`, then `dig @127.0.0.1 -p 5353 doubleclick.net`. CONTRIBUTING.md has the full 7-step manual smoke test.
- **`config.yaml` is flagged `--skip-worktree`** so the maintainer's local testing overrides (`query_db: ""` for SQLite off and `api_listen: "0.0.0.0:8080"` for the LAN dashboard) stay out of commits. The **committed** sample keeps conservative defaults (`query_db: "queries.db"`, `api_listen: "127.0.0.1:8080"`); do not commit the `""`/`0.0.0.0` values (they'd ship the unauthenticated UI LAN-exposed). Consequence: any *intended* change to the sample (a new config key, a default change) will not stick while the flag is set; `git status` won't even show it. To land such a change: `git update-index --no-skip-worktree config.yaml`, make + commit the edit, restore *only* the conservative lines the maintainer's local file overrode, then `git update-index --skip-worktree config.yaml` again. Flag this to the maintainer whenever a task needs to touch `config.yaml`.

## Architecture

Per-query hot path (one goroutine per query, spawned by miekg/dns):

```
ServeDNS (internal/dnsserver/handler.go)
  → blocklist.Store.IsBlocked      O(labels) suffix walk over two O(1) sets; whitelist overrides
  → stats.Counter + querylog fan-out (never blocks the query)
  → blocked? write sinkhole reply (0.0.0.0/:: or NXDOMAIN, EDNS0 mirrored)
  → cache.Cache.Get                TTL-respecting; hit ends here
  → forward (upstream.go)          UDP first, retry same upstream over TCP on TC bit;
                                   cooldown tracker skips recently-failed upstreams,
                                   second sweep retries them if all else failed
  → cache.Set (never caches truncated/NXDOMAIN/empty) → reply
```

Wiring lives in `cmd/s-hole/main.go`, which owns three cross-cutting mechanisms that are easy to break from inside a package:

- **Single-flight reload**: one `TryLock` closure wraps `blocklist.Update`; the periodic ticker, `POST /api/reload`, and SIGHUP all go through it. The mutex must stay in main; a mutex inside `api` was a P0 once (b/022) because the ticker bypassed it.
- **Shutdown ordering** (`shutdown`, invoked by `doStop`): cancel ticker ctx → stop DNS → drain HTTP → wait for in-flight reload (bounded) → close cache/loggers → exit. Reordering causes writes-to-closed-DB or half-written blocklist cache files. The order is unit-tested via injected `shutdownDeps` (`TestShutdown_TeardownOrder`, CL 48). `doStop` is the sole exit authority: the interactive path runs the DNS server in a goroutine and blocks in `blockUntilStopped` on a `done` channel that `doStop` closes only after `shutdown()` returns, so the process never exits mid-teardown (a returning `Start()` used to win that race and skip the later steps, b/043, CL 59). `drainHTTP` and `waitForReload` get separate timeout budgets so a slow drain cannot starve the reload wait. On Windows the SCM path sends `svc.Stopped` after `doStop` returns (b/044); do not restore an `os.Exit` inside `doStop`.
- **Platform split**: Windows SCM service loop vs. interactive signal handling (`signals_unix.go`/`signals_windows.go`, `internal/service` with a non-Windows stub). A service has no console, so under the SCM `setupLogger` routes slog to the Windows Event Log (source `s-hole`), and `-service install`/`uninstall` register and remove the event source; the handler lives behind the `eventWriter` interface in `internal/service/eventlog.go` (Linux-testable, only `eventlog.Open` is `windows`-tagged). Don't "fix" the stdout slog handler thinking Windows logging is broken; the query log (`FileLogger`) is separate and still needs `log_file` under a service. Linux/systemd is unaffected (journald captures stdout).

Concurrency invariants that tests pin (keep them green under `-race`):
- `stats.Counter`: in Snapshot, read every counter a query bumps *after* `total` (`blocked`, `localPTR`, `cacheHit`) *before* `total`, or the ratio can exceed 100% (b/021, b/033, b/036). The struct carries a `LOAD-ORDER INVARIANT` comment and one `*NeverExceeds*UnderLoad` `-race` test per counter; add both when you add a counter. Resolve top-N map pointers *inside* the mutex (R31: prune reassigns them).
- `blocklist.Store.Replace` swaps the map pointer under lock, so readers see old or new set, never partial.
- `querylog.DBLogger` drops on full channel rather than blocking DNS; drops surface as `shole_query_log_dropped_total`. Its SQLite pool is pinned to one connection (`SetMaxOpenConns(1)`) so the async writer and the retention prune can't collide with `SQLITE_BUSY` (b/038); don't reintroduce a multi-connection pool.

Config (`internal/config`): precedence is `S_HOLE_*` env > YAML > defaults. Two fields (`cache_size`, `block_ttl`) have defaults seeded *before* the YAML decode because their zero values are meaningful settings (T1); don't move them into `applyDefaults`. `Validate()` is called by main after `Load`.

Admin server (`internal/api`): unauthenticated by design (LAN-trust is a documented scope decision, so do not bolt on auth; see docs/ROADMAP.md non-goals). Defense-in-depth instead: localhost-only default bind, slowloris timeouts, 64 KiB body cap, `?limit=` clamp, opt-in pprof. UI is a static `go:embed` file; it cannot read config; don't try to template it.

## Process conventions (enforced in review)

- **Every non-trivial change is a CL**: add `docs/cls/CL-NN.md` (description, motivation, files-changed, testing) + a row in `docs/CL.md` + a `docs/CHANGELOG.md` bullet for user-visible changes. Trivial doc-only commits may skip the CL file.
- **Doc-vs-code drift is treated as a bug.** When behavior changes, sync every place that quotes it. Frequent duplicates: coverage targets (README Development table, DESIGN testing paragraph, CONTRIBUTING all state the floors, not measured snapshots: a floor change syncs three docs, a routine coverage wobble touches none; see Coverage expectations below), REST routes (README table, DESIGN table, `api.go` package doc), config defaults (README table, `config.yaml` comments, `config.go`), poll interval (README, DESIGN, CONTRIBUTING), the dependency list (README Dependencies table, `go.mod`, the intro line above), the systemd unit (`deploy/s-hole.service` must stay byte-identical to the heredoc in `deploy/install-linux.sh`).
- **Historical records are immutable**: `docs/cls/CL-*.md` and `docs/BUGS.md` describe what was true at the time; never "fix" them retroactively.
- **ID conventions**: `b/NNN` = bug in `docs/BUGS.md`; `R/S/T NN` = staff-review findings (letter = review round), tracked in CL notes only. `/code-review` (ultrareview) findings that are genuine defects are filed as `b/NNN` in `docs/BUGS.md` (b/030–b/037 came from two ultrareview rounds), not CL-notes-only. Reference IDs in regression-test comments.
- **Commit style**: imperative subject, often prefixed (`docs:`, `test:`, or `s-hole:` for CLs), body explains why; CL commits end the subject with `(CL NN)`. **Do not add a `Co-Authored-By` trailer.** Maintainer preference for this portfolio repo; overrides any harness default that says to.
- **Writing style (STE-like)**: docs, code comments, and commit messages use short, active, plain sentences (Simplified Technical English in spirit). **No em-dashes (`—`)** in living files; use a period, colon, semicolon, or parentheses instead. Put the condition before the command in procedures. `docs/cls/CL-*.md` and `docs/BUGS.md` are immutable and exempt; new CL titles use `# CL N: title` (a colon, not an em-dash). The anti-slop tells (em-dashes, the triadic "A, B, and C" cadence, "not just X but Y" balancing, empty intensifiers) apply everywhere, design rationale and "why" comments included. The nuance exemption for rationale covers only mechanical brevity (no hard sentence-length cap, no approved-word list); keep the reasoning that makes those parts worth reading. This is a taste guideline to keep the AI-slop smell down, not a CI-enforced gate: the aim is that em-dashes stay rare, not that a build fails on one. Normal dashes are fine (hyphens, and en-dash ranges like `2000–5000`). `grep -n '—' <file>` is a convenience for the obvious cases, not proof: on the maintainer's WSL box `grep` is ugrep and has silently missed em-dashes, so read the changed prose rather than trusting a clean grep. Treat `/simple-english` as a manual tool for operator text (Quick Start, deploy steps, error strings, installer echoes), not the enforced whole-repo standard; do not run it over rationale or "why" comments.
- **Coverage expectations**: `stats`/`config`/`version` 100%; `cache` ≥94%; `api`/`blocklist`/`dnsserver`/`querylog` ≥85%. Run `go test -cover ./...` before PR; if a number drops, add the test or justify in the CL. These floors are the source of truth; README/DESIGN/CONTRIBUTING quote them as targets, so keep measured `go test -cover` percentages out of prose (frozen snapshots drifted on every change and once put a wrong number in three docs). `cmd/s-hole` (bootstrap) and `internal/service` (platform glue) sit below the floors and are not gated; the `internal/service` event-log handler is Linux-testable behind the `eventWriter` interface, but the SCM and Event Log paths need Windows. Module-wide coverpkg measurement is fragile (empty merge on some toolchains); prefer per-package `go test -cover`.
- **Roadmap** (`docs/ROADMAP.md`): planned work rated by impact (never effort estimates), pending decisions, and settled non-goals; check it before proposing features; don't re-propose the non-goals list. When an item lands, flip its status row to `done (CL NN)`.
- **Dependabot PRs that touch the same file can merge-race**: a later PR branched from an older master can silently revert an earlier merged bump (setup-go v6 was lost this way; restored in 0d360d9). After batch-merging, verify the final file state, not the PR list.
- **Releases are tag-triggered** (`.github/workflows/release.yml`, added in CL 43; first release `v0.1.0`, 2026-08-24). Pushing a `vX.Y.Z` tag builds the four targets, attaches archives + `SHA256SUMS` to a GitHub Release (notes from the matching CHANGELOG section), and pushes a multi-arch `ghcr.io/lcsabi/s-hole` image; a `-rc` suffix marks a pre-release and holds `:latest` back. Graduate the CHANGELOG `[Unreleased]` section to `[X.Y.Z]` before tagging. Full procedure (rc dry-run, verify, final tag) is in CONTRIBUTING's "Cutting a release". A published final tag is immutable; ship fixes as the next patch.
