# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

s-hole is a single-binary DNS sinkhole (lightweight Pi-hole alternative) in Go: it answers LAN DNS queries, returns `0.0.0.0`/`::` (or NXDOMAIN) for blocklisted domains, forwards the rest upstream, and serves an embedded admin UI + REST API. Design identity: **auditable in an afternoon** — one binary, one YAML config, tiny dependency graph (`miekg/dns`, `yaml.v3`, pure-Go SQLite, `x/sys` for the Windows service). Don't add dependencies without strong justification.

## Commands

```bash
make check        # fmt + vet + lint + test — what CI runs; run before any commit
make test         # go test -count=1 ./...
make test-race    # race detector — requires a CGO toolchain (gcc)
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
- Measure **module-wide** coverage on Linux/WSL only: `go test -coverpkg=./... ./...`. A Windows Go install missing the `covdata` tool silently under-merges the profile — this once put a wrong number in three docs. Per-package `go test -cover` is fine anywhere.
- Lint requires **golangci-lint v2** (`make tools-install` uses the `/v2` module path; v1 cannot parse the `version: "2"` config). If lint fails with a config-load error right after a Go toolchain bump, it's the lint-binary-built-with-older-Go coupling — see the CL 24 addendum. The deliberate errcheck exclusions live in `.golangci.yml` with their rationale.
- Closed-port UDP tests make `./internal/dnsserver` take ~17 s on Windows vs ~2 s on Linux — expected, not a hang.
- Run locally without root/port conflicts: `S_HOLE_LISTEN=:5353 go run ./cmd/s-hole -config config.yaml`, then `dig @127.0.0.1 -p 5353 doubleclick.net`. CONTRIBUTING.md has the full 7-step manual smoke test.

## Architecture

Per-query hot path (one goroutine per query, spawned by miekg/dns):

```
ServeDNS (internal/dnsserver/handler.go)
  → blocklist.Store.IsBlocked      O(1) set lookup; whitelist overrides
  → stats.Counter + querylog fan-out (never blocks the query)
  → blocked? write sinkhole reply (0.0.0.0/:: or NXDOMAIN, EDNS0 mirrored)
  → cache.Cache.Get                TTL-respecting; hit ends here
  → forward (upstream.go)          UDP first, retry same upstream over TCP on TC bit;
                                   cooldown tracker skips recently-failed upstreams,
                                   second sweep retries them if all else failed
  → cache.Set (never caches truncated/NXDOMAIN/empty) → reply
```

Wiring lives in `cmd/s-hole/main.go`, which owns three cross-cutting mechanisms that are easy to break from inside a package:

- **Single-flight reload**: one `TryLock` closure wraps `blocklist.Update`; the periodic ticker, `POST /api/reload`, and SIGHUP all go through it. The mutex must stay in main — a mutex inside `api` was a P0 once (b/022) because the ticker bypassed it.
- **Shutdown ordering** (`doStop`): cancel ticker ctx → stop DNS → drain HTTP → wait for in-flight reload (bounded) → close cache/loggers → exit. Reordering causes writes-to-closed-DB or half-written blocklist cache files.
- **Platform split**: Windows SCM service loop vs. interactive signal handling (`signals_unix.go`/`signals_windows.go`, `internal/service` with a non-Windows stub).

Concurrency invariants that tests pin (keep them green under `-race`):
- `stats.Counter`: read `blocked` before `total` in Snapshot (b/021: >100% block rate); resolve top-N map pointers *inside* the mutex (R31: prune reassigns them).
- `blocklist.Store.Replace` swaps the map pointer under lock — readers see old or new set, never partial.
- `querylog.DBLogger` drops on full channel rather than blocking DNS; drops surface as `shole_query_log_dropped_total`.

Config (`internal/config`): precedence is `S_HOLE_*` env > YAML > defaults. Two fields (`cache_size`, `block_ttl`) have defaults seeded *before* the YAML decode because their zero values are meaningful settings (T1) — don't move them into `applyDefaults`. `Validate()` is called by main after `Load`.

Admin server (`internal/api`): unauthenticated by design (LAN-trust is a documented scope decision — do not bolt on auth; see docs/ROADMAP.md non-goals). Defense-in-depth instead: localhost-only default bind, slowloris timeouts, 64 KiB body cap, `?limit=` clamp, opt-in pprof. UI is a static `go:embed` file — it cannot read config; don't try to template it.

## Process conventions (enforced in review)

- **Every non-trivial change is a CL**: add `docs/cls/CL-NN.md` (description, motivation, files-changed, testing) + a row in `docs/CL.md` + a `docs/CHANGELOG.md` bullet for user-visible changes. Trivial doc-only commits may skip the CL file.
- **Doc-vs-code drift is treated as a bug.** When behavior changes, sync every place that quotes it. Frequent duplicates: coverage numbers (README table, DESIGN testing paragraph, CONTRIBUTING targets), REST routes (README table, DESIGN table, `api.go` package doc), config defaults (README table, `config.yaml` comments, `config.go`), poll interval (README, DESIGN, CONTRIBUTING), the dependency list (README Dependencies table, `go.mod`, the intro line above), the systemd unit (`deploy/s-hole.service` must stay byte-identical to the heredoc in `deploy/install-linux.sh`).
- **Historical records are immutable**: `docs/cls/CL-*.md` and `docs/BUGS.md` describe what was true at the time — never "fix" them retroactively.
- **ID conventions**: `b/NNN` = bug in `docs/BUGS.md`; `R/S/T NN` = staff-review findings (letter = review round), tracked in CL notes only. Reference IDs in regression-test comments.
- **Commit style**: imperative subject, often prefixed (`docs:`, `test:`, or `s-hole:` for CLs), body explains why; CL commits end the subject with `(CL NN)`.
- **Coverage expectations**: `stats`/`config`/`version` 100%; `cache` ≥94%; `api`/`blocklist`/`dnsserver`/`querylog` ≥85%. Run `go test -cover ./...` before PR; if a number drops, add the test or justify in the CL.
- **Roadmap** (`docs/ROADMAP.md`): planned work rated by impact (never effort estimates), pending decisions, and settled non-goals — check it before proposing features; don't re-propose the non-goals list. When an item lands, flip its status row to `done (CL NN)`.
- **Dependabot PRs that touch the same file can merge-race**: a later PR branched from an older master can silently revert an earlier merged bump (setup-go v6 was lost this way; restored in 0d360d9). After batch-merging, verify the final file state, not the PR list.
