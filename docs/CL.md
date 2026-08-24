# CLs: s-hole DNS Sinkhole

This file is the index for the per-CL change-list records. Each entry
links to a focused file under `docs/cls/` so that:

- `git blame` and `git log` show only the surface area touched by a CL,
  rather than every CL touching the same file.
- Each CL renders as a properly-paginated page on GitHub.
- New CLs add a file rather than appending to a long log.

Each change is kept small and self-contained so it can be reviewed on its
own; the per-file layout mirrors how a large, long-lived codebase treats
every change as a separate, numbered, reviewable unit.

| CL | Topic |
|---:|---|
| [CL 1](cls/CL-01.md) | Initial DNS sinkhole implementation (phases 1–2) |
| [CL 2](cls/CL-02.md) | Configuration system and query logging (phases 3–4) |
| [CL 3](cls/CL-03.md) | Admin REST API and web UI (phase 5) |
| [CL 4](cls/CL-04.md) | Packaging, deployment, and service management (phase 6) |
| [CL 5](cls/CL-05.md) | DNS response cache and Raspberry Pi optimisations |
| [CL 6](cls/CL-06.md) | Startup network hint and self-contained install script |
| [CL 7](cls/CL-07.md) | Fix bugs and improvements from code review (b/003–b/020) |
| [CL 8](cls/CL-08.md) | Staff-engineer review fixes (b/021–b/027) |
| [CL 9](cls/CL-09.md) | Project structure cleanup and LICENSE |
| [CL 10](cls/CL-10.md) | Unit tests for every package + b/028 |
| [CL 11](cls/CL-11.md) | Architecture: slog, context, package rename |
| [CL 12](cls/CL-12.md) | Correctness fixes (R8–R20) |
| [CL 13](cls/CL-13.md) | New endpoints + features |
| [CL 14](cls/CL-14.md) | Docs + tests + CI |
| [CL 15](cls/CL-15.md) | Re-enable SIGHUP reload on Unix; correct platform framing |
| [CL 16](cls/CL-16.md) | Production-grade test coverage |
| [CL 17](cls/CL-17.md) | Documentation sync pass |
| [CL 18](cls/CL-18.md) | Production project layout (cmd/, docs/, SECURITY) |
| [CL 19](cls/CL-19.md) | Build identity, lint, dependabot, templates |
| [CL 20](cls/CL-20.md) | Act on fourth staff review (R31–R48) |
| [CL 21](cls/CL-21.md) | Act on fifth staff review (S1–S11) + split CL log |
| [CL 22](cls/CL-22.md) | Act on sixth staff review (T1–T8): cache_size 0, TCP retry on truncation |
| [CL 23](cls/CL-23.md) | Dual-stack listener default (`:53`) + IPv6 network docs |
| [CL 24](cls/CL-24.md) | Make the lint gate real: golangci-lint v2 compliance |
| [CL 25](cls/CL-25.md) | Dashboard: Cache Hit Rate stat card |
| [CL 26](cls/CL-26.md) | Test: dual-transport-safe port picking; surface Start errors (b/029) |
| [CL 27](cls/CL-27.md) | RFC 6303 local PTR answering for private-range zones |
| [CL 28](cls/CL-28.md) | Blocklist size in `/api/stats` and dashboard |
| [CL 29](cls/CL-29.md) | Hardening batch: goleak, govulncheck, empty-blocklist alarm |
| [CL 30](cls/CL-30.md) | Wildcard / subdomain blocking (suffix match) |
| [CL 31](cls/CL-31.md) | Skip and WARN on invalid config whitelist entries |
| [CL 32](cls/CL-32.md) | Benchmark companions for the hot path (cache, handler) |
| [CL 33](cls/CL-33.md) | Wire up TopBlocked: `/api/top-blocked` + dashboard toggle |
| [CL 34](cls/CL-34.md) | Strip the FQDN trailing dot in the dashboard |
| [CL 35](cls/CL-35.md) | Linux installer prints the installed build version/commit |
| [CL 36](cls/CL-36.md) | Act on ultrareview findings (b/030–b/035) |
| [CL 37](cls/CL-37.md) | Cache-hit-rate load-order fix (b/036); case-sensitivity by design (b/037) |
| [CL 38](cls/CL-38.md) | Pin the query-log SQLite pool to one connection (b/038) |
| [CL 39](cls/CL-39.md) | Move the Docker binary out of the /app volume (b/039) |
| [CL 40](cls/CL-40.md) | Add deploy/uninstall-linux.sh companion to the installer (roadmap #12) |
| [CL 41](cls/CL-41.md) | Move Recent Queries below Actions on the dashboard |
| [CL 42](cls/CL-42.md) | Act on ultrareview findings (b/040, b/041) |
| [CL 43](cls/CL-43.md) | v0.1.0 release workflow and CHANGELOG graduation |
| [CL 44](cls/CL-44.md) | Resolve release notes for pre-release tags |
| [CL 45](cls/CL-45.md) | Audit-log whitelist mutations and reload trigger source |
| [CL 46](cls/CL-46.md) | Pin the IsBlocked zero-allocation invariant with a test |
| [CL 47](cls/CL-47.md) | Pin the single-flight reload and case-sensitive cache-key invariants |
| [CL 48](cls/CL-48.md) | Make the shutdown teardown order testable |
| [CL 49](cls/CL-49.md) | Link two invariants to their guard tests at the enforcement site |
| [CL 50](cls/CL-50.md) | Trim per-query allocations on the handler and lookup hot path |
| [CL 51](cls/CL-51.md) | Document the benchmarking and profiling workflow |
| [CL 52](cls/CL-52.md) | Add benchmarks for the stats, cache-write, and parse paths |
| [CL 53](cls/CL-53.md) | Add contention benchmarks and enable mutex/block profiling |

When a new CL lands, drop a new file into `docs/cls/` and add a row
here. The per-CL file should start with a top-level `# CL N: title`
heading so the rendered page has a sensible title.
