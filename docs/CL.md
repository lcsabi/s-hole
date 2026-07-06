# CLs: s-hole DNS Sinkhole

This file is the index for the per-CL change-list records. Each entry
links to a focused file under `docs/cls/` so that:

- `git blame` and `git log` show only the surface area touched by a CL,
  rather than every CL touching the same file.
- Each CL renders as a properly-paginated page on GitHub.
- New CLs add a file rather than appending to a long log.

In a real Piper-based workflow each would be a separate numbered CL;
the per-file layout here mirrors that intent for an open-source repo.

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

When a new CL lands, drop a new file into `docs/cls/` and add a row
here. The per-CL file should start with a top-level `# CL N — title`
heading so the rendered page has a sensible title.
