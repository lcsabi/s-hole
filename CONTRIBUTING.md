# Contributing to s-hole

Thanks for considering a contribution. s-hole is intentionally small —
a single binary, a single YAML config, no runtime dependencies — and
this guide explains the conventions that keep it that way.

## Reporting issues

- **Security vulnerabilities:** please do **not** open a public issue.
  See [`SECURITY.md`](SECURITY.md) for the private-disclosure flow.
- **Bugs:** use the *Bug report* issue template. The template asks for
  `s-hole -version` output and a minimal reproducer.
- **Features:** use the *Feature request* template. The template
  prompts you to confirm the proposal isn't already a documented
  non-goal (see `docs/DESIGN.md`).

## Local development

### Prerequisites

- Go 1.25 or later.
- Optional: `golangci-lint` for `make lint` / `make check`. Install via:

  ```bash
  make tools-install
  ```

### The Makefile is the canonical entry point

```bash
make help          # full target list
make check         # gofmt + vet + golangci-lint + tests (what CI runs)
make test          # plain test run
make test-race     # tests with the race detector (CGO toolchain required)
make bench         # one iteration of each benchmark
make lint          # golangci-lint
make fmt           # gofmt -s -w .
make install       # go install into $GOBIN
make version       # show the version metadata the next build will embed
make tools-install # install golangci-lint
```

Before sending a PR, please run `make check` locally. CI runs the same
thing plus a race-enabled test run and cross-compile for
`linux/{amd64,arm64,armv7}` and `windows/amd64`.

### Running the binary

```bash
go build -o s-hole ./cmd/s-hole
sudo ./s-hole -config config.yaml          # Linux / macOS
```

`-version` prints the build identity; `-service install|uninstall|start|stop`
controls the Windows Service.

### Fuzz tests

Fuzz tests are not part of CI but are easy to run locally:

```bash
go test -fuzz=FuzzValidDomain -fuzztime=30s ./internal/blocklist/
```

`-fuzztime=30s` is a sensible smoke; longer runs are appropriate when
touching `ValidDomain`, `parseHostsFormat`, or `cacheFilename`.

## Project structure

```
cmd/s-hole/        application entry point (main package, signals)
internal/          all implementation packages (not importable externally)
deploy/            systemd unit + Linux install script
docs/              DESIGN, CHANGELOG, BUGS, CL index
docs/cls/          one file per CL
.github/           CI workflows, dependabot, CODEOWNERS, templates
```

All implementation packages live under `internal/` so the public API
surface is just `cmd/s-hole`. If you find yourself wanting to expose a
package, please open a discussion first — the `internal/` boundary is
load-bearing for the "auditable in an afternoon" goal.

## Pull-request conventions

### Branches and commits

- Branch off `master`.
- Keep commits focused. A PR can be one commit or many, but the merge
  commit message should read like a CL description (see below).
- The Conventional-Commits style is *not* required, but a sentence-form
  imperative subject is appreciated (`fix: drop tzdata from runtime
  image` rather than `dropped tzdata`).

### CL descriptions

Each non-trivial change lands as a CL in `docs/cls/CL-NN.md`. The CL
file is the durable record; the PR template links to it. A CL file
should contain:

- A one-line description matching the PR title.
- The motivation (the "why", not the "what").
- A *Files changed* block sketching the surface area.
- A *Testing* block sketching how you verified the change.

Look at `docs/cls/CL-20.md` for a recent example.

### Issue/staff-review IDs

The repo tracks two kinds of identifiers:

- `b/NNN` — a Buganizer-style bug filed in `docs/BUGS.md`.
- `R NN` — a finding from a staff-engineer review. These are tracked
  in CL notes only, not in `BUGS.md`.

If your change fixes one of these, mention the ID in the commit message
and in any regression-test comment so future readers can trace the
context.

### Tests are not optional

Every behaviour change needs a test. Coverage gates are not enforced
strictly, but the per-package targets are:

- `internal/stats`, `internal/config`, `internal/version`: 100 %
- `internal/cache`: ≥ 94 %
- `internal/api`, `internal/blocklist`, `internal/dnsserver`,
  `internal/querylog`: ≥ 85 %

The `cmd/s-hole` package sits around 28 % because the rest is the
`main()` bootstrap and SCM glue that aren't unit-testable. Module-wide
coverage tracks around 71 %.

Run `go test -cover ./...` locally to see the current state before
sending a PR; if your change drops a number, please either add the
missing test or note in the CL why the drop is acceptable.

## Code style

- Always `gofmt -s -w .` before committing (`make fmt`).
- Follow the standard library naming conventions: capitalised
  identifiers are exported; short receiver names; ALL_CAPS only in
  constant blocks.
- Errors flow up the stack as values; package boundaries log them via
  `log/slog`.
- Don't pull in a new dependency without discussion. The full `go.sum`
  fits on a single screen and we'd like to keep it that way.

## Doc-vs-code drift is treated as a bug

If you change observable behaviour, the relevant doc must change with
it. The audit-and-sync conventions are:

- `README.md` — operator-facing surface (CLI flags, env vars, REST
  endpoints, deployment).
- `docs/DESIGN.md` — design rationale (why we did it this way).
- `docs/CHANGELOG.md` — one bullet per user-visible change.
- `docs/cls/CL-NN.md` — the full CL record.

A PR that updates code without the matching doc lines will be sent
back for adjustment.

## License

By contributing, you agree that your contribution will be licensed
under the project's MIT license (see [`LICENSE`](LICENSE)).
