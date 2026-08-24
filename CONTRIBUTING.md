# Contributing to s-hole

Thanks for considering a contribution. s-hole is intentionally small: a
single binary, a single YAML config, and no runtime dependencies. This
guide explains the conventions that keep it that way.

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
thing plus a race-enabled test run (which also runs the goroutine-leak
check via `go.uber.org/goleak`), a `govulncheck` scan (`make vuln`
locally), and cross-compile for `linux/{amd64,arm64,armv7}` and
`windows/amd64`.

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

`-fuzztime=30s` is a good smoke test. Run longer when you change
`ValidDomain`, `parseHostsFormat`, or `cacheFilename`.

### Manual smoke test

Unit tests cover the packages. This seven-step pass (about five minutes)
exercises the running binary end-to-end. Run it before a release tag, or after
you change startup, shutdown, or anything in the query path. Port 5353
avoids both the privileged-port bind and the local resolver's claim on
port 53 (`systemd-resolved` holds `127.0.0.53:53` on most distros).

```bash
# Terminal 1: build and run; this terminal is also the live query log.
go build -o /tmp/s-hole ./cmd/s-hole
S_HOLE_LISTEN=:5353 S_HOLE_QUERY_DB=/tmp/q.db S_HOLE_CACHE_DIR=/tmp \
  /tmp/s-hole -config config.yaml
```

Expect: `blocklist updated total=…`, two `dns listener started` lines,
and the router-setup banner. Then, in a second terminal:

1. **Probes.** `curl localhost:8080/healthz` → `ok`;
   `curl localhost:8080/readyz` → `ok` (503 means the blocklist
   download failed).
2. **DNS behaviour.** `dig @127.0.0.1 -p 5353 doubleclick.net +short`
   → `0.0.0.0`; `dig @127.0.0.1 -p 5353 sub.doubleclick.net +short`
   → `0.0.0.0` too (suffix blocking: a subdomain of a blocked domain
   is blocked); `dig @127.0.0.1 -p 5353 example.com +short` → a real
   IP; repeat the third query → same answer, near-instant (cache
   hit). Terminal 1 shows a `BLOCK` / `ALLOW` line per query; if a
   query produces no line, it never reached the process.
3. **Dashboard.** Open `http://localhost:8080`; the stat cards and
   recent-queries table should reflect step 2 within one poll (~3 s).
4. **Whitelist round-trip.** Query a blocked domain, `POST
   /api/whitelist` with `{"domain":"…"}`, query again (now resolves),
   `DELETE /api/whitelist?domain=…`, query again (blocked again).
   Do one add via the dashboard's actions panel to cover the UI path.
5. **Reload single-flight.** Two immediate
   `curl -X POST localhost:8080/api/reload` calls: the first returns
   `"reload triggered"`, the second `"reload already in progress"`.
6. **Stats vs. metrics.** `curl localhost:8080/api/stats` and
   `curl localhost:8080/metrics`; blocked/total/cache numbers must
   agree with what you just did.
7. **Persistence + shutdown.** Ctrl+C: expect the final stats print
   and a clean exit. Restart: `/api/queries?limit=10` still shows the
   pre-restart rows, and startup is faster (blocklists load from the
   disk cache).

## Cutting a release

Releases are tag-triggered. Push a `vMAJOR.MINOR.PATCH` tag and
`.github/workflows/release.yml` builds the four targets, attaches a per-target
archive plus `SHA256SUMS` to a GitHub Release (notes drawn from the matching
`[X.Y.Z]` CHANGELOG section), and pushes a multi-arch
`ghcr.io/lcsabi/s-hole` image. The version is the tag name, so `s-hole
-version` on a released build reports it instead of `dev`.

The procedure:

1. **Graduate the CHANGELOG first, as a normal CL.** Rename `## [Unreleased]`
   to `## [X.Y.Z] - YYYY-MM-DD` and add a fresh empty `## [Unreleased]` above
   it. Merge that before tagging, so the tag points at a commit whose CHANGELOG
   already carries the release section.
2. **Dry-run with a pre-release tag.** Run `git tag -a vX.Y.Z-rc1 -m … && git
   push origin vX.Y.Z-rc1`. A tag with a `-` suffix is published as a GitHub
   pre-release and does not move the Docker `:latest`, so a mistake costs
   nothing.
3. **Verify the rc.** Confirm the four archives and `SHA256SUMS` are attached,
   `sha256sum -c SHA256SUMS` passes on a downloaded archive, a downloaded binary
   reports the tag under `-version`, `docker pull
   ghcr.io/lcsabi/s-hole:X.Y.Z-rc1` runs and reports the same version, and the
   Release notes render the `[X.Y.Z]` CHANGELOG section (not a placeholder).
4. **Tear down the rc.** Run `gh release delete vX.Y.Z-rc1 --yes --cleanup-tag`
   (removes the Release and the tag) and `git tag -d vX.Y.Z-rc1`. Delete the rc
   image from the `ghcr` package too if you want a clean package page.
5. **Cut the final tag.** Run `git tag -a vX.Y.Z -m … && git push origin
   vX.Y.Z`. This tag has no `-`, so the Release is marked Latest and `:latest`
   moves to it.
6. **Confirm.** `gh release view vX.Y.Z` shows `isPrerelease=false`,
   `docker manifest inspect ghcr.io/lcsabi/s-hole:latest` resolves, and the
   `ghcr` package is public.

A published final tag is immutable. Never move or delete it once it is out;
ship a fix as the next patch (`vX.Y.Z+1`).

## Project structure

```
cmd/s-hole/        application entry point (main package, signals)
internal/          all implementation packages (not importable externally)
deploy/            systemd unit + Linux install/uninstall scripts
docs/              DESIGN, CHANGELOG, BUGS, ROADMAP, CL index
docs/cls/          one file per CL
.github/           CI workflows, dependabot, CODEOWNERS, templates
```

All implementation packages live under `internal/` so the public API
surface is just `cmd/s-hole`. If you find yourself wanting to expose a
package, please open a discussion first; the `internal/` boundary is
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

- `b/NNN`: a bug filed in `docs/BUGS.md` (issue-tracker style: a stable
  ID, a priority, a component, and a root-cause/fix record).
- `R NN` / `S NN` / `T NN`: findings from successive staff-engineer
  review rounds (the letter identifies the round). These are tracked
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

The `cmd/s-hole` package sits around 36 % because the rest is the
`main()` bootstrap and SCM glue that aren't unit-testable. Module-wide
coverage tracks around 78 %.

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

## Writing style

Docs, code comments, and commit messages follow a house style inspired by
Simplified Technical English: short active sentences, plain words, one idea per
sentence. Two conventions:

- **Keep em-dashes (`—`) out of prose.** Overused, they read as AI-slop, so use
  a period, colon, semicolon, or parentheses instead. This is a taste guideline,
  not a gate: normal dashes are fine (hyphens, and en-dash ranges like
  `2000–5000`). `grep -n '—'` on your changed files is a handy convenience check,
  but it is not mechanically enforced and can miss occurrences, so read the prose
  rather than trusting a clean result.
- **Procedures read as instructions.** Put the condition before the command, use
  the imperative, and keep each step to one action.

Design rationale can stay nuanced; the goal is clarity, not mechanical brevity.
The nuance exemption covers only mechanical brevity (no hard sentence-length cap,
no approved-word list). The anti-slop tells still apply everywhere, rationale and
"why" comments included: no em-dashes, no triadic "A, B, and C" cadence, no "not
just X but Y" balancing, no empty intensifiers. Only the em-dash rule is
greppable; the others are a reviewer-eyeball check. `/simple-english` is a manual
tool for operator text (Quick Start, deploy steps, error strings, installer
echoes), not the whole-repo standard.
The immutable historical records (`docs/cls/CL-*.md`, `docs/BUGS.md`) are exempt,
and new CL titles use `# CL N: title` (a colon, not an em-dash).

## Doc-vs-code drift is treated as a bug

If you change observable behaviour, the relevant doc must change with
it. The audit-and-sync conventions are:

- `README.md`: operator-facing surface (CLI flags, env vars, REST
  endpoints, deployment).
- `docs/DESIGN.md`: design rationale (why we did it this way).
- `docs/CHANGELOG.md`: one bullet per user-visible change.
- `docs/cls/CL-NN.md`: the full CL record.

A PR that updates code without the matching doc lines will be sent
back for adjustment.

## License

By contributing, you agree that your contribution will be licensed
under the project's MIT license (see [`LICENSE`](LICENSE)).
