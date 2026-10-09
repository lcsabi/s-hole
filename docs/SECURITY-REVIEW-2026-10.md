# Privacy and security review, October 2026

In October 2026, s-hole 2.0.0 had a privacy and security review. This page
says what the review found, what changed, and what is still open.

## Scope

The review had three parts:

1. An external staff-level privacy and security review of s-hole 2.0.0.
2. A check of each claim in that review against the code, the CI, the
   repository settings, and live runs.
3. The maintainer's own audit of the code, the deploy files, the CI, and the GitHub
   repository settings.

The live checks ran on these systems:

- a Debian 13 VM (amd64, systemd 257, Docker 29)
- a Raspberry Pi 5 (arm64, systemd 252)
- Windows 10 22H2
- Android 13, for DNS over TLS

## Results

The review and the fix work found 37 issues: 21 security issues and 16
privacy issues. No
issue had High severity.

| Severity | Count | Meaning |
|---|---|---|
| High | 0 | Remote, default settings, direct data exposure or compromise. |
| Medium | 5 | A real effect under a plausible condition, or a default that breaks a written design rule. |
| Low | 22 | Needs an unusual setup or an earlier compromise, or is defense in depth. |
| Info | 10 | Hardening, a defect with no current trigger, or documentation. |

Each issue is fixed, except two that only the planned device pairing can
fix: every account on the s-hole host can use the dashboard, and a dashboard
on the LAN uses plain HTTP. For these two, the documentation now states the
limit, and ROADMAP #42 sets the requirements.

A final pass on 2026-10-09 checked every issue against the acceptance checks
that can run today: tests, code, documentation, and live runs. The release
checks ran on 2.1.0 and 2.1.1. Every archive, the binary in it, and the image
verify with `gh attestation verify`. A published release asset cannot be
replaced.

## The Medium issues

- **One device could turn off DNSSEC validation for the whole network.** The
  response cache did not store the CD and DO bits of a query. A device that
  sent CD=1 put an answer that had failed validation in the cache, and every
  other device then got it. The cache now keeps a separate answer for each
  combination of the two bits. (b/096, fixed in 2.0.1.)
- **A blocklist download followed a redirect from HTTPS to plain HTTP.** An
  attacker on the network path could then change the list. s-hole now refuses
  such a redirect and keeps the last cached copy, if there is one. (b/097, fixed in 2.0.1.)
- **On Windows, the service account could change its own binary and
  config.** An administrator who ran that binary later would run a changed
  program. The binary now goes in `C:\Program Files\s-hole`, and the service
  can change only the files that it creates. (b/104, fixed in 2.1.0.)
- **The periodic stats line wrote activity counts to the system journal.**
  The difference between two lines showed when the household was active, and
  a purge could not delete the journal. The line now holds the uptime only.
  (b/098, fixed in 2.0.1.)
- **Every account on the s-hole host can use the admin API.** It can read,
  export, and delete the history and change the allowlist. The dashboard has no login, so the owner-only file mode of the
  database gives no protection while s-hole runs. `PRIVACY.md` and
  `SECURITY.md` now say this and recommend a dedicated host. The planned
  device pairing (ROADMAP #42) must also cover requests from the host itself.

## Other changes

**DNS answers and the cache.** An upstream reply must answer the question
that s-hole sent. The cache keeps an answer for one day at most. A query
with RD=0 gets REFUSED, so a device cannot read the cache without adding the
name to it.

**The application log.** A log line from the DNS path never names a queried
domain or a client. Admin
API write errors and an admin handler panic no longer log the requester's
address. The allowlist audit line names the requester only while
`query_log.mode` records queries, masked with `query_log.clients`, so the
default settings log no address.

**Activity data.** The per-minute graph follows `query_log.mode`: under the
default `"none"` it records nothing.

**What stays on the network.** More reverse zones are answered locally (RFC
6303, RFC 6598, and the host's own IPv6 prefix). `fritz.box` is a local
name. s-hole does not treat an on-link public or CGNAT IPv4 subnet as LAN. A
query from a source that s-hole cannot read gets REFUSED.

**DNS server limits.** At most 512 queries wait for an upstream, and the
plain-TCP listener accepts at most 256 connections. There is no limit for
each client: such a limit would keep device addresses in memory. DNS over
TLS accepts TLS 1.3 only. The DoH client follows no redirect.

**Admin API.** A request that the browser marks as sent from another site
gets 403. Browsers add this mark only for the loopback dashboard (the
default) or HTTPS. The dashboard script
moved to its own file, so the content security policy allows no inline
script. The runtime allowlist holds at most 1,000 entries and refuses
entries such as `co.uk`.

**Deletion.** An offline purge overwrites the query files with zeros before
it deletes them. s-hole also overwrites the SQLite WAL with zeros before
SQLite frees it. A live check on a raw disk image found no queried name after
a retention prune or a purge, with s-hole running or stopped. On flash storage, an overwrite is best effort.

**Deployment.** The systemd unit has a tighter sandbox (`systemd-analyze
security` gives 1.5 OK). The README shows hardened `docker run` commands and
explains why port 53 must be published on an explicit IPv4 address.

**Supply chain.** Every GitHub Action is pinned to a commit SHA. Each workflow
job has only the token rights it needs. From 2.1.0, each release archive and
the container image have a signed build provenance attestation, and the image
has an SBOM, and releases are immutable. Release tags are protected. The
Docker base images are pinned by digest, and one pin sets the Go release for CI,
the archives, and the image. A weekly scan checks `master` and the latest
release binaries for known vulnerabilities. gosec and CodeQL run on every
change.

**Documentation.** `PRIVACY.md` now names the activity history that a
Prometheus server keeps. The README shows how to use DoH upstreams only, and
says that a dashboard on the LAN uses plain HTTP.

## Review items with no change

Some recommendations needed no change:

- **A setting for encrypted upstreams only.** A list with DoH upstreams only
  already fails closed (SERVFAIL). The README now shows how.
- **A newer `go` line in `go.mod`.** That line is the minimum version to build
  the module. It does not choose the toolchain of a release.
- **CVE-2026-86003.** It affects CoreDNS, which s-hole does not use.
- **Rotation of the text query log.** logrotate, journald, and the container
  runtime do this better. The setting already warns that retention does not
  reach the file.
- **Per-client cache partitions.** They would cost memory and protect little.
  The timing side channel is documented in `PRIVACY.md`.

## Still open

- **Login for the dashboard (ROADMAP #42).** Device pairing is planned. It
  must cover requests from the s-hole host and use HTTPS when the dashboard
  listens on the LAN. Until then, keep the dashboard on `127.0.0.1` and run
  s-hole on a dedicated host.

## Known limits

These limits are documented in `PRIVACY.md` and `SECURITY.md`:

- A LAN device can tell from response times, and from the remaining TTL,
  whether another device looked up a name recently.
- An exported file, a backup, or a VM snapshot keeps the history outside
  retention and purge.
- The system journal, Docker logs, and Prometheus keep data under their own
  retention, which s-hole cannot reach.
- With the default upstreams, s-hole sends a public name over plain DNS when
  every DoH upstream fails, and it warns when it does.

## Where the fixes are

| Release | Changes |
|---|---|
| 2.0.1 | DNS answer integrity (CL 97), blocklist redirect policy (CL 98), application log and activity data (CL 99) |
| 2.1.0 | LAN scope and local names (CL 101), DNS server limits and DoT TLS 1.3 (CL 102), admin API hardening (CL 104), purge overwrite (CL 105), Linux and Docker hardening (CL 106), Windows service access list (CL 107), SQLite WAL overwrite (CL 110), privacy documentation (CL 112) |
| 2.1.1 | An update of `golang.org/x/net`, so that a vulnerability scan of the release binaries is clean (CL 114) |
| CI and repository | Supply chain (CL 108), static analysis (CL 111) |

The bug entries are b/096 to b/105 in `docs/BUGS.md`. Each CL file in
`docs/cls/` describes its change, its tests, and its privacy effect.
