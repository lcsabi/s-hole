# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in s-hole, **please do
not open a public issue**. Instead, report it privately so a fix can be
prepared before the issue becomes public.

- **Email:** laszlo.cs4ba@gmail.com
- **Subject:** include the string `[s-hole security]`
- **Encryption:** optional; ask for a public key if you need one

Please include in your report:

- A description of the issue and its impact.
- Steps to reproduce, ideally with a minimal config.
- Affected version (commit hash or release tag).
- Any suggested mitigation.

You can expect:

- An acknowledgement within **3 working days**.
- A status update within **14 days** of the acknowledgement.
- Public disclosure (with credit, if desired) once a fix is released or
  90 days after the initial report, whichever comes first.

## Scope

In scope:

- The DNS server, blocklist downloader, query log, admin HTTP server,
  cache, and configuration loader as shipped from this repository.
- Crashes, privilege escalation, information disclosure, or
  denial-of-service vectors that can be triggered from the LAN or via a
  malicious blocklist URL configured by the operator.

Out of scope:

- Issues that depend on the operator running the binary as `root` or
  exposing the admin API to the public internet — both are explicitly
  warned against in `README.md`.
- Reports against third-party blocklist content; s-hole treats lists as
  untrusted input but cannot vouch for what they contain.
- DNS amplification or spoofing on a deployment that ignores the
  "LAN-only" guidance.

## Defensive Posture (Summary)

- **Admin HTTP** binds to `127.0.0.1:8080` by default (LAN access is
  opt-in). The server applies `ReadHeaderTimeout=5s`, `ReadTimeout=15s`,
  `WriteTimeout=30s`, `IdleTimeout=60s`, and a 64 KiB body cap on POST
  endpoints.
- **Blocklist downloads** use a dedicated `http.Client` with a 60-second
  timeout and a 256 MiB `io.LimitReader` cap. Non-200 responses fall back
  to the stale cache rather than poisoning it. Files are written
  atomically via `.tmp` + `os.Rename`.
- **Domain inputs** (both from blocklists and the whitelist API) are
  validated by `blocklist.ValidDomain` (length ≤ 253, must contain a dot,
  alphanumerics + `.-_` only).
- **systemd unit** ships with `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome=true`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`.
- **No CGO** — the binary is statically linked, so a libc or
  `libsystemd` vulnerability cannot reach the s-hole process.

For the full design discussion of these mitigations, see
`docs/DESIGN.md` ("Security Considerations").
