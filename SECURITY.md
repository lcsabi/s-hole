# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in s-hole, **please do
not open a public issue**. Instead, report it privately via GitHub's
coordinated-disclosure flow so a fix can be prepared before the issue
becomes public:

**[github.com/lcsabi/s-hole/security/advisories/new](https://github.com/lcsabi/s-hole/security/advisories/new)**

That route gives the maintainer a private channel and the reporter an
audit trail. It is the modern equivalent of `security@` and is more
durable than a personal email address.

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
  exposing the admin API to the public internet. Both are explicitly
  warned against in `README.md`.
- Reports against third-party blocklist content. s-hole treats lists as
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
- **Profiling endpoints** (`/debug/pprof/*`) are off by default. They
  register only when `enable_pprof: true` is set (which also turns on
  mutex and block profiling), and a startup WARN then recommends a
  localhost-bound `api_listen`. Keep them off in normal operation.
- **systemd unit** ships with `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome=true`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`.
- **DNS over TLS** is off by default. When `dot_listen` is set, the listener
  caps open connections at 256, accepts TLS 1.2 or later, and bounds the TLS
  handshake with the 2-second per-connection read timeout. The operator
  supplies the certificate and private key; keep the key readable only by root
  and the `s-hole` group (mode `640`). A reload whose files do not load keeps
  the current certificate, and an expired or failing certificate shows in the
  log, `/metrics`, and the dashboard. The `dot` object in `/api/stats` includes
  the last reload error, which can name the certificate file path. Like the
  rest of the admin API it is unauthenticated, so keep `api_listen` on
  localhost or a trusted LAN.
- **A private CA installed on clients is trusted for every site.** For DoT with
  a private certificate, each client must trust its CA. Whoever holds that
  CA's private key can then impersonate any website to those devices, so keep
  the key off the s-hole box. With mkcert, the CA key stays on the workstation
  that issued the certificate. The README's openssl command sets
  `basicConstraints=critical,CA:FALSE`: by default `openssl req -x509` makes a
  CA, and its key (`tls_key`) lives on the s-hole box. With `CA:FALSE` the
  certificate cannot sign others, so a device that trusts it by mistake
  trusts only that DNS server. A publicly trusted certificate (ACME) needs no
  client install.
- **No CGO.** The binary is statically linked, so a libc or
  `libsystemd` vulnerability cannot reach the s-hole process.
- **Client name labels are read-only and privacy-bounded.** The optional
  `client_names` map adds device labels to the admin API, so it is device-
  identity PII on the unauthenticated read surface. The label is resolved from
  the stored (already masked) client value, so it can never reveal more than
  `query_privacy` already exposes (under `subnet` only a CIDR key resolves,
  under `drop` none). The map is parsed once at load, so it adds no network
  call or new wire-parsed input, and labels are HTML-escaped in the UI. Keep
  `api_listen` on localhost or a trusted LAN when you use it.

For the full design discussion of these mitigations, see
`docs/DESIGN.md` ("Security Considerations").
