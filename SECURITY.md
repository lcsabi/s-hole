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
- A web page that, through the operator's own browser, reads from or changes
  the admin server (DNS rebinding, cross-site requests), also while the admin
  server listens on localhost only.
- Query data that reaches a place `PRIVACY.md` does not list, or that stays
  after retention or a purge should have removed it.

Out of scope:

- Issues that depend on the operator running the binary as `root` or
  exposing the admin API to the public internet. Both are explicitly
  warned against in `README.md`.
- Reports against third-party blocklist content. s-hole treats lists as
  untrusted input but cannot vouch for what they contain.
- DNS amplification or spoofing on a deployment that ignores the
  "LAN-only" guidance.

## Defensive Posture (Summary)

- **Private by default.** s-hole records no queries and no client addresses
  until the operator opts in, every config mistake falls back to the most
  private value, and each setting that is less private or less secure than
  its default gives a WARN that repeats with every stats line. `PRIVACY.md`
  lists every place s-hole keeps or sends data.
- **LAN only.** The DNS server answers loopback, private, link-local, and
  unique-local sources and the subnets of the host's interfaces, and refuses
  every other source before it touches the stats, the cache, or the query log.
- **DNS answers.** The cache keeps a separate answer for each combination of
  the CD and DO bits, so one client's DNSSEC choice does not reach another
  client. An upstream reply must match the query's name, type, and class, or
  s-hole tries the next upstream. A cached answer lives one day at most. A
  query with RD=0 (a query that reads only the cache) gets REFUSED.
- **Admin HTTP** binds to `127.0.0.1:8080` by default (LAN access is
  opt-in, with a repeating WARN). The server applies `ReadHeaderTimeout=5s`,
  `ReadTimeout=15s`, `WriteTimeout=30s`, `IdleTimeout=60s`, and a 64 KiB body
  cap on POST endpoints. Every route answers only a request addressed to an IP
  address, `localhost`, or the machine's own hostname (421 otherwise), which
  stops DNS rebinding. `http.CrossOriginProtection` refuses cross-site
  state-changing requests, and JSON endpoints require `application/json`.
  Every response carries `Cache-Control: no-store`, a Content-Security-Policy,
  `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, and
  `Cross-Origin-Resource-Policy: same-origin`.
  None of this is authentication: the dashboard has no login (see
  `docs/ROADMAP.md` for the planned device pairing). A purge
  (`POST /api/purge`) is accepted only from the s-hole host itself.
- **Stored data** is owner-only: s-hole creates its files with mode `600`
  (umask `077`, and `UMask=0077` in the unit), the data directory is `700`,
  and the query database is opened with `secure_delete`, so a pruned or
  purged row is overwritten in the file. On Windows the service runs as a
  virtual account (`NT SERVICE\s-hole`), and install gives the config folder
  an owner-only access list. The Docker image runs as UID 65532.
- **The application log** carries no query name and no client address, except
  a warning about one failed query under `query_log.mode: "all"` and the
  allowlist audit line. A write error is logged without socket addresses.
- **URLs that s-hole shows** (logs, `/metrics` labels, `/api/stats`) hide
  user info and the query string, where a private list or DoH endpoint can
  keep a token.
- **Blocklist downloads** use a dedicated `http.Client` with a 60-second
  timeout and a 256 MiB `io.LimitReader` cap. Non-200 responses fall back
  to the stale cache rather than poisoning it. Files are written
  atomically via `.tmp` + `os.Rename`.
- **Domain inputs** (blocklist lines, `blocking.allowlist` entries, and the
  allowlist API) are validated by `blocklist.ValidDomain`: length ≤ 253, an
  interior dot, letters, digits, and `.-_` only, no empty label, and no label
  that starts or ends with `-`.
- **Profiling endpoints** (`/debug/pprof/*`) are off by default. They
  register only when `admin.pprof: true` is set (which also turns on
  mutex and block profiling), and s-hole then warns at startup and with every
  stats line. Keep them off in normal operation.
- **systemd unit** ships with `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome=true`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, and
  `UMask=0077`.
- **DNS over TLS** is off by default. When `dns.dot_listen` is set, the listener
  caps open connections at 256, accepts TLS 1.2 or later, and bounds the TLS
  handshake with the 2-second per-connection read timeout. The operator
  supplies the certificate and private key; keep the key readable only by root
  and the `s-hole` group (mode `640`). A reload whose files do not load keeps
  the current certificate, and an expired or failing certificate shows in the
  log, `/metrics`, and the dashboard. The `dot` object in `/api/stats` includes
  the last reload error, which can name the certificate file path. Like the
  rest of the admin API it is unauthenticated, so keep `admin.listen` on
  localhost or a trusted LAN.
- **A private CA installed on clients is trusted for every site.** For DoT with
  a private certificate, each client must trust its CA. Whoever holds that
  CA's private key can then impersonate any website to those devices, so keep
  the key off the s-hole box. With mkcert, the CA key stays on the workstation
  that issued the certificate. The README's openssl command sets
  `basicConstraints=critical,CA:FALSE`: by default `openssl req -x509` makes a
  CA, and its key (`dns.dot_key`) lives on the s-hole box. With `CA:FALSE` the
  certificate cannot sign others, so a device that trusts it by mistake
  trusts only that DNS server. A publicly trusted certificate (ACME) needs no
  client install.
- **No CGO.** The binary is statically linked, so a libc or
  `libsystemd` vulnerability cannot reach the s-hole process.
- **Client name labels are read-only and privacy-bounded.** The optional
  `client_names` map adds device labels to the admin API, so it is device-
  identity PII on the unauthenticated read surface. The label is resolved from
  the stored (already masked) client value, so it can never reveal more than
  `query_log.clients` already exposes (under `subnet` only a CIDR or
  network-address key resolves, under `drop` none). The map is parsed once at load, so it adds no
  network call or new wire-parsed input, and labels are HTML-escaped in the
  UI. Keep `admin.listen` on localhost or a trusted LAN when you use it.

For the full design discussion of these mitigations, see
`docs/DESIGN.md` ("Security Considerations").
