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
  unique-local sources and the IPv6 subnets of the host's interfaces, and
  refuses every other source before it touches the stats, the cache, or the
  query log. A public or CGNAT IPv4 subnet on an interface is not admitted
  (s-hole logs a WARN that names it). A source address that s-hole cannot
  read is refused. If s-hole cannot read the interface addresses (for
  example, a sandbox without `AF_NETLINK`), it logs a WARN at most once an
  hour.
- **DNS server limits.** At most 512 queries wait for an upstream at the same
  time. A query over this limit gets SERVFAIL at once, and
  `shole_forward_limited_total` counts it. The plain-TCP listener caps open
  connections at 256, like the DoT listener, and closes a connection
  that sends nothing for 2 seconds, or that is idle for 8 seconds after a
  query. These limits are global. A limit for
  each client would keep client addresses in memory, so there is none.
- **DNS answers.** The cache keeps a separate answer for each combination of
  the CD and DO bits, so one client's DNSSEC choice does not reach another
  client. An upstream reply must match the query's name, type, and class, or
  s-hole tries the next upstream. A cached answer lives one day at most. A
  query with RD=0 (a query that reads only the cache) gets REFUSED. The DoH
  client follows no redirect: a DoH upstream that answers with a redirect is
  a failed attempt, and s-hole tries the next upstream (b/102). So a query
  goes only to a configured upstream, never over plain HTTP.
- **Admin HTTP** binds to `127.0.0.1:8080` by default (LAN access is
  opt-in, with a repeating WARN). The server applies `ReadHeaderTimeout=5s`,
  `ReadTimeout=15s`, `WriteTimeout=30s`, `IdleTimeout=60s`, and a 64 KiB body
  cap on POST endpoints. Every route answers only a request addressed to an IP
  address, `localhost`, or the machine's own hostname (421 otherwise), which
  stops DNS rebinding. A request that the browser marks as sent from another
  site (`Sec-Fetch-Site: cross-site` or `same-site`) gets 403 on every route,
  so a web page cannot time a GET reply or start an export through the
  operator's browser. The one exception is a link that opens the dashboard
  page (a top-level navigation to `/`). A request without this header
  (`curl`, Prometheus, the healthcheck) passes. Browsers send this header
  only to `localhost`, a loopback address, or HTTPS, so the check protects
  the default `127.0.0.1:8080` bind. It does not protect a dashboard opened
  by its LAN address over plain HTTP. `http.CrossOriginProtection`
  also refuses cross-site state-changing requests, and JSON endpoints require
  `application/json`. Every response carries `Cache-Control: no-store`, a
  Content-Security-Policy that allows no inline script (the dashboard script
  is a separate file), `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: no-referrer`, and `Cross-Origin-Resource-Policy:
  same-origin`.
  None of this is authentication: the dashboard has no login (see
  `docs/ROADMAP.md` for the planned device pairing). A purge
  (`POST /api/purge`) is accepted only from the s-hole host itself.
- **Stored data** is owner-only: s-hole creates its files with mode `600`
  (umask `077`, and `UMask=0077` in the unit), the data directory is `700`,
  and the query database is opened with `secure_delete`, so a pruned or
  purged row is overwritten in the file. A purge also overwrites the query
  log file with zeros before it empties or deletes it, and a purge while
  s-hole is stopped overwrites the database files with zeros before it
  deletes them. The overwrite refuses a symbolic link, a file that is not a
  regular file, and (on Unix) a file with more than one hard link: the
  uninstaller runs the purge as root in a directory that the `s-hole` user
  owns. On Windows the service runs as a virtual account
  (`NT SERVICE\s-hole`), and install gives the config folder an owner-only
  access list. The Docker image runs as UID 65532.
- **The application log** carries no query name, no client address, and no
  total query count (the failure summaries count failed queries only). The
  one exception is the allowlist audit line: it names the domain, and the
  requester's address only while `query_log.mode` records queries, masked by
  `query_log.clients` (no address under the defaults). An error from a client connection (a
  DNS reply or an admin API response that could not be sent) is logged
  without socket addresses. The admin web server's own error lines (for
  example, after a handler panic) go to the `api` logger at ERROR, with each
  IP address replaced by `client` (b/103).
- **URLs that s-hole shows** (logs, `/metrics` labels, `/api/stats`) hide
  user info and the query string, where a private list or DoH endpoint can
  keep a token.
- **Blocklist downloads** use a dedicated `http.Client` with a 60-second
  timeout and a 256 MiB `io.LimitReader` cap. Non-200 responses fall back
  to the stale cache rather than poisoning it. Files are written
  atomically via `.tmp` + `os.Rename`. An HTTPS download does not follow a
  redirect to a URL that is not HTTPS (b/097): the download fails, s-hole
  logs a warning, and the stale cache is used if there is one. A redirect to
  another HTTPS host is followed. A download stops after 10 requests (9
  redirects), as with Go's default policy.
- **Domain inputs** (blocklist lines, `blocking.allowlist` entries, and the
  allowlist API) are validated by `blocklist.ValidDomain`: length ≤ 253, an
  interior dot, letters, digits, and `.-_` only, no empty label, and no label
  that starts or ends with `-`. The allowlist API also refuses a two-label
  entry that starts with `co`, `com`, `org`, `net`, `gov`, `ac`, or `edu`
  (such as `co.uk`), because it would unblock every site under that public
  suffix. It keeps at most 1,000 entries that it added (a removal frees a
  place); the entries in `blocking.allowlist` do not count.
- **Profiling endpoints** (`/debug/pprof/*`) are off by default. They
  register only when `admin.pprof: true` is set (which also turns on
  mutex and block profiling), and s-hole then warns at startup and with every
  stats line. Keep them off in normal operation.
- **systemd unit** ships with `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome=true`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, and
  `UMask=0077`. It also sets a sandbox: `PrivateTmp` with
  `ReadOnlyPaths=/tmp /var/tmp` (a query path under `/tmp` fails to write),
  `PrivateDevices`,
  `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`,
  `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`,
  `ProtectProc=invisible`, `ProcSubset=pid`, `RestrictNamespaces`,
  `RestrictSUIDSGID`, `RestrictRealtime`, `LockPersonality`,
  `MemoryDenyWriteExecute`, `RemoveIPC`, `SystemCallArchitectures=native`,
  and a system-call filter (`@system-service` without `@privileged` and
  `@resources`). `RestrictAddressFamilies` allows `AF_UNIX`, `AF_INET`,
  `AF_INET6`, and `AF_NETLINK`. s-hole needs `AF_NETLINK` to read the
  subnets of the host's interfaces for the LAN check.
- **Docker.** The README's `docker run` examples use `--read-only`,
  `--security-opt no-new-privileges:true`, and `--cap-drop ALL` with
  `--cap-add NET_BIND_SERVICE`. In the bridge example, port 53 is published
  on the host's IPv4 address only. If it is published without an address,
  Docker relays IPv6 queries with the bridge gateway as the source, and the
  LAN check cannot refuse an IPv6 source from the internet.
- **DNS over TLS** is off by default. When `dns.dot_listen` is set, the listener
  caps open connections at 256, accepts TLS 1.3 only, and bounds the TLS
  handshake with the 2-second per-connection read timeout. In TLS 1.2, a
  resumed session sends its session ticket in clear text, so a passive
  observer on the LAN could link the DoT connections of one device. Android 9,
  the first version with Private DNS, supports only TLS 1.2 for it, so it
  cannot use s-hole's DoT. The operator supplies the certificate and private
  key; keep the key readable only by root and the `s-hole` group (mode `640`). A reload whose files do not load keeps
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
