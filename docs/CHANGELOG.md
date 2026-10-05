# Changelog

All notable changes to s-hole are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project loosely
tracks [Semantic Versioning](https://semver.org/), starting from the first
tagged release, `v0.1.0`. Detailed per-CL descriptions live under `cls/`, indexed by
`CL.md`; this file is the operator-facing summary.

## [Unreleased]

### Added
- **A troubleshooting guide.** `docs/TROUBLESHOOTING.md` lists the common
  problems, the log lines that each one produces, and what to do. (CL 89)
- **The blocklist `loaded` log line says where each list came from.** A new
  `from` attribute is `download` (fetched now), `cache` (at startup, the on-disk
  cache was less than 24 hours old, so s-hole did not fetch), or `stale_cache` (the fetch
  failed, so s-hole used an older cache). Before, a cache load and a download
  logged the same line. (CL 88)
- **DNS over TLS for LAN clients.** An optional encrypted listener (RFC 7858),
  usually on port 853. It is aimed at Android's default Automatic Private DNS
  mode: the phone uses DoT on its own when the network's DNS server offers it
  and does not check the certificate, so a self-signed certificate works and
  the phone needs no setup. Set `dot_listen`, `tls_cert`, and `tls_key` to turn
  it on; it is off by default. The README also covers strict mode (a domain you
  own and a publicly trusted certificate) and desktop DoT clients. DoT queries
  get the same blocking, cache, and logging as plain ones. If the port is taken
  or the certificate does not load, s-hole stops with an error instead of
  running without DoT. Tested with `systemd-resolved` on Debian 12 in both
  modes, and with Android Automatic mode on Bliss OS 16.9.7 (Android 13) in
  VirtualBox. Android strict mode rejected a user-installed certificate, so it
  needs a publicly trusted one; that route is untested, and the README says so.
  (CL 86)
- **Certificate renewal without a restart.** A reload (the dashboard button,
  `POST /api/reload`, `systemctl reload s-hole`, SIGHUP, or the periodic
  refresh) re-reads the DoT certificate and key. If the new files do not load,
  s-hole keeps serving the current certificate. The systemd unit gains
  `ExecReload`. (CL 86)
- **DoT certificate status.** The dashboard header shows a certificate badge
  (OK, EXPIRES SOON, EXPIRED, RELOAD FAILED). `/api/stats` has a `dot` object,
  and `/metrics` has `shole_dot_certificate_expiry_timestamp_seconds` and
  `shole_dot_certificate_reload_failures_total`, with example alert rules and
  Grafana panels. The log and `-check-config` warn when the certificate has
  expired or expires within 14 days. (CL 86)
- **DNS-over-HTTPS (DoH) upstream forwarding.** An `upstreams` entry can now be a
  DoH endpoint with an IP host, for example `https://1.1.1.1/dns-query` (also
  `8.8.8.8`, `9.9.9.9`). s-hole POSTs the query to it over HTTPS (RFC 8484), so
  the hop to the upstream is encrypted and an ISP that intercepts plain port-53
  traffic no longer sees or rewrites it. DoH and plain entries share the one
  ordered list and the same failover, so listing a plain resolver after a DoH
  entry keeps a fallback. The DoH host must be an IP, not a hostname. (CL 85)

### Changed
- **A DoH upstream with user info or with no path is dropped.** An entry such
  as `https://user:pass@1.1.1.1/dns-query` or `https://1.1.1.1` now gets the
  `ignoring malformed upstream` warning at startup, like any other malformed
  entry. User info would show on the unauthenticated `/metrics` page, and a
  DoH endpoint is a path on the server (`/dns-query`). (CL 91)
- **The pprof warning has its advice in a `hint` field.** The message
  `pprof endpoints enabled; bind api_listen to localhost only` is now
  `pprof endpoints enabled`. Update a log search that matches the old text.
  (CL 91)
- **A Windows service tells Windows how long a stop can take.** The stop
  state now carries a 15-second wait hint. (CL 91)
- **A port conflict on the DNS port stops startup with `dns listen failed`.**
  s-hole now binds UDP and TCP right after it reads the config, before it
  loads the blocklists. Before, the conflict showed later, as `dns server
  failed`. `dns server failed` now means that a listener failed while
  s-hole ran. The three `udp listener shutdown`, `tcp listener shutdown`,
  and `dot listener shutdown` warnings are now one message, `dns listener
  shutdown failed`, with a `net` field. Under the Windows service, the WARN
  `dns server stopped` is now the ERROR `dns server failed`. (CL 90, b/063)
- **The Windows service restarts after a failure.** `-service install` sets
  three restart actions, 5 seconds apart. An existing service does not get
  them. To add them, run the two `sc.exe` commands in the README section
  "Windows (system service)". (CL 90, b/065)
- **The uninstaller lists extra files in `/etc/s-hole`.** Before it deletes the
  directory, its prompt names every entry there other than `config.yaml` (such as
  a DoT certificate and key), and its summary counts them. (CL 86)
- **Reload log lines no longer say "blocklist".** A reload now also re-reads the
  DoT certificate, so `blocklist reload requested via API` and `blocklist reload
  requested via timer` became `reload requested via API` and `reload requested
  via timer`. Update any log search or alert that matches the old text. (CL 86)
- **The dashboard's Reload Blocklists button is now Reload.** It also re-reads
  the DoT certificate when DoT is on. (CL 86)
- **`POST /api/reload` answers `"reload queued"` instead of `"reload already in
  progress"`.** A reload request that arrives during a reload is now queued, not
  dropped (see Fixed). Update any script that matches the old text. (CL 89, b/061)
- **Under systemd, log lines carry their priority.** Each line starts with its
  syslog priority, so `journalctl -u s-hole -p warning` shows only warnings and
  errors. Text lines in the journal have no `time=` field, because journald
  records the time. Terminal, Docker, and JSON output keep `time=`. (CL 89)
- **The periodic stats are one log line.** The multi-line `[stats]` block is now
  one `msg=stats pkg=stats` line with `uptime`, `queries`, `blocked`, `blocked_pct`,
  `local_ptr`, `cache_hits`, `cache_hit_pct`, `forward_failures`, and
  `upstream_errors`. The top-5 lists are no longer in the log; the dashboard
  and `/api/stats` show them. (CL 89)
- **Log messages say what happened.** Update any log search or alert that
  matches an old message. Old message, then new message:
  - `config` (at startup and in `-check-config`): `config load failed`
  - `config path`: `config path cannot be resolved`
  - `install`, `uninstall`, `start`, `stop`: `service install failed`,
    `service uninstall failed`, `service start failed`, `service stop failed`
  - `service`: `windows service failed`
  - `initial blocklist update`: `initial blocklist load failed`
  - `failed to load`: `blocklist load failed`
  - `block set is EMPTY: s-hole is running but blocking no domains. Check the
    blocklist URLs and network connectivity`: `block set is empty`, with the
    advice in a `hint` field
  - `SQLite logger disabled`: `query log database open failed`
  - `api server`: `admin UI server failed`
  - `dns server`: `dns server failed`
  - `api shutdown`: `admin UI shutdown failed`
  - `file log close`: `query file log close failed`
  - `db close`: `query log database close failed`
  - `recent query failed`, `top-blocked query failed`, `history query failed`:
    `query log read failed`, with a `route` field
  - `json encode failed`: `JSON response write failed`
  - `db begin failed, dropping batch`, `db prepare failed, dropping batch`,
    `db commit failed, dropping batch`: the same with `query log` in place
    of `db`
  - `db insert`: `query log insert failed`
  - `retention prune failed`, `retention prune`: `query log retention prune
    failed`, `query log retention prune done`
  - `ignoring malformed upstream (want host:port ...)`: `ignoring malformed
    upstream`, with the advice in a `hint` field
  - `admin UI listening` no longer has an `addr` field; `url` has the address.
  (CL 89)

### Fixed
- **A DoH upstream with an uppercase scheme now works.** An entry such as
  `HTTPS://1.1.1.1/dns-query` passed the config check, but s-hole did not send
  queries to it over DoH, so every query to it failed. (CL 91, b/067)
- **A blocklist download that breaks during the transfer now uses the cache.**
  If the connection closed or timed out while s-hole read the list, s-hole
  dropped the list's domains from the block set until the next good download,
  although a cache file was on disk. Now it uses the cache file, as it does
  when it cannot connect, and logs `download failed, using stale cache`.
  (CL 91, b/068)
- **A Windows service with a relative `-config` path in a subfolder now
  starts.** The service changed to the config folder and then looked for the
  relative path again from there. `-service install` stores an absolute path,
  so a service that it installed was not affected. (CL 91, b/069)
- **A reload request during shutdown no longer starts a reload.** A SIGHUP or
  an API request after the stop began could start a blocklist download that
  shutdown did not wait for. s-hole now logs `reload refused during shutdown`.
  (CL 91, b/070)
- **A DoH reply always carries the query's ID.** A DoH server or proxy that
  answered with a different DNS ID made the client discard the answer and
  retry. (CL 91)
- **A Windows service no longer writes its files into `C:\Windows\System32`.**
  Windows starts every service in that folder. The sample config's relative
  `query_db` and `cache_dir` put the query database and the blocklist cache
  there, and a relative `log_file` put the query log there too. Now the
  service starts in the directory of its config file. If you ran s-hole as a
  Windows service with relative paths, move `queries.db` from
  `C:\Windows\System32` to the folder of your `config.yaml` before you start
  the new version. This keeps your query history. (CL 90, b/066)
- **The Windows service no longer shows Running when it answers nothing.**
  If the DNS server stopped with an error, the service kept reporting
  Running and nothing restarted it. Now it stops with an error code, and
  the restart actions that `-service install` sets start it again. (CL 90,
  b/065)
- **A DNS listener that fails while s-hole runs no longer skips the
  shutdown.** s-hole exited at once, so the query log lost its last entries.
  Now it stops in order, then exits with an error, and systemd restarts it.
  (CL 90, b/064)
- **A stop right after the start no longer leaves the DNS port open.** If
  s-hole stopped before its UDP or TCP server had started, that server kept
  the port and served until the process exited. (CL 90, b/063)
- **Warnings and errors from most of s-hole were logged as INFO.** Lines from
  the `api`, `blocklist`, `config`, `dns`, and `querylog` parts had the whole
  line inside `msg` and the level INFO, for example `level=INFO msg="WARN
  download failed, using stale cache pkg=blocklist ..."`. A search for
  `level=WARN` or `level=ERROR` missed them, and the Windows Event Log recorded
  them as Information. Each line now has its real level and separate fields.
  (CL 89, b/062)
- **The blocklists now refresh every `refresh_interval`.** With the default 24h
  interval, s-hole downloaded its blocklists only every 48 hours: the first
  timer reload after a download found the cache just under 24 hours old and
  used it without a fetch. A manual reload within a day of a download also did
  not download. Every reload now downloads; only startup uses a cache that is
  less than 24 hours old. (CL 89, b/060)
- **A reload request during a reload is no longer lost.** A request from the
  timer, the dashboard, `POST /api/reload`, SIGHUP, or `systemctl reload` that
  arrived while a reload ran was dropped. Only the API reply said so. The log
  did not. For a DoT certificate renewed by a certbot deploy hook during a
  blocklist download, the new certificate then waited for the next timer
  reload. Now the request
  is queued and one more reload runs when the current one finishes. (CL 89,
  b/061)
- **`install-linux.sh --free-port-53` now frees port 53 on current systemd.** The
  installer looked for the `systemd-resolved` stub as `127.0.0.53:53`, but current
  systemd shows it as `127.0.0.53%lo:53` and runs a second stub on
  `127.0.0.54:53`. The check missed both, so the flag did nothing and s-hole
  failed to start with "address already in use". It now matches both stubs,
  checks again after the restart, and tells you when `/etc/resolv.conf` still
  points at the disabled stub. (CL 87, b/058)
- **The startup banner no longer offers container or VPN addresses.** On a host
  with Docker, the "Router setup" banner (and the installer's closing banner)
  listed the Docker bridge (`172.17.0.1`) as a DNS server for the router, which
  a router cannot reach. Container, VM, and VPN interfaces are now left out of
  the banner. s-hole still listens on the same addresses. (CL 87, b/059)

## [1.0.0] - 2026-09-18

### Fixed
- **`GET /api/queries?outcome=` now accepts the same spelling it reports.** Each
  row reports its outcome as `upstream_error`, but the filter accepted only
  `upstream-error`, so filtering by the value read back from a row silently
  returned every row. The filter now accepts both spellings. (CL 80, b/057)
- **The "Top Blocked Domains" and "Top Clients" lists no longer reorder
  equal-count entries on every refresh.** Domains with the same block count now
  keep a fixed order (by name). As a result, the "Since start" list no longer
  changes between refreshes. (CL 71)

### Added
- **Query-log export.** `GET /api/queries/export` streams the query log for
  download in CSV (default) or JSON (`?format=json`). It reuses the
  `/api/queries` filters, so a filtered export is the filtered view in bulk, and
  it is uncapped unless `?limit=N` is set. The Recent Queries panel gained Export
  CSV and Export JSON links that download the current filter; they grey out when
  query logging is off or set to `none`. The active `query_privacy` mode rides on
  a response header and a JSON envelope field. CSV fields are escaped against
  spreadsheet formula injection. Concurrent exports are bounded, returning 429
  past the limit. No new dependency. (CL 81, ROADMAP #24)
- **Prometheus and Grafana examples.** The `deploy/` directory now ships
  `prometheus.yml` (an example scrape config), `prometheus-alerts.yml` (example
  alert rules for resolver down, empty block set, stale source, query-log drops,
  forward and upstream failures, and goroutine growth), and `grafana-dashboard.json` (an
  importable dashboard for the `shole_*` metrics). They are optional and do not
  replace the built-in dashboard. No dependency and no binary change. (CL 79)
- **Go runtime gauges on `/metrics`.** Three new gauges expose process health for
  leak and heap-growth watching: `shole_goroutines` (the goroutine-leak signal,
  since s-hole runs one goroutine per in-flight query), `shole_memory_alloc_bytes`,
  and `shole_memory_heap_inuse_bytes`. They are read from the sampled
  `runtime/metrics` API once per scrape, so a scrape adds no stop-the-world pause
  and the query path is untouched. No new dependency and no config change. (CL 78)
- **Failed-query visibility.** s-hole now records a per-query outcome and shows
  failures in three places: the query-volume graph gains two lines, unresolved
  (s-hole could not answer, so it returned SERVFAIL) and upstream error (a live
  upstream returned SERVFAIL/REFUSED, which s-hole relayed); the recent-query log
  gains "Unresolved" and "Upstream error" filters (`GET /api/queries?outcome=`)
  and a status badge per row; and `/metrics` gains `shole_forward_failures_total`,
  `shole_upstream_errors_total`, and per-upstream `shole_upstream_transport_failures_total`.
  The flat log file marks a failed query with a trailing ` FAILED` token on the
  ALLOW line. Recording is forward-only: rows written before the upgrade read as
  not-failed. (CL 77)
- **"Cached" line on the query-volume graph.** The "Queries over time" graph now
  draws a third line for cache hits, next to total and blocked, so caching
  effectiveness over the day and the cache warm-up after a restart are visible;
  the cache hit rate reads off the chart as the ratio of the cached line to the
  total line. The query log records a per-query `cache_hit` flag (`GET /api/history`
  reports a `cached` count per bucket), and the flat log file marks a cache hit with
  a trailing ` CACHED` token on the ALLOW line. Recording is forward-only: rows
  written before the upgrade read as not-cached. (CL 76)
- **Query-log search and filter.** The recent-query log now filters by domain
  (substring), by block status (all, blocked, or allowed), and by client. The
  filter runs in SQL through `GET /api/queries?domain=&client=&blocked=`, so it
  matches only the stored (masked) columns. The client picker follows
  `query_privacy` and is hidden under `drop`. The active filter persists across
  reloads. A highlighted filter row (with a "Filtering: …" summary and a Clear
  button) shows while a filter is set, and the dashboard header shows the active
  `query_privacy` mode at all times. (CL 74)
- **Client name attribution.** A new `client_names` config map gives each client a
  label in the log and the Top Clients panel. A key is an exact IP or a CIDR. The
  value is the label. The panel and the recent-query log show the label with the
  masked IP beneath it. The label is read-only. s-hole resolves it from the stored
  (masked) client value, so it tracks `query_privacy` and never shows more than
  that setting allows. Under `subnet` only CIDR keys match. Under `drop` none
  match. An exact key wins over a CIDR. s-hole skips a bad key and logs a WARN.
  (CL 73)
- **Query-log privacy modes.** A new `query_privacy` setting controls how the
  client IP is stored: `raw` (as-is, the default and current behavior), `drop`
  (store no client), or `subnet` (mask the host bits to IPv4 /24 or IPv6 /64).
  The client is masked once at write time, so the text log, the SQLite log, and
  the dashboard Top Clients panel all show the same value. Use `drop` on a flat
  home LAN and `subnet` on segmented or VLAN networks. Masking is forward-only:
  rows written at `raw` keep their addresses. The Top Clients panel describes the
  active mode, and `/api/stats` echoes it. Override with `S_HOLE_QUERY_PRIVACY`.
  (CL 72)
- **A "Queries over time" graph on the dashboard.** A new panel leads the
  dashboard. It shows a chart of total and blocked queries per time
  bucket, with a 24h / 7d window toggle and a per-bucket hover readout. A new
  `GET /api/history?window=24h&bucket=1h` endpoint aggregates the query log in
  SQL. What the graph shows depends on `log_queries`: total and blocked under
  `all`, one blocked line under `blocked`, and an empty state under `none` or when
  `query_db` is unset. (CL 70)
- **Collapsible panels.** The three panels that fetch their own data (Queries
  over time, Recent Queries, Top Blocked) now have a collapse arrow. Collapsing
  a panel hides it and stops polling its endpoint; the choice is remembered in
  the browser. (CL 70)

### Changed
- **Upstreams are validated at startup.** Each `upstreams` entry must be
  `host:port`. A malformed entry (for example a bare `1.1.1.1` with no `:53`) is
  dropped with a warning, a config where every entry is malformed now fails to
  start (and fails `-check-config`) instead of returning SERVFAIL per query, and
  a single configured upstream logs a note that there is no forwarding fallback.
  (CL 82)
- **Building from source now needs Go 1.26 or later** (was 1.25). The
  `golang.org/x/sys` 0.48.0 dependency requires it. This affects source builds
  only; the release binaries and the Docker image are unchanged. (CL 75)

## [0.2.1] - 2026-09-03

### Added
- **`s-hole -check-config -config <path>`** loads and validates a config the way
  startup does, then exits (`0` and a `config OK` line when valid, non-zero with
  the failing field otherwise). Use it to check an edit before restarting the
  service. (CL 66)
- **The Linux installer is hardened against silent failures.** It validates its
  arguments (a swapped binary/config pair is now rejected, not written over each
  other), dry-runs the config before starting, warns when `systemd-resolved`
  holds port 53 (and frees it under `--free-port-53`), and health-checks the
  service after starting: a unit that does not come up prints the last log lines
  and fails the install, so a dead service no longer looks green. It also gained
  `-h`/`--help`. (CL 66)

### Changed
- **The Linux installer's safety checks are tighter.** It now rejects a binary
  that runs but does not identify as s-hole; before, any file that ran was
  accepted. It also detects the `systemd-resolved` stub on TCP port 53 as well
  as UDP. (CL 67)

### Fixed
- **A non-positive `refresh_interval` or `stats_interval` is now rejected at
  startup.** Like `db_flush_interval`, a value such as `0s` or `-5s` used to pass
  validation (and `-check-config`) and then crash a background timer once the
  service was up. All three interval fields now fail cleanly with a clear error
  instead. (CL 68)
- **A failed admin-server bind is now surfaced at startup.** If `api_listen` is
  misconfigured or its port is taken, s-hole logs a clear WARN, keeps serving
  DNS, and the startup banner reports the admin UI as unavailable instead of
  advertising a URL that refuses connections. Previously the failure was a single
  easy-to-miss log line and the banner still advertised the UI. (CL 63)
- **Blocklist source cache files no longer collide.** Cache filenames are now
  derived from a hash of the source URL, so two similar URLs cannot map to one
  file and clobber each other's cached copy. (CL 62)
- **An over-size blocklist source is no longer silently truncated.** If a source
  exceeds the 256 MiB per-source cap, s-hole now logs a WARN and keeps the
  previous cached copy (marked stale) instead of caching the truncated download
  as fresh. (CL 62)
- **`/api/stats` reports `sources` as `[]`, never `null`,** before the first
  blocklist refresh completes. (CL 62)
- **A non-positive `db_flush_interval` now fails cleanly at startup.** A value
  like `0s` or `-5s` used to crash the daemon from a background goroutine after
  the database was already open. It is now rejected with a clear config error,
  the same as a malformed duration string. (CL 61)
- **Boolean env overrides are case-insensitive and fail safe.**
  `S_HOLE_LOCAL_PTR` and `S_HOLE_ENABLE_PPROF` now accept `1`/`true`/`yes` and
  `0`/`false`/`no` in any case, and leave the setting at its default on an
  unrecognised value. Previously a value such as `TRUE` or an empty string turned
  local PTR answering (on by default) off, leaking LAN reverse-DNS upstream. (CL 61)
- **Upstream failover no longer doubles work during an outage.** When every
  upstream is failing, s-hole now contacts each configured resolver at most once
  per query. A retry-sweep bug re-contacted the resolvers that had just failed,
  which doubled failure-path latency and upstream load during an outage (the
  client result, SERVFAIL, was unaffected). (CL 60)
- **Clean shutdown no longer loses data.** On `systemctl stop`, restart, or
  Ctrl+C, s-hole now completes its ordered teardown before the process exits: it
  drains in-flight admin requests, waits for an in-flight blocklist refresh to
  finish its atomic rename, and flushes the query-log database. A race let the
  process exit early and skip these steps, which could drop the final batch of
  logged queries or cut off a refresh mid-write. The in-flight reload wait also
  gets its own timeout so a slow HTTP drain cannot shorten it. (CL 59)

## [0.2.0] - 2026-08-28

### Added
- **Windows service logging.** When launched by the Windows SCM (which gives the
  process no console), s-hole routes its application log to the Windows Event Log
  (source `s-hole`, mapping INFO/WARN/ERROR to the three Event Log severities)
  instead of a discarded stdout. `-service install` registers the event source
  and `-service uninstall` removes it. Startup errors, blocklist-refresh
  failures, and admin audit lines are now visible in Event Viewer. Linux and
  interactive runs are unchanged. (CL 57)
- **"Why is this blocked?" endpoint.** `GET /api/check?domain=NAME` returns the
  block decision (blocked, whitelisted, or allowed) and the full suffix walk that
  produced it: which parent entry matched the block set, and which whitelist
  entry overrode it. The dashboard Actions panel gets a matching "check a domain"
  box that shows the decision and the full walk. It is a read-only diagnostic: it
  bumps no counter and writes no query-log row. (CL 56)
- **Per-source blocklist health.** `/api/stats` now carries a `sources` array
  (URL, domain count, last-refresh time, and a stale flag) for each configured
  blocklist, the dashboard renders it as a "Blocklist Sources" panel with an
  OK/STALE badge, and `/metrics` adds `shole_blocklist_source_size` and
  `shole_blocklist_source_stale` gauges. When one source silently returns an
  empty or truncated list, the operator now sees which one, instead of only a
  drop in the aggregate size. (CL 55)
- **Cache drop metric and expired-slot reclaim.** A new
  `shole_cache_dropped_total` counter on `/metrics` reports entries the cache
  refused because it was full of unexpired entries, the signal that `cache_size`
  is too small for the working set. When the cache is full, `Set` now reclaims a
  slot from an expired entry (a bounded scan) before dropping, so a cache full
  of not-yet-swept expired entries no longer refuses new inserts until the
  once-a-minute sweep. Reclaimed inserts are not counted as drops, so the metric
  reports real capacity pressure rather than sweep-timing noise. (CL 54)
- **Audit logging for admin actions.** A whitelist add or remove now logs the
  domain and the requester address at `Info`, and each blocklist reload logs its
  trigger source, so a `POST /api/reload` is distinguishable from the periodic
  timer and a SIGHUP. The admin API is unauthenticated on the LAN, so these
  state changes previously left no trace in the log. (CL 45)

### Changed
- **`enable_pprof` now also enables mutex and block profiling.** With pprof on,
  `/debug/pprof/mutex` and `/debug/pprof/block` report lock contention and
  blocking events, which the Go runtime leaves off (and those endpoints empty)
  by default. Both sample rather than record every event, so the cost is small
  and is paid only while pprof is enabled, which stays off by default and should
  be bound to localhost. (CL 53)

## [0.1.0] - 2026-08-24

### Added
- **Pre-built releases.** Pushing a `v*` tag now runs
  `.github/workflows/release.yml`, which builds the four targets
  (linux/amd64, linux/arm64, linux/armv7, windows/amd64) with the version
  ldflags and attaches a per-target archive (`tar.gz` for Linux, `zip` for
  Windows, each bundling the binary, `config.yaml`, `LICENSE`, `README.md`,
  and the Linux deploy scripts) plus a `SHA256SUMS` file to a GitHub Release.
  The same tag publishes a multi-arch (amd64 + arm64) image to
  `ghcr.io/lcsabi/s-hole`. `s-hole -version` on a released build reports the
  tag instead of `dev`. (CL 43)
- **A Linux uninstaller, `deploy/uninstall-linux.sh`.** Reverses
  `install-linux.sh`. It stops and disables the service, removes the unit,
  binary, config, and the `s-hole` system user/group, and prints a summary of
  what it removed and kept. Operator data in `/var/lib/s-hole` (query log +
  blocklist caches) is preserved unless you pass `--purge`; `--restore-resolved`
  removes a `DNSStubListener=no` drop-in and restarts `systemd-resolved`; `-y`
  skips the confirmation prompt. (CL 40)
- **All-time top-blocked domains on the dashboard.** The "Top Blocked Domains"
  panel now has a "Since start / All time" toggle. "Since start" is the
  existing in-memory tally (resets when s-hole restarts); "All time" is a new
  persistent tally read from the SQLite query log, so it survives restarts and
  is not capped. It is served by a new `GET /api/top-blocked?limit=N` endpoint
  (default 50, max 1000), which returns an empty list when `query_db` is not
  configured. (CL 33)
- s-hole now logs a loud `WARN` whenever a blocklist update leaves the block
  set empty: a fresh run that could reach no source, or a source that
  responded but parsed to zero domains. Previously an empty result after a
  reachable source looked like a normal refresh in the logs, so "running but
  blocking nothing" could go unnoticed. (CL 29)
- Two standing CI safety nets: goroutine-leak detection (`go.uber.org/goleak`,
  test-only) across the cache, querylog, and DNS-server packages, and
  `govulncheck` scanning for known CVEs (also available locally via
  `make vuln`). (CL 29)
- The current number of blocked domains is now included in the `/api/stats`
  JSON response as `blocklist_size` and displayed as a "Blocklist Size" card
  on the dashboard. This confirms at a glance that the blocklist downloaded
  and parsed successfully after each refresh. (CL 28)
- PTR queries for RFC 6303 private-range reverse zones (10/8, 172.16/12,
  192.168/16, fc00::/7, fe80::/10) are now answered locally with authoritative
  NXDOMAIN instead of being forwarded upstream. No public resolver holds records
  for these addresses; forwarding only wastes a round-trip and leaks internal LAN
  addressing to the upstream resolver. Controlled by `local_ptr` (default `true`;
  set to `false` if you run a private reverse DNS zone on your LAN). The counter
  appears as `local_ptr_count` in `/api/stats` and `shole_local_ptr_total` in
  `/metrics`. The `S_HOLE_LOCAL_PTR` environment variable overrides the config.
- The dashboard shows a fourth stat card, **Cache Hit Rate**, bound to
  the `cache_hit_pct` value the UI already polls from `/api/stats`,
  the number that tells you whether `cache_size` fits your network.
- `CLAUDE.md` at the repo root gives AI coding assistants the
  canonical commands, hot-path architecture, concurrency invariants,
  and process conventions up front.
- `docs/ROADMAP.md` collects planned work (release workflow, subdomain
  blocking, DoH upstreams, hardening batch), pending decisions, and,
  equally deliberately, the non-goals, so future reviews don't
  re-propose them.
- `CONTRIBUTING.md` documents a seven-step manual smoke-test workflow
  (probes → DNS behaviour → dashboard → whitelist round-trip → reload
  → stats/metrics cross-check → persistence + shutdown) for release
  verification.
- `runTicker` now honors a context for clean shutdown: background
  tickers (stats print, blocklist refresh) exit when `doStop` cancels
  the application-wide context instead of being implicitly reclaimed
  by `os.Exit`. New `TestRunTicker_StopsOnContextCancel` regression.
- `internal/version.Info` struct + `Short()` now returns it. The
  startup-log line uses it, and the API has a real caller instead of
  being dead exported code.
- `CONTRIBUTING.md` at the repo root documents the Makefile entry
  points, fuzz-run instructions, project layout, ID conventions
  (`b/NNN`, `R NN`), coverage targets, and the doc-sync rule.
- New tests close coverage gaps the fifth review found: `Dropped()`
  actually increments under overflow + stays 0 under healthy load
  (S5); `/debug/pprof/*` is 404 by default and 200 only when
  `EnablePprof(true)` (S6); the panic-recovery log line includes the
  goroutine stack (S7 / R45 regression).
- `/readyz` readiness endpoint (200 once the blocklist has loaded; 503
  otherwise). Pairs with `/healthz` for Kubernetes-style probes.
- `/debug/pprof/*` endpoints behind `enable_pprof: true` (or
  `S_HOLE_ENABLE_PPROF=1`). Off by default. Required for live CPU/heap
  profiling during incident response.
- `shole_query_log_dropped_total` metric and `DBLogger.Dropped()`;
  operators now see when the query log channel overflows under load.
- `Store.WhitelistLen()`, an O(1) counterpart to `Len()` for the
  `/metrics` scrape path.
- Full-stack integration test wiring store + cache + querylog + handler
  + DNS server + mock upstream through three real queries.
- Fuzz tests for `ValidDomain`, `parseHostsFormat`, and `cacheFilename`.
- `make tools-install` installs `golangci-lint` into `$GOBIN`.
- CI runs `go mod verify` to catch supply-chain integrity issues.
- Build-time version identity: `internal/version` holds `Version`,
  `Commit`, and `BuildDate` vars written at link time via `-X` ldflags.
  `s-hole -version` prints the full identity; startup logs include it.
  Makefile and Dockerfile populate the values from git and the current
  UTC timestamp; CI does the same via GitHub Actions context.
- `Makefile` gains the conventional production targets: `make check`
  (fmt + vet + lint + test), `test`, `test-race`, `bench`, `lint`,
  `fmt`, `vet`, `install`, `version`, and `help`.
- `golangci-lint` integrated: `.golangci.yml` config + a lint job in
  CI that runs before the test job.
- Dependabot keeps Go modules, GitHub Actions, and the Docker base
  image up to date with weekly PRs.
- `.github/CODEOWNERS` declares review ownership.
- Pull-request template and issue templates (bug + feature) under
  `.github/`.
- Production-grade project layout: the `main` package now lives under
  `cmd/s-hole/`; `DESIGN.md`, `CL.md`, `BUGS.md`, and `CHANGELOG.md`
  live under `docs/`. The `go install` path is now
  `github.com/lcsabi/s-hole/cmd/s-hole@latest`.
- `SECURITY.md` security-disclosure policy at the repo root.
- Comprehensive test coverage round: every implementation package now
  at ≥ 85 % line coverage (`config` and `stats` at 100 %). Module-wide
  coverage went from 60.8 % to 71.3 %, with the residual being the
  `main()` bootstrap and Windows SCM glue that cannot be unit-tested.
- `SIGHUP` triggers a blocklist refresh on every non-Windows build.
  Operators can run `kill -HUP $(pidof s-hole)` or
  `systemctl kill -s HUP s-hole` to refresh without enabling the
  admin API. SIGHUP shares the single-flight gate with the timer and
  `POST /api/reload`.
- `/healthz` liveness endpoint (R4).
- `/metrics` Prometheus exposition with counters for queries, blocks,
  cache hits/misses, cache size, blocklist size, whitelist size (R3).
  Hand-rolled exposition format, no new dependencies.
- Environment-variable overrides for every commonly-tuned config field
  via `S_HOLE_*` (R5). See README for the full list.
- Upstream health tracking with a 30-second cooldown for failing
  resolvers, eliminating the "every query waits 3s on the dead primary"
  failure mode (R6).
- SQLite query-log retention via `query_db_retention_days` (R16).
- Structured logging via `log/slog` throughout the codebase. JSON
  format opt-in via `S_HOLE_LOG_FORMAT=json` (R1).
- Context propagation: forward upstream calls and SQLite reads now
  honor cancellation and deadlines (R2).
- EDNS0 OPT pseudo-record is mirrored on sinkhole replies so clients
  do not fall back to legacy DNS (R12).
- Per-domain validator (`blocklist.ValidDomain`) used both by the
  loader and by the whitelist POST endpoint (R13, R14).
- Atomic blocklist cache writes via `.tmp` + rename: torn writes
  during a network drop or process kill no longer leave a half-written
  cache file (R9).
- Top-N maps in `stats.Counter` are capped at 4096 entries; the bottom
  half is pruned when the cap is exceeded (R19).
- Recovery from `runTicker` panics: a panicking ticker function is
  logged and the next tick still fires (R8).
- ASCII fallback for the startup banner when `S_HOLE_LOG_FORMAT=json` or
  `S_HOLE_ASCII_BANNER=1` is set (R24).
- Benchmark for `blocklist.Store.IsBlocked` (R27).
- Tests for upstream forwarder with a real in-process mock UDP server,
  EDNS0 pass-through, atomic cache write, ValidDomain, top-N map cap,
  SQLite retention prune, /metrics, /healthz, env-var overrides (R27,
  R28, plus coverage for everything new in this release).

### Changed
- **Dashboard panel order.** The Actions panel (reload blocklists, whitelist a
  domain) now sits above the Recent Queries log instead of below it. Actions
  keeps a stable, reachable position, and the always-growing query log moves to
  the bottom of the page. (CL 41)
- **Blocking now matches subdomains.** A blocklist (or whitelist) entry now
  covers the whole subtree beneath it: `ads.example.com` blocks
  `x.ads.example.com` as well, so trackers can no longer sidestep a list
  entry by rotating subdomains. Lookups walk a domain's parent labels
  (`a.b.example.com → b.example.com → example.com`) instead of requiring an
  exact match. The whitelist is matched the same way and still wins at every
  level, so it remains the escape hatch for an over-broad block entry:
  whitelist `safe.doubleclick.net` (or a parent domain) to let a subtree
  through while the rest of the blocked domain stays sinkholed. There is no
  new configuration; the behaviour is unconditional. (CL 30)
- **Invalid `whitelist` entries are now dropped with a `WARN`.** Because
  whitelist matching is suffix-based (CL 30), a bare label such as a TLD
  would silently exempt its whole subtree. At startup, `config.Load` now
  drops any `whitelist` entry that is not a valid domain name (the same
  `ValidDomain` check the REST `/api/whitelist` endpoint applies) and logs
  each dropped entry at `WARN`. A typo is surfaced loudly instead of quietly
  disabling blocking for an entire suffix, and it does not abort startup: a
  dropped entry fails safe (the domain stays blockable) and one bad line
  cannot take DNS down for the LAN. (CL 31)
- **The Linux installer now prints the installed build.** `deploy/install-linux.sh`
  ends with an "Installed build" box showing the version, commit, and build date
  of the binary it just placed (`s-hole -version`). A stale `scp` was previously
  silent: the operator had no signal that the running service predated the fix
  they meant to ship. (CL 35)
- Dependency refresh via Dependabot: `alpine` 3.24 base image,
  `golang.org/x/sys` v0.47.0, and CI action majors (checkout v7,
  cache v6, setup-go v6, golangci-lint-action v9).
- The default `listen` is now `":53"` (dual-stack wildcard, IPv4 +
  IPv6) instead of the IPv4-only `"0.0.0.0:53"`, so clients querying
  over IPv6 on dual-stack LANs are served instead of silently ignored.
  Set `listen: "0.0.0.0:53"` explicitly to restore IPv4-only binding.
  The README also documents the RA/RDNSS bypass trap on IPv6 networks.
- The admin dashboard polls `/api/stats` and `/api/queries` every 3
  seconds (was 5) for a snappier live view.
- `/api/queries` clamps `?limit=` to 1000 so one request cannot
  marshal the entire history table into a single JSON response (T3).
- DESIGN's "Alternatives Considered" no longer claims Windows is the
  first-class platform. Linux is the primary deployment target; the
  Windows SCM path is the secondary supported platform.
- Default `api_listen` is now `127.0.0.1:8080`; operators who want
  LAN access must opt in explicitly (R18). Pre-existing configs that
  set `api_listen: "0.0.0.0:8080"` are unaffected.
- Implementation package `internal/dns` renamed to `internal/dnsserver`
  to disambiguate from `github.com/miekg/dns` (R7).
- HTTP server error responses no longer leak internal error strings to
  the client; the message is logged server-side and the client sees a
  generic 500.
- `querylog.DBLogger.Recent` and `TopBlocked` now take a `context.Context`
  argument so HTTP handlers can propagate request cancellation.
- `querylog.NewDBLogger` now takes a fourth argument: `retentionDays`.
- `api.New` now takes a `CacheStatser` argument (may be `nil`) so the
  `/metrics` endpoint can surface cache statistics.

### Fixed
- **A whitelist typo can no longer disable a whole TLD.** `ValidDomain` accepted
  a bare TLD written with a trailing root dot (`"com."`), which normalized to the
  bare label `"com"` and, through subtree matching, exempted every `.com` domain
  from blocking. The validator now requires an interior dot, so `"com."` (and
  `"."`, `"a."`, `".com"`) is rejected at the config, API, and dashboard entry
  points; a real FQDN like `"example.com."` stays valid. (b/040, CL 42)
- **The Docker container starts again when a data volume is mounted.** The
  binary lived at `/app/s-hole`, but `/app` is the declared volume and the
  documented `-v "$(pwd)/data:/app"` bind mount shadowed it, so the container
  died at start with `exec: "./s-hole": ... no such file or directory`, i.e.
  the recommended deployment was broken. The binary now lives on `PATH`
  (`/usr/local/bin/s-hole`), outside the `/app` data volume; every documented
  `docker run` command is unchanged. (CL 39)
- **The query-log retention prune no longer intermittently skips under
  concurrent writes.** The SQLite connection pool is now pinned to a single
  connection (with a `busy_timeout` as a backstop), so the async writer and the
  hourly prune can't collide with `SQLITE_BUSY`, which previously made the
  prune silently skip a tick and, under the race detector, flaked a CI test. No
  operator-facing behaviour change beyond retention now pruning reliably. (CL 38)
- **`/api/stats` can no longer momentarily report a cache hit rate above 100 %.**
  `Snapshot` read the cache-hit counter after the total-queries counter, so a
  concurrent cache hit slipping between the two reads could push the ratio over
  100 % on the dashboard's Cache Hit Rate card. It now reads the later-incremented
  counter first, the same fix already applied to blocked-vs-total (b/021) and
  local-PTR-vs-total (b/033). (CL 37)
- **The Linux installer now restarts the service instead of starting it**, so
  re-running `install-linux.sh` to upgrade actually swaps the running binary.
  `systemctl start` is a no-op on an already-active unit, so an upgrade would
  otherwise keep running the old build while the new "Installed build" banner
  advertised the new one, the exact stale-deploy the banner exists to catch. (CL 36)
- **Mixed-case private-range PTR queries are now answered locally.** The RFC 6303
  intercept matched names case-sensitively, so a query such as
  `1.1.168.192.IN-ADDR.ARPA.` (as produced by dns-0x20 forwarders) slipped past
  it and leaked upstream. DNS names are case-insensitive; the intercept now folds
  case before matching, like the blocklist already did. (CL 36)
- **`/api/stats` can no longer momentarily report `local_ptr_count` greater than
  `total_queries`.** `Snapshot` read the two atomic counters in an order that let
  a concurrent PTR query slip between them; it now reads the later-incremented
  counter first (the same fix already applied to blocked-vs-total, b/021). (CL 36)
- **`/debug/pprof/symbol` now accepts POST**, so `go tool pprof` can symbolize a
  remote profile against a running instance (it POSTs the program-counter list).
  The route had been registered GET-only, which answered POST with 405. Only
  relevant when `enable_pprof` is on. (CL 36)
- **The installer's admin-UI hint no longer misreports a LAN bind as
  localhost-only.** It matched only the literal `0.0.0.0`; binding to a specific
  LAN IP, a bare `:8080`, or the IPv6 wildcard now correctly prints the LAN URL,
  mirroring the in-binary banner's loopback check. (CL 36)
- The dashboard no longer displays the DNS trailing dot on domain names. The
  Top Blocked Domains and Recent Queries panels stripped it for display
  (`sub.doubleclick.net.` now renders as `sub.doubleclick.net`). Queries are
  still recorded and served over the API as the exact wire-format name; the
  change is presentation-only, so it also cleans up rows already stored in the
  query log. (CL 34)
- The shipped sample `config.yaml` is back to conservative defaults:
  `query_db: "queries.db"` (SQLite logging on) and `api_listen:
  "127.0.0.1:8080"` (localhost only). A first-hardware deployment's
  `""` / `0.0.0.0:8080` working values had been committed by accident,
  which would have exposed the unauthenticated admin UI to the LAN out
  of the box.
- The CI lint job passes again after two stacked problems: the
  `golangci-lint-action@v6` pin installs golangci-lint v1, which
  cannot even load a `version: "2"` config targeting Go 1.25 (bumped
  to `@v8`, which installs v2); and once v2 actually runs, it lacks
  the v1-era default errcheck exclusions, flagging 40+ idiomatic
  best-effort calls. Restored a documented exclusion subset in
  `.golangci.yml`, made `Server.Shutdown` log listener errors instead
  of discarding them, and fixed `make tools-install` to install
  golangci-lint v2.
- `deploy/install-linux.sh` no longer advertises `http://<lan-ip>:8080`
  for the admin UI when `api_listen` is left at the localhost-only
  default; the shell-script counterpart of the T4 banner fix. It now
  reads `api_listen` from the installed config and prints either the
  LAN URLs or a localhost note with the opt-in instruction.
- README's Docker port-conflict note no longer recommends disabling
  `systemd-resolved` entirely (which kills host DNS resolution on
  distros where `resolv.conf` points at the stub); it now shows the
  `DNSStubListener=no` drop-in that releases port 53 while keeping the
  host resolver working.
- `cache_size: 0` in the YAML file now actually disables the DNS
  response cache, as documented. Previously the post-decode default
  silently turned 0 back into 2000; only the `S_HOLE_CACHE_SIZE=0` env
  override worked (T1). `block_ttl: 0` is likewise honored now: it
  tells clients not to cache sinkhole replies.
- Truncated upstream replies (TC bit) are retried over TCP against the
  same upstream before being returned, so large answers (DNSSEC, big
  TXT/CDN RRsets) resolve instead of dead-ending the client's TCP
  fallback at the forwarder. Truncated responses are also no longer
  cached (T2).
- The DNS response cache keys unknown record types as `TYPE1234`
  instead of an empty string, so two distinct unknown qtypes can no
  longer collide on one cache entry (T6).
- One overlong blocklist line (past bufio's default 64 KiB token cap)
  no longer aborts parsing of the entire list; the parser tolerates
  lines up to 1 MiB and keeps dropping garbage per-line as before (T5).
- The startup banner no longer advertises `http://<lan-ip>:8080` for
  the admin UI when `api_listen` is bound to localhost (the default);
  it prints `http://127.0.0.1:8080 (this machine only)` instead (T4).
- Integration test no longer relies on a hardcoded 150 ms sleep to
  wait for the SQLite flush tick; it polls for up to 2 s. Fast on
  healthy CI, robust under load.
- `reloadFn` defer order collapsed into a single closure so the
  mutex is released before the WaitGroup signals done, matching
  reader expectations.
- Counter.Snapshot data race: `topN` now reads the map pointer under
  the same mutex that protects the prune-and-reassign in
  `RecordQuery`. The race detector previously fired when prune and
  snapshot collided.
- `querylog.DBLogger.run()` no longer uses a magic literal `100` for
  the per-batch flush trigger; both the cap *and* the trigger now
  reference the same `flushBatchSize` constant.
- `panic` recovery in `runTickerOnce` now logs the full goroutine stack
  via `debug.Stack()` so a panic in the field is diagnosable from
  logs alone.
- `Dockerfile` no longer installs `tzdata` (~30 MB removed). Container
  logs default to UTC, which is what production wants.
- `SECURITY.md` now points reporters at the GitHub Security Advisories
  flow rather than a personal email.
- `CODEOWNERS` and `SECURITY.md` updated for the actual GitHub handle
  (`@lcsabi`).
- Module path renamed to `github.com/lcsabi/s-hole` to match the
  GitHub account. `go install` URL changed accordingly.
- `/api/whitelist` GET now returns domains in sorted order so the UI
  doesn't shuffle between refreshes.
- `json.Encoder.Encode` errors in `/api/*` responses are now logged
  rather than discarded (R10).
- `apiServer.Shutdown` errors during `doStop` are now logged (R11).
- `blocklist.fetchList` now escapes colons in cache filenames; the prior
  scheme could not be written or renamed on NTFS for URLs with embedded
  ports.

## [Initial implementation]

See the per-CL files under `cls/CL-01.md` through `cls/CL-10.md` for the
pre-changelog development log. `CL.md` is the index.
