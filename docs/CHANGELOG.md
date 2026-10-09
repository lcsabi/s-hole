# Changelog

All notable changes to s-hole are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project loosely
tracks [Semantic Versioning](https://semver.org/), starting from the first
tagged release, `v0.1.0`. Detailed per-CL descriptions live under `cls/`, indexed by
`CL.md`; this file is the operator-facing summary.

## [Unreleased]

### Changed

- **More reverse lookups stay on the LAN.** With `dns.local_ptr: true` (the
  default), s-hole now answers "no such name" itself for the reverse lookups
  of `127/8`, `0/8`, `169.254/16`, `100.64/10` (CGNAT and Tailscale), the
  IPv4 and IPv6 documentation ranges, `255.255.255.255`, `::`, and `::1`
  (RFC 6303, RFC 6598), and for the public IPv6 prefix of the s-hole host's
  own LAN. An IPv6 address made from a device's MAC address names the device,
  so these lookups no longer go to the upstream. (CL 101)
- **`fritz.box` is a built-in local domain.** Names under it, such as
  `laptop.fritz.box`, go only to an upstream on the LAN, like `.lan` and
  `home.arpa`. If you added `fritz.box` to `dns.local_domains`, you can
  remove it. The entry does no harm. (CL 101)
- **A search domain that is not local is reported.** At startup, s-hole logs
  an INFO line, `a search domain of this host is not a local domain`, for
  each `search` or `domain` entry in the host's resolver files
  (`/etc/resolv.conf` and `/run/systemd/resolve/resolv.conf`) that is not a
  local domain. If the router uses that domain for the devices on the LAN,
  add it to `dns.local_domains`. s-hole does not add it on its own. (CL 101)
- **A failed read of the interface addresses is logged.** When s-hole cannot
  read the addresses of its network interfaces, for example under a systemd
  sandbox without `AF_NETLINK`, it keeps the last list it read. With no list,
  it refuses devices that use a public IPv6 address, and reverse lookups for
  the LAN's own IPv6 prefix go upstream. s-hole now logs a WARN, `interface
  address read failed`, at most once an hour, with a hint. (CL 101)
- **DNS over TLS accepts TLS 1.3 only.** In TLS 1.2, a resumed session sends
  its session ticket in clear text, so an observer on the LAN could link the
  DoT connections of one device. Android 10 and later support TLS 1.3.
  Android 9 can no longer use s-hole's DoT: in Automatic Private DNS mode
  it sends plain DNS to s-hole, and in strict mode it cannot resolve names. (CL 102)
- **New metric `shole_forward_limited_total`.** It counts the queries that
  got SERVFAIL because of the forward limit (see Security below). (CL 102)
- **Smaller Docker image.** The image sets the binary's file capability in
  the build stage, so it no longer stores the binary twice: about 34 MB on
  disk instead of 60 MB, and about 10 MiB to download instead of 18 MiB
  (amd64). The image works the same way. (CL 103)

### Fixed

- **The Windows dashboard purge empties the query log file.** On Windows,
  the **Delete history** button overwrote the query log file with zeros but
  could not empty it: the step failed with `empty failed: ... Access is
  denied`, and the file kept its size. Now s-hole empties the file through a
  second handle, after it checks that the path still names the open log
  file. (CL 107, b/105)
- **Subnet masking fails closed.** Under `query_log.clients: "subnet"`, a
  client value that s-hole cannot parse is now stored or logged empty, not
  unchanged. The allowlist audit line was affected: for a requester with a
  link-local IPv6 address (with a zone, such as `fe80::1%eth0`) it logged the
  full address, while `query_log.mode` recorded queries and `admin.listen`
  was on an IPv6 address. It now logs no address for such a requester.
  (CL 101, b/101)
- **A DoH upstream's redirect is no longer followed.** On an HTTP 307 or 308
  redirect, s-hole sent the query again to the redirect target, which could
  be another host or a plain `http://` URL. Now a redirect is a failed
  attempt: s-hole tries the next upstream, and the failure summary shows
  `redirect refused`. (CL 102, b/102)
- **The admin web server's own error lines hold no address.** When a
  dashboard or API request failed with a program error, Go's web server wrote
  a line with the device's IP address and port, at INFO, outside the `api`
  logger. Now this line, and every other line the web server writes on its
  own, goes to the `api` logger at ERROR as `admin HTTP server error`, with
  each IP address replaced by `client`. No request is known to cause this
  error. (CL 104,
  b/103)

### Security

- **A public or CGNAT IPv4 subnet on an interface is no longer LAN.** s-hole
  answered every device in a subnet of its own interfaces. On a host with a
  public IPv4 address (a rented server) or a CGNAT address (`100.64.0.0/10`),
  that let the neighbors in the provider's network use s-hole and probe its
  cache. Now an IPv4 interface subnet counts only inside the private ranges.
  s-hole logs a WARN, `an interface subnet is not treated as LAN`, that names
  each such subnet. A VPN interface address, such as a Tailscale
  `100.x.y.z/32`, also gives this WARN. An upstream in such a subnet, such as
  an internet provider's router at a CGNAT address, no longer counts as an
  upstream on the LAN, so s-hole does not send local names to it. IPv6
  interface subnets are LAN as before. There is no setting to change this.
  (CL 101)
- **DNS server limits.** At most 512 queries wait for an upstream at the same
  time. A query over this limit gets SERVFAIL at once, counts as unresolved,
  and shows as `forward limit` in the `queries could not be resolved` line.
  The plain-TCP listener caps open connections at 256, like the DoT listener.
  One device on the LAN can no longer hold thousands of upstream queries or
  idle TCP connections. There is no rate limit for each client, because it
  would keep client addresses in memory. (CL 102)
- **A query whose source address s-hole cannot read gets REFUSED.** The LAN
  check ran only for a valid source address. The DNS listeners always give
  one, so no query reached this case; the check now fails closed. (CL 101,
  b/100)
- **The admin server refuses requests from another site.** A web page could
  not read the admin API through your browser, but it could send GET requests
  to it: time a `/api/queries?domain=` reply to guess whether the history
  holds a name, or start exports. Now a request that the browser marks as
  sent from another site (`Sec-Fetch-Site: cross-site` or `same-site`) gets
  403 on every route. A link from another page still opens the dashboard.
  `curl`, Prometheus, and the healthcheck send no such header and are not
  affected. Browsers send the header only to `localhost`, a loopback address,
  or HTTPS, so this protects the default `127.0.0.1:8080` bind, not a
  dashboard opened by its LAN address over plain HTTP. (CL 104)
- **The allowlist API has limits.** `POST /api/allowlist` refuses a
  two-label entry that starts with `co`, `com`, `org`, `net`, `gov`, `ac`, or
  `edu`, such as `co.uk`, with 400: the entry would unblock every site under
  that public suffix. The allowlist keeps at most 1,000 entries added through
  the API; when it is full, a new entry gets 409 until you remove one. The
  entries in `blocking.allowlist` do not count and have no limit. The
  dashboard shows the reason. (CL 104)
- **The dashboard runs no inline script.** The dashboard script is now a
  separate file, and the Content-Security-Policy no longer allows inline
  script. If an injection ever got into the page, the browser would not run
  it. (CL 104)
- **A purge overwrites the query files with zeros.** `s-hole -purge`, the
  dashboard's **Delete history** button, and `uninstall-linux.sh --purge` now
  overwrite the query log file with zeros and sync it before they empty or
  delete it. When s-hole is stopped, the purge also overwrites the query
  database and its `-wal` and `-shm` files with zeros before it deletes
  them. Before, a stopped purge only deleted the files, and a purge of a
  running s-hole only emptied the log file, so the history stayed in free
  disk blocks. The purge does not overwrite through a symbolic link or a file
  with more than one hard link. When s-hole is
  stopped, it keeps that file; when s-hole runs, it still empties the log
  file. In both cases it reports the step as failed. The overwrite is best
  effort (see `PRIVACY.md`). (CL 105)
- **The write-ahead log is overwritten before SQLite frees it.** SQLite keeps
  copies of the changed database pages, with domains, clients, and times, in
  the `-wal` file next to the query database. SQLite empties that file
  after a retention prune and during a purge, and deletes it when s-hole
  stops. It did not overwrite the file first, so the copies stayed in free
  disk blocks. Now s-hole overwrites the file with zeros first: when it
  starts, after a retention prune, during a purge, and when it stops. If
  another program reads or writes the database at that moment, or the
  `-wal` file is a link, s-hole does not overwrite or empty the file. At
  startup, after a prune, and at a stop, it logs the WARN `query log WAL
  overwrite failed`; a purge reports the step as failed. (CL 110)
- **The systemd unit puts s-hole in a sandbox.** s-hole cannot see other
  processes, cannot reach hardware devices or change kernel settings, and
  can use only the system calls of a normal network service. It can open
  only Unix, IPv4, IPv6, and netlink sockets. `systemd-analyze security
  s-hole` now rates the unit "OK", not "MEDIUM". To get the new unit, run
  `install-linux.sh` again. (CL 106)
- **Hardened `docker run` examples.** The README examples now use
  `--read-only`, `--security-opt no-new-privileges:true`, and
  `--cap-drop ALL --cap-add NET_BIND_SERVICE`. With `--cap-drop ALL` alone,
  the container stops at start with `operation not permitted`. The bridge
  example explains why port 53 is published on the host's IPv4 address:
  without an address, Docker relays IPv6 queries with the bridge gateway
  (for example `172.17.0.1`) as the source, so the LAN check cannot refuse
  an IPv6 source from the internet. (CL 106)
- **The Windows service can no longer change its binary or its config.**
  `-service install` gave the service account "modify" on the config
  folder, and the README put the binary there too. A program that took
  control of s-hole could replace `s-hole.exe` or `config.yaml`. An
  administrator who ran that binary later (for example, with `-purge`) then
  ran the program as Administrator. Now the service can read the config
  folder and change only the files that it creates. `-service install`
  refuses a binary that the service account can change or replace, a binary
  in the config folder, a missing `config.yaml`, a shared config folder such
  as a drive root, and a config folder that holds a link or a file that
  another account owns. Put the binary in `C:\Program Files\s-hole` and
  the config in `C:\ProgramData\s-hole`. An installed service keeps the
  old access list until you move it. To move an install from `C:\s-hole`,
  follow "Upgrade from an install in `C:\s-hole`" in the README. On
  Windows, the purge now also refuses a file with more than one hard link.
  (CL 107, b/104)
- **Signed releases.** Each release archive, the binary in it, and the
  container image now have a signed build provenance attestation. It shows
  that the release workflow of `lcsabi/s-hole` built the file from the
  release tag. Check it with `gh attestation verify <file> --repo
  lcsabi/s-hole` (see "Install a pre-built release" in the README). The image
  also has an SBOM, and the release notes name the Go release that built the
  archives and the image (the same one, from the `golang` image that the
  Dockerfile pins). A published release and its tag cannot change.
  The workflows pin every action to a commit SHA and give each job only the
  token rights that it needs, and the Dockerfile pins its base images by
  digest. A weekly scan runs `govulncheck` on the binaries of the latest
  release. (CL 108)
- **Built with go1.26.9.** The v2.0.1 binaries were built with go1.26.8.
  `govulncheck -mode=binary` finds 12 standard-library advisories in them
  (for example in `net/http` and `html/template`) that go1.26.9 fixes.
  This release builds the archives and the image with go1.26.9 or later.
  (CL 108)

## [2.0.1] - 2026-10-08

A patch release with privacy and security fixes. The config format and the
config defaults do not change. One change is visible on the dashboard: under
the default `query_log.mode: "none"` the "Queries over time" graph is now
empty (see Changed). Lines that s-hole 2.0.0 already wrote to the system
journal stay there; s-hole cannot delete them (see `docs/TROUBLESHOOTING.md`).

### Changed

- **A query with RD=0 gets REFUSED.** A query with the RD (recursion desired)
  bit clear, such as `dig +norec`, reads only the cache. A LAN device
  was able to read the cache with it and not add to the cache. The remaining
  TTL of a cached answer showed when another device queried the name. s-hole
  now refuses such a query, as Unbound does by default, and does not count or
  record it. Stub resolvers always set RD, so devices see no change. (CL 97)
- **The "Queries over time" graph follows `query_log.mode`.** Under the
  default `query_log.mode: "none"` the graph is now empty, and the panel says
  why: the counts per minute show when the household is active, so s-hole no
  longer keeps them by default. Under `"blocked"` the graph shows the blocked
  queries only; under `"all"` it shows every line, as before. The counters
  since startup (Total Queries, Blocked, Block Rate, Cache Hit Rate) do not
  change. To get the graph back, set `query_log.mode` to `"blocked"` or
  `"all"`. (CL 99)
- **No query names in the application log.** Under `query_log.mode: "all"`, a
  failed reply write logged one WARN with the domain, and the once-a-minute
  `queries could not be resolved` line had a `last_domain` field. Both are
  gone: the domain stays in the query log, which retention and purge reach. A
  reply that s-hole cannot send now goes into a once-a-minute summary,
  `replies could not be sent`, with the count and the errors. The WARN for
  each failed write (`write response failed`, `write sinkhole reply failed`,
  and the other `write ... failed` lines) is gone under every mode. (CL 99)
- **The allowlist audit line follows the query log settings.** `allowlist
  entry added` and `allowlist entry removed` still name the domain. The line
  has the address of the device that made the change only while
  `query_log.mode` is `"blocked"` or `"all"`, masked like a query-log row by
  `query_log.clients`: no `client` field under `"drop"`, the subnet under
  `"subnet"`, the address under `"full"`. Under the defaults the line has no
  address. (CL 99)

### Fixed

- **The cache served one client's DNSSEC choice to every client.** s-hole
  sends the client's CD and DO bits upstream, but cached the reply without
  them. After one CD=1 query (checking disabled), every device got the
  unvalidated answer, including a name that fails DNSSEC validation. After a
  DO=0 query, a client that asked for DNSSEC records got none. The cache key
  now holds both bits. (CL 97, b/096)
- **The stats line no longer writes the query counts to the system log.**
  Every 5 minutes, the `msg=stats` line logged the counts since startup, also
  under the default settings. The difference between two lines showed how
  many queries the household made in each 5 minutes, and s-hole cannot delete
  the system journal. The line now holds the uptime only. The dashboard and
  `/metrics` still show the counts. The warnings line still follows the stats
  line. (CL 99, b/098)
- **An admin API write error no longer logs the client's address.** When a
  browser or script closed the connection during a response or an export,
  the WARN held both socket addresses. The error is now logged without them.
  (CL 99, b/099)

### Security

- **An upstream reply must match the query.** s-hole accepts a reply only when
  it is a response to a standard query with the same name, type, and class.
  Any other reply counts as a failed attempt, and s-hole tries the next
  upstream. The failure summary shows it as `reply does not match the query`,
  and `shole_upstream_transport_failures_total` counts it. On a plain-DNS
  upstream, a spoofed reply for another name then cannot get into the cache.
  (CL 97)
- **The cache keeps an answer for one day at most.** An answer leaves the cache
  after 86,400 seconds (Unbound's default `cache-max-ttl`), whatever TTL the
  upstream gave. A cached answer never has a TTL longer than that. (CL 97)
- **An HTTPS blocklist download no longer follows a redirect to plain HTTP.**
  Before, a list URL that redirected from `https://` to `http://` was
  downloaded in plain text with no warning, so anyone on the network path
  could change the list. s-hole now refuses such a redirect, logs
  `blocklist redirect refused` with both URLs, and uses its cached copy of the
  list if it has one. Without a copy, the list does not load. A redirect to
  another HTTPS host still works. (CL 98, b/097)

## [2.0.0] - 2026-10-07

This release changes the config format and every default (CL 93). Read the
upgrade notes first.

### Upgrade to 2.0 (read first)

s-hole 2.0 is private by default. It records no queries and no client
addresses until you turn that on, and it warns, at startup and with every
stats line, about each setting that records more. The config file has a new
layout, so a 1.x config needs an edit. (CL 93)

1. **Move the config to the 2.0 layout.** Keys now sit in four sections. A 1.x
   key is ignored, with a `config problem` warning that names its new key, and
   that setting uses its 2.0 default, which is never less private than the old
   value. `s-hole -check-config` fails while any 1.x key is left.
   `install-linux.sh` runs the same check with the new binary before it
   changes anything. If the check fails, the 1.x install keeps running as it
   was. A 1.x build reads a 2.0 file without an error, but with its 1.x
   defaults, so do not edit `/etc/s-hole/config.yaml` in place while 1.x
   runs. Write the 2.0 config to a new file. Then check it, put it in place,
   and run the installer with one command. The command checks the new file
   first; if the check fails, it stops before it replaces the installed config:

   ```bash
   sudo ./s-hole -check-config -config config-2.0.yaml \
     && sudo install -m 640 -o root -g s-hole config-2.0.yaml /etc/s-hole/config.yaml \
     && sudo bash install-linux.sh ./s-hole ./config.yaml
   ```

   | 1.x key | 2.0 key | Value changes |
   |---|---|---|
   | `listen` | `dns.listen` | |
   | `dot_listen`, `tls_cert`, `tls_key` | `dns.dot_listen`, `dns.dot_cert`, `dns.dot_key` | off is `"off"` |
   | `upstreams` | `dns.upstreams` | default is now Quad9 DoH, Cloudflare DoH, Quad9 plain, Cloudflare plain |
   | `cache_size` | `dns.cache_entries` | |
   | `local_ptr` | `dns.local_ptr` | |
   | `blocklists` | `blocking.lists` | |
   | `whitelist` | `blocking.allowlist` | |
   | `block_mode` | `blocking.reply` | `zero` is `zero_ip` |
   | `block_ttl` | `blocking.reply_ttl_seconds` | |
   | `refresh_interval` | `blocking.refresh_interval` | |
   | `cache_dir` | `blocking.cache_dir` | |
   | `log_queries` | `query_log.mode` | default `"none"` (was `all`) |
   | `query_privacy` | `query_log.clients` | `raw` is `full`; default `"drop"` (was `raw`) |
   | `query_db` | `query_log.database` | off is `"off"`; default off |
   | `log_file` | `query_log.file` | empty used to mean standard output: now `"off"` is off and `"stdout"` is standard output; default off |
   | `query_db_retention_days` | `query_log.retention_days` | default 7 (was 0, forever) |
   | `db_flush_interval` | `query_log.flush_interval` | |
   | `client_names` | `query_log.client_names` | |
   | `api_listen` | `admin.listen` | |
   | `enable_pprof` | `admin.pprof` | |
   | `stats_interval` | `stats_interval` | unchanged |

   An `S_HOLE_*` variable is now `S_HOLE_` plus the key path:
   `S_HOLE_LISTEN` is `S_HOLE_DNS_LISTEN`, `S_HOLE_API_LISTEN` is
   `S_HOLE_ADMIN_LISTEN`, `S_HOLE_QUERY_DB` is `S_HOLE_QUERY_LOG_DATABASE`,
   `S_HOLE_LOG_QUERIES` is `S_HOLE_QUERY_LOG_MODE`, `S_HOLE_QUERY_PRIVACY` is
   `S_HOLE_QUERY_LOG_CLIENTS`, `S_HOLE_RETENTION_DAYS` is
   `S_HOLE_QUERY_LOG_RETENTION_DAYS`, and so on. A 1.x variable is ignored
   with a warning that names the new one.
2. **Decide what to keep.** The 2.0 defaults keep no history. To keep one, set
   `query_log.mode` and `query_log.database`, and s-hole warns while they are
   on. With retention on, the first prune at startup deletes the rows older
   than `query_log.retention_days` (7 by default). Query lines no longer go to
   the system journal unless you set `query_log.file: "stdout"`.
3. **Check names and addresses that changed.** The allowlist API is
   `/api/allowlist` (was `/api/whitelist`), the metric is
   `shole_allowlist_size`, and `/api/check` reports `allowlisted` and
   `matched_allowlist`. `/api/stats` has a `privacy` object and `warnings`
   instead of `query_privacy`. The export headers are
   `X-Shole-Query-Log-Clients` and `X-Shole-Query-Log-Mode`, and the JSON
   export has `clients` and `mode`. The dashboard answers only requests
   addressed to an IP address, `localhost`, or the machine's own hostname: a
   name from your router, such as `pi.lan`, gets `421`.
4. **Docker:** the image runs as UID 65532. Run
   `sudo chown -R 65532:65532 data` once on the host directory you mount at
   `/app`. Until you do, s-hole still resolves and blocks, and its warnings
   name this command. `--cap-add=NET_BIND_SERVICE` is no longer needed. Host
   networking is now the recommended Linux setup (see the README).
5. **Windows service:** uninstall and install the service again, so it runs
   as `NT SERVICE\s-hole` and its folder gets an owner-only access list.
6. **The host that runs s-hole** should not use s-hole as its own DNS server.
   s-hole now warns when it does; the README shows how to set the host's
   resolver.
7. **Local names** such as `printer` or `nas.lan` now go only to an upstream
   on the LAN (CL 94). If they resolved before because one of your upstreams
   was the router, nothing changes. Otherwise s-hole answers them with "no
   such name" and logs `no upstream on the LAN` at startup. To resolve them,
   add the router to `dns.upstreams` after the DoH entries. If the router
   uses its own domain, such as `fritz.box`, add it to `dns.local_domains`.


### Added
- **A minimal upstream query.** s-hole sends the upstream a new query with
  only the question, a few flags, a random query ID (ID 0 over DoH), and its
  own EDNS record. The device's EDNS options (a cookie that identifies the
  device, a Client Subnet) and its query ID no longer leave the LAN, and
  s-hole sends no cookie of its own. The cache no longer passes one device's
  reply options to another. (CL 94)
- **Local names stay on the LAN.** Single-label names (`printer`) and names
  under `.local`, `home.arpa`, `.internal`, `.test`, `.intranet`,
  `.private`, `.corp`, `.home`, `.lan`, and `.localdomain` go only to an
  upstream on the LAN; with none, s-hole answers "no such name". The new
  setting `dns.local_domains` adds router domains such as `fritz.box`.
  `localhost` names get the loopback address, and `.onion`, `.invalid`, and
  `.alt` names get "no such name", with no query upstream. A new counter
  counts these local answers: `local_name_count` in `/api/stats`,
  `shole_local_names_total` in `/metrics`, and `local_names` in the stats
  line. (CL 94)
- **EDNS padding (RFC 8467).** DoH queries are padded to a multiple of 128
  bytes, so their size does not show the name. A DoT reply is padded to a
  multiple of 468 bytes when the device padded its query. (CL 94)
- **Wildcard blocklists.** A `*.example.com` line, as in oisd's "domains
  (wildcards)" lists, blocks the domain and its subdomains; before, such a
  list loaded 0 domains. (CL 95)
- **A warning for a list s-hole cannot read.** When a list is empty, or s-hole
  skips more of its lines than it reads, it logs `blocklist has no domains` or
  `blocklist lines skipped` (with the counts), with a hint that names the
  formats it reads. An Adblock list, such as EasyList, now gives this warning.
  (CL 95)
- **Private defaults, and a warning for every exception.** Each setting that
  is less private or less secure than its default gives a `privacy warning` at
  `-check-config` and at startup, and one `privacy and security warnings in
  effect` line repeats all of them with every stats line. The dashboard shows
  them too. They cannot be turned off. s-hole also warns about stored rows
  written under a less private setting (with the date retention removes
  them), about queries sent unencrypted because every DoH upstream failed, and
  about queries refused from outside the LAN. (CL 93)
- **Delete the query history.** `s-hole -purge`, `POST /api/purge`, and a
  dashboard button on the s-hole host delete the stored queries, the query log
  file, the downloaded blocklists, the Top lists, the per-minute graph, and the
  DNS response cache. `uninstall-linux.sh --purge` runs it. (CL 93)
- **`PRIVACY.md`**: every place s-hole keeps or sends data, with the defaults,
  how long it stays, who can read it, and how to delete it. Release archives
  include it. (CL 93)
- **The dashboard says what s-hole records**: the query log mode, the client
  setting, and the stored-history retention, with a red badge while the history
  records which device asked. Its 24-hour graph now comes from per-minute
  counts kept in memory (no domains, no clients, never on disk), so it works
  under every setting. (CL 93)
- **`s-hole -healthcheck`**, used by the Docker image's new `HEALTHCHECK`. (CL 93)
- **A warning when the s-hole host uses s-hole as its own DNS server**,
  checked at startup, hourly, and in the installer, with a README walkthrough to set the
  host's resolver. (CL 93)
- **Metrics:** `shole_refused_total`, `shole_upstream_plaintext_fallback_total`,
  and `shole_query_log_file_dropped_total`. (CL 93)
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
  the phone needs no setup. Set `dns.dot_listen`, `dns.dot_cert`, and `dns.dot_key`
  to turn it on; it is off by default. The README also covers strict mode (a domain you
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
- **DNS-over-HTTPS (DoH) upstream forwarding.** A `dns.upstreams` entry can now be
  a DoH endpoint with an IP host, for example `https://1.1.1.1/dns-query` (also
  `8.8.8.8`, `9.9.9.9`). s-hole POSTs the query to it over HTTPS (RFC 8484), so
  the hop to the upstream is encrypted and an ISP that intercepts plain port-53
  traffic no longer sees or rewrites it. DoH and plain entries share the one
  ordered list and the same failover, so listing a plain resolver after a DoH
  entry keeps a fallback. The DoH host must be an IP, not a hostname, and the
  URL needs a path. A DoH URL with a user name or password is dropped with a
  warning that shows `redacted` in place of them. (CL 85, CL 91)

### Changed
- **A query with an opcode other than QUERY** (such as NOTIFY or UPDATE) now
  gets NOTIMP, and a query with more than one question gets SERVFAIL. s-hole
  forwarded both before. (CL 94)
- **Stricter domain validation.** s-hole now rejects a name with an empty
  label (`a..com`) or a label that starts or ends with a hyphen
  (`-ads.example.com`). DNS names cannot have either. The rule applies to
  blocklist lines, `blocking.allowlist` entries, domains added on the
  dashboard or through `POST /api/allowlist`, and the dashboard's domain
  check (`/api/check` returns 400). (CL 95)
- **Config format 2.0 and private defaults.** See "Upgrade to 2.0" above. A
  config mistake no longer stops s-hole: it warns and uses the default for that
  setting, and `-check-config` fails on any problem. Only a malformed
  `dns.listen`, an upstream list with no valid entry, and a broken DoT
  certificate pair stop startup. (CL 93)
- **The default upstreams are DoH** (Quad9, then Cloudflare), with the same two
  over plain DNS as a fallback that s-hole uses only when every DoH upstream
  has failed. (CL 93)
- **s-hole answers only clients on the local network** and refuses any other
  source. (CL 93)
- **The application log names no queried domain and no client address**,
  except a warning about one failed query under `query_log.mode: "all"` and the
  allowlist audit lines. `reload requested via API` no longer has a `client`
  field. Unresolved queries are summarized once a minute
  (`queries could not be resolved`, with each upstream's error and a hint when
  the system clock looks wrong) instead of one `upstream forward failed` line
  each. Update a log search that matched the old line. (CL 93)
- **The query log** stores times in UTC and domains in lowercase; a one-time
  migration converts the rows that are already stored. Query lines are written
  in the background and never block a DNS query. (CL 93)
- **Stored data is owner-only:** files are created with mode `600`, the data
  directory is `700`, and the systemd unit sets `UMask=0077`. An existing query
  database is tightened when it opens. (CL 93)
- **`whitelist` is now `allowlist`** in the config, the API, the metrics, and
  the dashboard. (CL 93)
- **The Docker image runs as an unprivileged user** (UID 65532), builds with a
  pinned Go release, and has a `HEALTHCHECK`. (CL 93)
- **The Windows service runs as its own virtual account** and gets an
  owner-only folder. (CL 93)
- **Blocklist downloads and DoH requests send `User-Agent: s-hole`**, and URLs
  that s-hole shows hide user info and query strings. Builds use `-trimpath`.
  (CL 93)
- **The dashboard's "All time" list is now "Stored"**, and its query filter is
  kept for the browser tab only. (CL 93)
- **The pprof warning has its advice in a `hint` field.** The message
  `pprof endpoints enabled; bind api_listen to localhost only` is now
  `pprof endpoints enabled`. Update a log search that matches the old text.
  (CL 91; CL 93 replaced it with a `privacy warning` line,
  `key=admin.pprof`)
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
    upstream`, with the advice in a `hint` field (CL 93 replaced it with a
    `config problem` line, `key=dns.upstreams`)
  - `admin UI listening` no longer has an `addr` field; `url` has the address.
  (CL 89)

### Fixed
- **A hosts list blocked `localhost.localdomain`.** The parser skipped only
  `localhost`. It now skips every localhost name: `localhost`, the names under
  it, and `localhost.localdomain`. (CL 94)
- **A cached reply lost its DNSSEC OK flag** after a few seconds, because the
  cache aged the EDNS0 OPT record like an answer (b/072). (CL 93)
- **A UDP reply could exceed what the client accepts** after a TCP retry or
  from a DoH upstream; it is now truncated with TC set (b/081). (CL 93)
- **Top Blocked split one domain by its letter case** (b/082). (CL 93)
- **Memory stayed near double after a blocklist reload**; s-hole now returns
  the freed memory at once (b/083). (CL 93)
- **The installer rejected the armv7 build on a 64-bit ARM kernel**, which runs
  it (b/084). (CL 93)
- **The smoke test's port 5353 collided with avahi**; it is now 5354 (b/085).
  (CL 93)
- **A blocklist whose cache file could not be written failed to load**; the
  downloaded list is now used with a warning. (CL 93)
- **The Router setup banner listed LAN addresses that s-hole did not listen
  on** when `dns.listen` named one address; it now shows that address
  (b/088). (CL 93)
- **`s-hole -purge` on a stopped s-hole could report success and leave the
  history** when it ran from another directory than s-hole's own; it now
  reports `not found at` with the path, and on Windows it uses the folder of
  `config.yaml` (b/091). (CL 93)
- **A reinstall after a default uninstall could not use the kept data**: the
  installer now gives the kept files back to the `s-hole` user, and a blocklist cache file that cannot
  be read is downloaded again instead of dropping the list (b/092). (CL 93)
- **A failed upgrade left the new binary installed**: `install-linux.sh` now
  checks the config before it changes anything (b/093). (CL 93)
- **An offline purge failed on Windows**: s-hole did not recognize a refused
  connection there, so `s-hole -purge` with the service stopped deleted
  nothing (b/094). (CL 93)
- **A failed download logged "using stale cache" for a cached copy that
  could not be read**; the list then failed anyway. s-hole now reads the copy
  first, and a list whose download and copy both fail names both errors
  (b/095). (CL 93)
- **The graph's last time label was cut off** at the right edge. (CL 93)
- **A `blocking.cache_dir` that did not exist was never created**, so every
  start downloaded every list again; s-hole now creates it, mode `700`
  (b/089). (CL 93)
- **A blocklist download that breaks during the transfer now uses the cache.**
  If the connection closed or timed out while s-hole read the list, s-hole
  dropped the list's domains from the block set until the next good download,
  although a cache file was on disk. Now it uses the cache file, as it does
  when it cannot connect, and logs `download failed, using stale cache`.
  (CL 91, b/068)
- **A reload request during shutdown no longer starts a reload.** A SIGHUP or
  an API request after the stop began could start a blocklist download that
  shutdown did not wait for. s-hole now logs `reload refused during shutdown`.
  (CL 91, b/070)
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
- **The blocklists now refresh every `blocking.refresh_interval`.** With the default 24h
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

### Security
- **A web page could read the query history through DNS rebinding** (b/073)
  **and change the allowlist with a cross-site request** (b/074), through the
  operator's own browser, also while the dashboard listened on localhost only.
  The admin server now answers only requests addressed to an IP address,
  `localhost`, or its own hostname, refuses cross-site requests that change
  something, requires JSON on JSON endpoints, and sends `no-store`, a CSP, and
  framing, referrer, and `nosniff` headers. (CL 93)
- **Every query went to the system journal by default**, outside retention and
  purge, and the direct writes could block queries; under load journald also
  dropped s-hole's own warnings (b/075). (CL 93)
- **Every local account could read the query history** (b/076). (CL 93)
- **A retention prune did not erase the deleted rows** from the database and
  WAL files (b/077). (CL 93)
- **The application log held query names and client addresses** whatever the
  query log settings said (b/078). (CL 93)
- **Privacy settings failed open**: an unknown key was ignored, an unknown
  client mode stored the full address, a negative retention kept everything,
  and a log file that could not open fell back to standard output (b/079).
  (CL 93)
- **s-hole answered queries from any source**, an open resolver on a host with
  a public IPv6 address (b/080). (CL 93)
- **The Windows service ran as LocalSystem** (b/086), **and the Docker image ran
  as root and built with an unpinned Go release** (b/087). (CL 93)

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
