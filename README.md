# s-hole

[![CI](https://github.com/lcsabi/s-hole/actions/workflows/ci.yml/badge.svg)](https://github.com/lcsabi/s-hole/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lcsabi/s-hole)](https://github.com/lcsabi/s-hole/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/lcsabi/s-hole.svg)](https://pkg.go.dev/github.com/lcsabi/s-hole)
[![Go Version](https://img.shields.io/github/go-mod/go-version/lcsabi/s-hole)](go.mod)
[![License](https://img.shields.io/github/license/lcsabi/s-hole)](LICENSE)

A lightweight, self-contained DNS sinkhole for network-wide ad and tracker blocking. Deploy it on any always-on machine, point your router's DHCP DNS field at it, and every device on the network is protected, with no per-device configuration required.

s-hole is intentionally small: a single binary, a single YAML config file, no runtime dependencies. The full codebase fits comfortably in an afternoon's reading.

![s-hole dashboard](docs/dashboard.gif)

### Contents

- [Features](#features)
- [Scope & limitations](#scope--limitations)
- [Quick Start](#quick-start)
- [Configuration](#configuration) (incl. [env-var overrides](#environment-variable-overrides) and [DNS over TLS](#dns-over-tls-android-private-dns))
- [REST API](#rest-api)
- [Deployment](#deployment): [Linux/Pi](#raspberry-pi--linux-systemd), [Docker](#docker), [Windows](#windows-system-service)
- [Building from Source](#building-from-source)
- [Engineering highlights](#engineering-highlights): the code and the process
- [Architecture](#architecture)
- [Development](#development): targets, coverage, CI, fuzz, integration test
- [Security Notes](#security-notes)
- [License](#license)

For maintainer-facing material, see `docs/DESIGN.md` (design rationale), `docs/CL.md` (change-list index → `docs/cls/`), `docs/BUGS.md` (bug tracker with priorities and root-cause records), `docs/CHANGELOG.md` (release notes), `docs/ROADMAP.md` (planned work and non-goals), and `CONTRIBUTING.md`.

---

## Features

- **Network-wide blocking.** Blocks ads and trackers at the DNS layer, before any connection is established.
- **Subdomain (suffix) blocking.** A blocked domain blocks its whole subtree, so `ads.example.com` also covers `x.ads.example.com`. Trackers cannot dodge a list entry by rotating subdomains.
- **Community blocklists.** Downloads and auto-refreshes hosts-file or plain-domain lists from any URL.
- **DNS response cache.** Serves repeat queries from memory. Typical cache hit rates of 40–70% reduce upstream load and latency.
- **Resilient upstream forwarding.** Tries upstreams in order over UDP, falls back to TCP on truncation, and skips recently-failed resolvers until they recover. Forwards over DNS-over-HTTPS (DoH) when an upstream is an `https://` endpoint, to encrypt the upstream hop.
- **DNS over TLS for LAN clients.** An optional encrypted listener (usually port 853) so clients such as Android phones in Private DNS mode can use s-hole. Off by default. You supply the certificate, and a reload picks up a renewed one without a restart.
- **Local reverse DNS.** Answers PTR queries for the RFC 6303 private ranges (`10/8`, `172.16/12`, `192.168/16`, and IPv6 ULA and link-local) locally, so internal LAN addressing never leaks to the upstream resolver. On by default. Disable it with `local_ptr: false`.
- **Dual query log.** A plain-text file for `grep` and `tail`, plus a SQLite database for historical queries.
- **Query-log privacy.** Choose how the client IP is stored: keep it, drop it, or mask it to a subnet (`query_privacy`). Optional `client_names` labels map an IP or subnet to a friendly device name in the log and the dashboard.
- **Admin web UI.** Live stats, a queries-over-time graph (total, blocked, cached, and failed), top blocked domains, top clients, per-source blocklist health, and a searchable recent query log with domain, client, status, and outcome filters. Also whitelist management and a "why is this blocked?" domain check. The dashboard refreshes automatically.
- **REST API.** All UI data is available as JSON, ready for scripting and future integrations.
- **Observability.** Serves Prometheus metrics at `/metrics` (query, cache, blocklist, upstream-failure, DoT-certificate, and Go-runtime health) and liveness and readiness probes at `/healthz` and `/readyz`, with no external metrics library. Ready-made Grafana dashboard and Prometheus scrape/alert examples ship under `deploy/`.
- **Configurable sinkhole mode.** Returns `0.0.0.0` (the default, a silent failure) or `NXDOMAIN`.
- **Cross-platform.** A single binary for Windows, Linux x86-64, Linux arm64 (Pi 4/5), and Linux armv7 (Pi 2/3).
- **Windows Service.** Installs as an auto-start system service with one command.
- **Linux systemd.** Ships a hardened unit file with `CAP_NET_BIND_SERVICE`, so it needs no root at runtime.
- **Docker.** A multi-stage image of about 33 MB.

---

## Scope & limitations

- **DNS blocking is domain-granular.** It blocks third-party ad and tracker
  networks and device telemetry well, but it cannot touch ads served from the
  same domain as the content. Run a browser content blocker alongside it for
  the first-party and element-level filtering it cannot do.
- s-hole matches on the queried name and does not follow CNAME chains, so a
  cloaked tracker disguised as a first-party subdomain can slip past a
  blocklist entry. Following those chains (CNAME deep-inspection) is on the
  roadmap.
- **Faster browsing comes from blocking, not acceleration.** s-hole usually
  makes pages feel faster because the browser has less to load, not because
  your network is faster. A blocked ad or tracker domain returns `0.0.0.0`, so
  the browser never fetches that content. Repeat DNS lookups return from the
  in-memory cache with no upstream round-trip. The effect is largest on
  ad-heavy pages and low-end devices.
- **It is not a content cache.** s-hole answers DNS only. A first-time lookup
  of an allowed domain still forwards upstream through s-hole. This adds a
  small hop on a healthy LAN, but it is not faster than a direct query. s-hole
  never caches or proxies the pages you visit, so it cannot speed up
  first-party content or raise your bandwidth.

---

## Quick Start

### Prerequisites

- Go 1.26 or later (for building from source)
- Port 53 available (requires Administrator on Windows, root or `CAP_NET_BIND_SERVICE` on Linux)

### Install a pre-built release

Each tagged release attaches a per-target archive and a `SHA256SUMS` file to the
[GitHub Releases page](https://github.com/lcsabi/s-hole/releases). Download the
archive for your platform (`linux_amd64`, `linux_arm64`, `linux_armv7`, or
`windows_amd64`), then verify and unpack it:

```bash
sha256sum -c SHA256SUMS --ignore-missing   # confirm the download
tar -xzf s-hole_v1.0.0_linux_amd64.tar.gz  # Linux (unzip the .zip on Windows)
```

Each archive contains the binary, a sample `config.yaml`, `LICENSE`, `README.md`,
and (on Linux) the `deploy/` install scripts and systemd unit. The same tag also
publishes a container image. See [Docker](#docker) for the pull command.

### Install via the Go toolchain

If your `$GOBIN` is on `PATH`, the latest commit can be fetched with:

```bash
go install github.com/lcsabi/s-hole/cmd/s-hole@latest
```

### Run interactively

```bash
# Build from a local clone
go build -o s-hole ./cmd/s-hole

# Run (requires elevated privileges for port 53)
sudo ./s-hole -config config.yaml          # Linux / macOS
.\s-hole.exe -config config.yaml           # Windows (Administrator)
```

On first run, s-hole downloads the blocklists (~80 000 domains with the default lists, and the exact count shifts as the upstream lists evolve) and caches them to disk. Later starts skip the download when the cache is less than 24 hours old.

Each source download is capped at 256 MiB. Real blocklists are far smaller, so hitting the cap means a wrong URL or a broken source. If a source exceeds the cap, s-hole logs a WARN, keeps serving the previous cached copy of that source (marked stale), and does not replace it with the truncated download.

### Point your router at it

In your router's DHCP settings, set the **DNS Server** field to the IP address of the machine running s-hole. All devices on the network get the new DNS server on their next DHCP renewal (or immediately after they reconnect).

Keep a fallback upstream DNS as the secondary DNS entry (for example `1.1.1.1`). s-hole can become unavailable, so the fallback keeps the LAN online.

> **IPv6 networks:** on a dual-stack LAN, routers typically advertise a
> DNS server over IPv6 as well (via RA/RDNSS or DHCPv6), and many
> clients *prefer* it. If that advertisement still points at the router
> or your ISP, dual-stack devices will quietly bypass s-hole for most
> queries and the ads come back. Either disable the router's IPv6 DNS
> advertisement, or give the s-hole machine a stable IPv6 address and
> advertise that instead (s-hole listens on IPv6 by default via
> `listen: ":53"`).

### Verify it works

With `nslookup` (preinstalled on Windows and macOS):

```
nslookup doubleclick.net <s-hole-ip>
# expected: Address: 0.0.0.0

nslookup google.com <s-hole-ip>
# expected: a real IP address
```

Or with `dig` (`apt install dnsutils` / `dnf install bind-utils`):

```
dig @<s-hole-ip> doubleclick.net +short   # expected: 0.0.0.0
dig @<s-hole-ip> google.com +short        # expected: a real IP address
```

These commands address s-hole explicitly, so they work even before the
router change above. Network-wide blocking begins only after DHCP hands
out s-hole's address and clients renew their leases. Then devices are
filtered without naming the server.

If a query times out, check s-hole's query log (stdout, or
`journalctl -u s-hole -f` under systemd): every query that reaches the
process produces one `ALLOW`/`BLOCK` line. A missing line means the
query never arrived. Look at the network path (firewall, wrong IP,
client tool) rather than at s-hole. Under the Windows service stdout is
discarded, so set `log_file` to capture these query lines. The
application log (startup, refresh, and audit messages) goes to the
Windows Event Log automatically.

---

## Configuration

All configuration lives in `config.yaml`. Every field has a safe default. An empty file is valid.

| Field | Default | Description |
|---|---|---|
| `listen` | `:53` | Address and port for DNS queries (UDP + TCP). `:53` binds all interfaces, IPv4 + IPv6; use `0.0.0.0:53` for IPv4 only |
| `dot_listen` | _(off)_ | Address and port for the DNS-over-TLS listener, usually `:853`. Empty turns DoT off. When set, `tls_cert` and `tls_key` are required, and a port conflict or a bad certificate stops startup. See [DNS over TLS](#dns-over-tls-android-private-dns) |
| `tls_cert` | _(none)_ | Path to the PEM certificate the DoT listener presents. Re-read on every reload. Ignored while `dot_listen` is empty |
| `tls_key` | _(none)_ | Path to the PEM private key for `tls_cert`. Re-read on every reload. Ignored while `dot_listen` is empty |
| `upstreams` | `[1.1.1.1:53, 8.8.8.8:53]` | Upstream resolvers, tried in order. Each is a plain `host:port` or a DNS-over-HTTPS (DoH) endpoint with an IP host (`https://1.1.1.1/dns-query`; also `8.8.8.8`, `9.9.9.9`). DoH encrypts the upstream hop, which defeats an ISP that intercepts plain port-53 traffic; list a plain resolver after a DoH entry to keep a fallback. A DoH host must be an IP, not a hostname (a hostname-only provider is not supported yet). A malformed entry is dropped with a warning at startup, and a config where every entry is malformed fails to start |
| `blocklists` | StevenBlack + AdAway | List of URLs to download (hosts-file or plain-domain format) |
| `whitelist` | `[]` | Domains that are never blocked, regardless of blocklist membership. Matched by suffix and wins at every level: a whitelisted domain exempts its whole subtree, even past a more specific blocked parent |
| `refresh_interval` | `24h` | How often to re-download blocklists |
| `block_mode` | `zero` | Sinkhole reply: `zero` returns `0.0.0.0`/`::`, `nxdomain` returns NXDOMAIN |
| `block_ttl` | `300` | TTL (seconds) advertised on blocked replies; `0` tells clients not to cache them |
| `log_file` | stdout | Path to the plain-text query log |
| `log_queries` | `all` | Which queries to write to logs: `all`, `blocked`, or `none` |
| `query_privacy` | `raw` | How the client IP is stored: `raw` (as-is), `drop` (store no client), or `subnet` (mask to IPv4 /24 or IPv6 /64). Masked once at write time, so the logs and Top Clients agree; forward-only. Use `drop` on a flat LAN, `subnet` on segmented/VLAN networks |
| `client_names` | _(none)_ | Map of an exact IP or a CIDR to a label, shown in the log and Top Clients. The label is read-only. s-hole resolves it from the stored (masked) client, so it never shows more than `query_privacy` allows. Under `subnet` only CIDR keys match. Under `drop` none match. An exact key wins over a CIDR. s-hole skips a bad key with a WARN. No `S_HOLE_*` override. |
| `query_db` | _(off)_ | Path to the SQLite query log database; set a path to enable, empty disables it |
| `db_flush_interval` | `30s` | How often buffered queries are committed to SQLite |
| `cache_size` | `2000` | Maximum DNS responses held in the in-memory cache (0 to disable) |
| `stats_interval` | `5m` | How often stats are printed to stdout |
| `api_listen` | `127.0.0.1:8080` | Address for the admin web UI and REST API. Set to `0.0.0.0:8080` to expose to the LAN. |
| `cache_dir` | `.` | Directory for cached blocklist files |
| `query_db_retention_days` | `0` (forever) | Delete query-log rows older than this many days. `0` disables the prune. |
| `enable_pprof` | `false` | Expose `/debug/pprof/*` on the admin server. Localhost-only deployment recommended. |
| `local_ptr` | `true` | Answer PTR queries for RFC 6303 private ranges (10/8, 172.16/12, 192.168/16, fc00::/7, fe80::/10) locally with NXDOMAIN. Set to `false` if you run a private reverse DNS zone on your LAN. |

### Minimal config example

```yaml
upstreams:
  - "9.9.9.9:53"     # Quad9, privacy-focused and malware-blocking
whitelist:
  - "api.example.com"
log_queries: blocked
```

### Environment variable overrides

For container deployments where editing `config.yaml` requires a re-bind-mount, every commonly-tuned field can be overridden by an `S_HOLE_*` environment variable. The override is applied after the YAML is parsed:

| Variable | Equivalent YAML field |
|---|---|
| `S_HOLE_LISTEN` | `listen` |
| `S_HOLE_API_LISTEN` | `api_listen` |
| `S_HOLE_DOT_LISTEN` | `dot_listen` |
| `S_HOLE_TLS_CERT` | `tls_cert` |
| `S_HOLE_TLS_KEY` | `tls_key` |
| `S_HOLE_LOG_FILE` | `log_file` |
| `S_HOLE_LOG_QUERIES` | `log_queries` |
| `S_HOLE_QUERY_PRIVACY` | `query_privacy` |
| `S_HOLE_QUERY_DB` | `query_db` |
| `S_HOLE_CACHE_DIR` | `cache_dir` |
| `S_HOLE_BLOCK_MODE` | `block_mode` |
| `S_HOLE_REFRESH_INTERVAL` | `refresh_interval` |
| `S_HOLE_STATS_INTERVAL` | `stats_interval` |
| `S_HOLE_DB_FLUSH_INTERVAL` | `db_flush_interval` |
| `S_HOLE_CACHE_SIZE` | `cache_size` (integer) |
| `S_HOLE_BLOCK_TTL` | `block_ttl` (integer) |
| `S_HOLE_RETENTION_DAYS` | `query_db_retention_days` (integer) |
| `S_HOLE_ENABLE_PPROF` | `enable_pprof` (`1`/`true`/`yes` enable, case-insensitive) |
| `S_HOLE_LOCAL_PTR` | `local_ptr` (`1`/`true`/`yes` keep on; `0`/`false`/`no` opt out; case-insensitive) |
| `S_HOLE_LOG_FORMAT` | Slog handler format: `text` (default) or `json` |
| `S_HOLE_ASCII_BANNER` | set to `1` to use ASCII box-drawing on the startup banner |

### Recommended config for Raspberry Pi

```yaml
db_flush_interval: "60s"   # reduce SD card write frequency
cache_size: 5000            # more cache = fewer upstream queries
log_queries: blocked        # skip logging allowed queries to save writes
```

### DNS over TLS (Android Private DNS)

s-hole can also serve DNS over TLS (DoT, RFC 7858). A DoT client reaches s-hole over an encrypted connection, usually on port 853, and gets the same blocking, cache, and logging as a plain query. When Android's Private DNS is set to a provider hostname, the phone uses only DoT to that host and does not fall back to plain DNS, so it bypasses a plain-DNS s-hole. DoT is off by default.

> **Test status.** The DoT listener, the certificate reload, and the certificate status were tested with automated tests, `dig +tls`, and `openssl s_client`. They have **not** been tested with a real Android phone in Private DNS mode yet. Until that test is done, treat the Android steps below (the certificate route in step 1, the Android row of the client-trust table, and step 5) as untested. The Android behavior they describe comes from Android's documentation, not from a test run.

**1. Get a certificate.** A DoT client checks two things. The certificate must name the hostname the client connects with (the Subject Alternative Name, or SAN). The client must also trust the certificate's issuer. s-hole does not make a certificate for you, because only you know the hostname and can make your devices trust it. Pick one of these:

- **For Android Private DNS**, use a domain you own, such as `dns.example.com`. Get a publicly trusted certificate for it, for example from Let's Encrypt with a DNS-01 challenge (the box does not have to be reachable from the internet). In your domain's public DNS zone, add an A record that points `dns.example.com` at the s-hole box's LAN IP (s-hole cannot answer that name itself yet). The domain can be a cheap one, or a free dynamic-DNS subdomain if the provider supports the DNS-01 challenge.

  Android needs this route, not the desktop one, for two reasons:
  - **The phone must resolve the hostname.** Private DNS takes a hostname, not an IP, and the phone looks it up through the network's plain DNS, which is usually s-hole. s-hole forwards a local name such as `dns.home` upstream, where it does not exist, so the lookup fails. A name in a public DNS zone resolves through any upstream.
  - **The phone must trust the issuer.** A CA that you install on Android goes into the user store, and Private DNS probably trusts only the system store. A publicly trusted certificate is in every phone's system store already. (Untested; see the test status above.)

  Some routers and resolvers use DNS rebind protection: they drop an answer in which a public name points at a private IP. If the phone's lookups pass through such a router, `dns.example.com` does not resolve. s-hole does not filter these answers, so a phone that uses s-hole directly as its DNS server is not affected.
- **For desktop DoT clients**, use [mkcert](https://github.com/FiloSottile/mkcert). It makes a local CA, installs it on the machine that runs it, and issues the certificate. Put the hostname and LAN IP that clients use in the SAN:

  ```bash
  mkcert -install
  mkcert -cert-file cert.pem -key-file key.pem dns.home 192.168.1.10
  ```

  Then install the mkcert CA on every other client, as described in [Make clients trust the certificate](#make-clients-trust-the-certificate).
- **For a quick test only**, make a self-signed certificate with openssl:

  ```bash
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -days 397 -keyout key.pem -out cert.pem -subj "/CN=dns.home" \
    -addext "subjectAltName=DNS:dns.home,IP:192.168.1.10"
  ```

  Use it only with a client that takes the certificate for one command, such as `dig +tls-ca=cert.pem` in step 4. **Do not install this certificate as a trusted root on any device.** OpenSSL marks it as a CA, and its private key is `key.pem` on the s-hole box. Anyone who gets that key could then sign a certificate for any website, and every device that trusts `cert.pem` would accept it.

**2. Install the files.** The systemd service runs as the `s-hole` user and cannot see home directories (`ProtectHome=true`). Put the files in `/etc/s-hole/` and keep the key private:

```bash
sudo install -m 644 -o root -g s-hole cert.pem /etc/s-hole/cert.pem
sudo install -m 640 -o root -g s-hole key.pem  /etc/s-hole/key.pem
```

**3. Turn DoT on.** Add these lines to `/etc/s-hole/config.yaml`:

```yaml
dot_listen: ":853"
tls_cert: "/etc/s-hole/cert.pem"
tls_key: "/etc/s-hole/key.pem"
```

Then validate the file and restart:

```bash
s-hole -check-config -config /etc/s-hole/config.yaml
sudo systemctl restart s-hole
```

If the port is in use or the certificate does not load, s-hole stops with an error. It does not start without DoT.

**4. Test it.** This needs `dig` from BIND 9.18 or later. `+tls-ca` names the CA to trust for this one command: `cert.pem` for the openssl test certificate, or `"$(mkcert -CAROOT)/rootCA.pem"` for mkcert. With a publicly trusted certificate, leave out `+tls-ca`.

```bash
dig +tls +tls-ca=cert.pem +tls-hostname=dns.home @192.168.1.10 -p 853 doubleclick.net
```

A blocked domain returns `0.0.0.0`. A wrong hostname fails with "hostname mismatch".

**5. Point Android at it** (untested; see the test status above). Open the Private DNS setting (Settings → Network & internet → Private DNS on most phones; the path varies). Choose "Private DNS provider hostname" and enter the hostname from the certificate. The name points at a LAN address, so the phone cannot reach it away from home. On mobile data or another Wi-Fi network, the phone then reports that the Private DNS server cannot be reached and has no DNS. Set Private DNS back to Automatic or Off when you leave the LAN.

**Watch the certificate.** When DoT is on, the dashboard header shows a certificate badge: OK with the days left, EXPIRES SOON inside 14 days, and EXPIRED or RELOAD FAILED in red. Hover over it for the certificate names, the expiry, and the last reload error. `/api/stats` carries the same data in its `dot` object. `/metrics` exposes `shole_dot_certificate_expiry_timestamp_seconds` and `shole_dot_certificate_reload_failures_total`, and `deploy/prometheus-alerts.yml` has example alerts for both. s-hole also logs a WARN at startup, on every reload, and in `-check-config` when the certificate has expired or expires within 14 days.

**Renewing the certificate.** Replace the two files, then reload with `sudo systemctl reload s-hole`, the dashboard reload button, `POST /api/reload`, or SIGHUP. New connections get the new certificate, and there is no restart. The periodic blocklist refresh also reloads it. If the new files do not load, s-hole keeps the current certificate and logs a WARN. Certbot keeps its keys where only root can read them, so use a deploy hook that copies the files and reloads. Make the script executable (`chmod +x`). Certbot runs deploy hooks only on renewal, so run the script once by hand after the first issuance:

```sh
#!/bin/sh
# /etc/letsencrypt/renewal-hooks/deploy/s-hole.sh
install -m 644 -o root -g s-hole "$RENEWED_LINEAGE/fullchain.pem" /etc/s-hole/cert.pem
install -m 640 -o root -g s-hole "$RENEWED_LINEAGE/privkey.pem"   /etc/s-hole/key.pem
systemctl reload s-hole
```

**Docker.** Put the files in `data/` (the container sees them under `/app`), set `tls_cert: "/app/cert.pem"` and `tls_key: "/app/key.pem"`, and publish the port, for example `-p 192.168.1.10:853:853/tcp`. To reload, run `docker kill -s HUP s-hole` (the container runs Linux on every host), or use the dashboard or `POST /api/reload`.

#### Make clients trust the certificate

A client accepts the certificate only if it trusts the issuer. What you must do depends on the certificate route from step 1:

- **Publicly trusted certificate (ACME):** nothing. Every device already trusts the issuer. This is the only route that needs no work on each device.
- **mkcert:** install the mkcert CA certificate on each client. It is `rootCA.pem` in the folder that `mkcert -CAROOT` prints. Copy only `rootCA.pem`. Never copy `rootCA-key.pem`; keep it on the machine where you ran mkcert.
- **openssl test certificate:** do not install it on any device (see step 1).

To install `rootCA.pem` on a client:

| Client | How |
|---|---|
| Debian, Ubuntu | `sudo cp rootCA.pem /usr/local/share/ca-certificates/s-hole-ca.crt`, then `sudo update-ca-certificates`. The file name must end in `.crt`. |
| Fedora, RHEL | `sudo cp rootCA.pem /etc/pki/ca-trust/source/anchors/s-hole-ca.pem`, then `sudo update-ca-trust`. |
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain rootCA.pem` |
| Windows | In an Administrator prompt: `certutil -addstore -f Root rootCA.pem` |
| iOS, iPadOS | Send the file to the device (AirDrop or email) and install it in Settings → General → VPN & Device Management. Then turn on full trust in Settings → General → About → Certificate Trust Settings. |
| Android | Settings → Security → Encryption & credentials → Install a certificate → CA certificate. This adds the CA to the user store, and Private DNS probably ignores user-installed CAs (untested; see the test status above). Use a publicly trusted certificate for Android. |

The trust must be where the DoT client looks. Some clients use the system store, for example `systemd-resolved` with `DNSOverTLS=yes` and `DNS=192.168.1.10#dns.home`. Others read their own CA file, such as `dig +tls-ca=` or stubby's `tls_ca_file`.

> **Warning.** A CA that a device trusts can vouch for any website, and the trust is not limited to your DNS server. Whoever holds the CA's private key can impersonate any site to that device. Install a private CA only on devices you control, and keep its key off the s-hole box.

---

## REST API

The admin web UI is served at **`http://127.0.0.1:8080`** by default. This is localhost only, so a fresh install is not reachable from the LAN. Set `api_listen: "0.0.0.0:8080"` in `config.yaml` (or `S_HOLE_API_LISTEN=...`) to expose it. All data is also available as JSON.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/stats` | Live stats: uptime, query totals, block rate, cache hit rate, blocklist size, per-source blocklist health, top domains/clients (each client carries an optional `client_names` `label`), the active `query_privacy` mode, and a `dot` object with the DNS-over-TLS certificate state (`enabled`, `listen`, `names`, `not_after`, `expires_in_days`, `state` = `ok`/`expiring`/`expired`/`reload_failed`, and the last reload result) |
| `GET` | `/api/check?domain=NAME` | Why a domain is blocked: the decision plus the full suffix walk (matched block entry, overriding whitelist entry). Diagnostic; changes no state and does not count in stats |
| `GET` | `/api/queries?limit=N` | Last N queries from SQLite, newest first (default: 50, max: 1000). Filter with `?domain=` (substring), `?client=` (exact match on the stored value), `?blocked=true`/`false`, or `?outcome=unresolved`/`upstream-error` (failed queries). Each row carries a computed `outcome` (`allowed`/`blocked`/`unresolved`/`upstream_error`) and an optional `client_names` `label` |
| `GET` | `/api/queries/export?format=csv` | Download the query log for analysis in another tool. `?format=csv` (default) or `json`, streamed. Reuses the `/api/queries` filters, so a filtered export is the filtered view in bulk; uncapped unless `?limit=N` is set. Empty (valid) file when `query_db` is unset |
| `GET` | `/api/top-blocked?limit=N` | All-time most-blocked domains from SQLite (default: 50, max: 1000); empty when `query_db` is unset |
| `GET` | `/api/history?window=24h&bucket=1h` | Per-bucket total, blocked, cached (cache-hit), unresolved, and upstream-error query counts over the window, from SQLite (default: 24h window, 1h bucket; bucket count capped at 1000). Reports the effective `log_queries` mode (`all`/`blocked`/`none`/`off`), so the graph reflects only what is logged; empty when `query_db` is unset |
| `GET` | `/api/whitelist` | List all runtime-whitelisted domains |
| `POST` | `/api/whitelist` | Add a domain. Body: `{"domain": "example.com"}` |
| `DELETE` | `/api/whitelist?domain=…` | Remove a domain from the runtime whitelist |
| `POST` | `/api/reload` | Trigger an immediate reload: re-read the DoT certificate (when DoT is on), then refresh the blocklists. De-duplicated via a single-flight mutex; returns `"reload already in progress"` if one is already running |
| `GET`  | `/healthz` | Liveness probe. Always 200 OK while the HTTP server is responsive |
| `GET`  | `/readyz` | Readiness probe. 200 OK once the blocklist has loaded at least one entry, 503 otherwise |
| `GET`  | `/metrics` | Prometheus text exposition of the `shole_*` series: query, cache, blocklist, upstream-failure, DoT certificate (when DoT is on), and Go-runtime metrics. See the [Metrics reference](docs/DESIGN.md#metrics-reference) for the full list. |
| `GET`  | `/debug/pprof/*` | Standard Go pprof endpoints. Registered **only** when `enable_pprof: true` is set in config (or `S_HOLE_ENABLE_PPROF=1`). Pair with `api_listen: "127.0.0.1:8080"`. |

Runtime whitelist changes take effect immediately but do not persist across restarts. To make a whitelist entry permanent, add it to `config.yaml`.

---

## Deployment

The Quick Start runs s-hole as a foreground process. It lives exactly
as long as your terminal session and dies with a reboot, a crash, or a
logout. That is fine for evaluation, but once your router points the LAN
at s-hole, every device's internet depends on it. Deployment registers
the binary as a **service**: the operating system (systemd, the Windows
SCM, or Docker's restart policy) starts it at boot, restarts it if it
crashes, and runs it detached from any user session.

If you want the admin dashboard reachable from other devices, set
`api_listen: "0.0.0.0:8080"` in `config.yaml` **before** installing.
The default binds localhost only, and the UI is unauthenticated, so
LAN exposure is a deliberate opt-in.

### Raspberry Pi / Linux (systemd)

```bash
# Cross-compile on your development machine:
make pi          # arm64 (Pi 4, Pi 5)
make pi32        # armv7 (Pi 2, Pi 3)

# Copy binary, config, and the install/uninstall scripts to the Pi:
scp s-hole-linux-arm64 pi@raspberrypi.local:~/
scp config.yaml pi@raspberrypi.local:~/
scp deploy/install-linux.sh deploy/uninstall-linux.sh pi@raspberrypi.local:~/

# On the Pi, run the installer as root:
sudo bash install-linux.sh ./s-hole-linux-arm64 ./config.yaml
```

The installer creates a `s-hole` system user, places the binary at `/usr/local/bin/s-hole`, installs config to `/etc/s-hole/config.yaml`, and enables the service to start on boot. Before it starts the service it validates the arguments (so a swapped binary/config pair fails loudly, not silently), dry-runs the config through the binary, and warns if `systemd-resolved` is holding port 53. After the start it health-checks the unit: if the service does not come up it prints the last log lines and exits non-zero, so a dead service never looks installed. It ends by printing the installed build's version and commit. Confirm it matches the binary you meant to ship, because a stale `scp` is otherwise silent.

Run `sudo bash install-linux.sh -h` for the full options, including `--free-port-53` (disable the `systemd-resolved` stub for you when it holds port 53, instead of only warning). After it frees the port, the installer tells you if `/etc/resolv.conf` still points at the disabled stub. In that case the host has no DNS for programs that read that file (including s-hole's blocklist download) until you run `sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf`.

After installation:

```bash
sudo systemctl status s-hole     # check running state
sudo systemctl stop s-hole       # stop the service
sudo systemctl start s-hole      # start the service
sudo systemctl restart s-hole    # restart (for example after editing config)
sudo systemctl disable s-hole    # don't start on boot
sudo systemctl enable s-hole     # re-enable autostart
journalctl -u s-hole -f          # follow logs live
```

To trigger an immediate reload without restarting (Linux/macOS):

```bash
sudo systemctl reload s-hole            # via systemd
sudo kill -HUP "$(pidof s-hole)"        # or directly
```

SIGHUP is honored on every non-Windows platform. It runs the same single-flight reload as `POST /api/reload`. The reload re-reads the DoT certificate and key when DoT is on, then re-downloads the blocklists from the URLs that s-hole read at startup. It does not re-read `config.yaml`. To apply a change to any config value, restart the service.

The systemd unit runs with `CAP_NET_BIND_SERVICE` so it can bind port 53 (and 853 for DNS over TLS) without running as root. `ProtectSystem=strict` and `NoNewPrivileges` are set for defence in depth.

#### Operating an installed service

A few things to know once s-hole runs as a systemd service:

- **Config is *copied*, not live-linked.** The installer copies your config to `/etc/s-hole/config.yaml` on the **first** install only. It never overwrites an existing one (it prints `config already exists, skipping`), and re-running the installer or `scp`-ing a new file to your home directory does **not** update it. To apply a config change on an installed host, edit `/etc/s-hole/config.yaml` directly (or `sudo cp your-config.yaml /etc/s-hole/config.yaml`), then `sudo systemctl restart s-hole`. To catch a mistake before the restart, validate the file first with `s-hole -check-config -config /etc/s-hole/config.yaml`, which loads and validates it exactly the way startup does and exits non-zero on any error. A reload (`POST /api/reload` or SIGHUP) does not apply a config edit. It re-downloads from the URLs read at startup and re-reads the certificate files at the `tls_cert` and `tls_key` paths read at startup, so a changed blocklist URL or a changed certificate path also needs a restart to take effect.
- **`S_HOLE_*` environment overrides do not reach the service.** The systemd unit runs with a clean environment, so shell env vars only take effect when you run the binary directly. On the service, put values in `/etc/s-hole/config.yaml` (or add `Environment=` lines to the unit).
- **`query_db` and `cache_dir` are relative to `/var/lib/s-hole`.** Relative paths resolve against the service's working directory. Because the unit sets `ProtectSystem=strict` with `ReadWritePaths=/var/lib/s-hole`, the rest of the filesystem is read-only to the service. Keep both paths under `/var/lib/s-hole` (the defaults `queries.db` and `.` already do). Pointing them at `/tmp` or a home directory will silently fail to write.
- **The query log flushes on an interval.** Newly logged queries appear in `/api/queries` and the dashboard's "All time" panel only after the next SQLite flush (`db_flush_interval`, default `30s`), not instantly. Lower it for a more responsive view.

To remove s-hole, run the bundled uninstaller as root (from the `deploy/`
directory, or wherever you copied it):

```bash
sudo bash uninstall-linux.sh                     # keep /var/lib/s-hole (query log + caches)
sudo bash uninstall-linux.sh --purge             # also delete /var/lib/s-hole
sudo bash uninstall-linux.sh --restore-resolved  # also restore the systemd-resolved stub on :53
```

It stops and disables the service, removes the unit, binary, config
(`/etc/s-hole`), and the `s-hole` system user and group, then prints a summary
of what it removed and kept. `/etc/s-hole` also holds any files you added to it,
such as a DNS-over-TLS certificate and key. The prompt lists them before it
deletes them, so back up a key you have no other copy of. Your query history and blocklist caches in
`/var/lib/s-hole` are preserved unless you pass `--purge`. `--restore-resolved`
applies only if you had freed port 53 by disabling the `systemd-resolved` stub.
It removes that drop-in and restarts the resolver. The flags combine
(`--purge --restore-resolved` is a full teardown); add `-y` to skip the
confirmation prompt.

### Docker

**1. Create a data directory and place your config in it:**

```bash
mkdir -p data
cp config.yaml data/
```

The container uses `/app` as its working directory and reads config from
`/app/config.yaml`. Mounting `./data` there keeps all persistent files (the
SQLite database, blocklist cache, and config) on the host so they survive
container restarts and image upgrades.

For the admin dashboard to be reachable through Docker, set
`api_listen: "0.0.0.0:8080"` in `data/config.yaml`. The default binds
`127.0.0.1`, which inside a container answers only the container's own loopback,
not the published port, so the dashboard would refuse connections. Container
`0.0.0.0` does **not** mean "exposed to the world": which host interface actually
reaches it is decided by the `-p …:8080` mapping in step 4, and the UI is
unauthenticated, so it is not exposed until you publish it.

**2. Find the host's LAN IP.**

The machine running s-hole needs a stable LAN address, a static IP or a DHCP
reservation, because it's what your router hands out to every client as the DNS
server, and what the container binds below. Find it:

```bash
ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1   # for example 192.168.1.10
```

**Why bind to this address rather than publish on all interfaces?** Most Linux
hosts run `systemd-resolved`, which already holds `127.0.0.53:53`. A bare
`-p 53:53` publishes on `0.0.0.0` (every interface, loopback included) and
collides with it, and `docker run` fails with *"address already in use."* Binding
to the LAN IP sidesteps the conflict (`systemd-resolved` only ever binds
loopback, never the LAN interface) and keeps the unauthenticated dashboard off
every other interface. (Docker Desktop for Mac/Windows has no such listener, so
a bare `-p 53:53` works there too, but the LAN-IP form below is correct
everywhere.)

**3. Build the image** (or pull a pre-built one):

```bash
docker build -t s-hole .
# Or pull a tagged release instead of building:
#   docker pull ghcr.io/lcsabi/s-hole:1.0.0   (and use that name in step 4)
```

**4. Run** (substitute the address from step 2):

```bash
HOST_IP=192.168.1.10          # the LAN IP from step 2
docker run -d \
  --name s-hole \
  --restart unless-stopped \
  --cap-add=NET_BIND_SERVICE \
  -p ${HOST_IP}:53:53/udp -p ${HOST_IP}:53:53/tcp \
  -p ${HOST_IP}:8080:8080 \
  -v "$(pwd)/data:/app" \
  s-hole
```

Point your router's DHCP **DNS Server** field at `${HOST_IP}`, and open the
dashboard at `http://${HOST_IP}:8080`. For a host-only dashboard, publish it as
`-p 127.0.0.1:8080:8080` instead.

> **The startup banner shows the container's IP, not the host's.** s-hole prints
> a "Router setup" box with a DNS-server and Admin-UI address, but from inside
> the container it can only see its own bridge address (for example `172.17.0.2`). It
> has no way to know the host IP or the port you published. **Under Docker,
> ignore those lines** and use `${HOST_IP}` (the address you bound above) for
> both the router setting and the dashboard URL.

After the first run `./data` will look like this:

```
data/
├── config.yaml             ← your config (you created this)
├── queries.db              ← SQLite query log
└── blocklist_*.txt         ← cached blocklist downloads
```

To update config, edit `./data/config.yaml` and restart the container:

```bash
docker restart s-hole
```

**On Windows (Docker Desktop)**, the host has no `systemd-resolved` stub on port
53, so the conflict above does not apply and you can publish on all interfaces
with the bare form. Use backtick for line continuation and `${PWD}` for the
current directory:

```powershell
docker run -d `
  --name s-hole `
  --restart unless-stopped `
  --cap-add=NET_BIND_SERVICE `
  -p 53:53/udp -p 53:53/tcp `
  -p 8080:8080 `
  -v "${PWD}\data:/app" `
  s-hole
```

This publishes the unauthenticated dashboard on every interface. To keep it
host-only use `-p 127.0.0.1:8080:8080`, or pin it to one address by prefixing
the port with that IP as in the Linux command. Point your router at the Windows
machine's LAN IP, not the container address the startup banner prints.

> **Want s-hole on every interface (`0.0.0.0:53`) instead of one LAN IP?** Then
> the `systemd-resolved` stub has to give up port 53. Turn off *just* the stub,
> not the whole service:
> ```bash
> sudo mkdir -p /etc/systemd/resolved.conf.d
> printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
> sudo systemctl restart systemd-resolved
> ```
> The installer does the same when you pass `--free-port-53`; `uninstall-linux.sh --restore-resolved` reverses it.
> `systemd-resolved` still resolves for local programs that use NSS, but on
> distros where `/etc/resolv.conf` points at `127.0.0.53`, releasing the stub
> leaves anything that reads `resolv.conf` directly without a resolver. Repoint
> `/etc/resolv.conf` afterwards, for example to resolved's upstream list with
> `sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf`, or at s-hole. Only then can you use
> the bare `-p 53:53` / `-p 8080:8080` form.

### Windows (system service)

Run once as Administrator to register s-hole as an auto-start Windows Service:

```powershell
# Install (uses the config path you specify, must be absolute)
.\s-hole.exe -service install -config C:\s-hole\config.yaml

# Start / stop
.\s-hole.exe -service start
.\s-hole.exe -service stop

# Remove
.\s-hole.exe -service uninstall
```

The service can also be managed through the standard Windows Services panel (`services.msc`) or `sc.exe`.

Windows has no SIGHUP. To reload the blocklists, or a renewed DNS-over-TLS certificate, use the dashboard reload button or `POST /api/reload`.

A service has no console, so s-hole routes its application log (startup,
blocklist refresh, and audit messages) to the Windows Event Log. Read it in
Event Viewer under **Windows Logs > Application**, source **s-hole**. `-service
install` registers the event source and `-service uninstall` removes it. The
per-query `ALLOW`/`BLOCK` log is separate: set `log_file` to keep it, since
stdout is discarded under the service.

### Monitoring (Prometheus + Grafana)

s-hole serves Prometheus metrics at `/metrics`, and the built-in dashboard covers
the day-to-day view with no extra software. If you already run Prometheus and
Grafana, the `deploy/` directory has ready-made assets to plug s-hole into that
stack:

- `deploy/prometheus.yml`: an example scrape config for the s-hole target.
- `deploy/prometheus-alerts.yml`: example alert rules (resolver down, empty block
  set, stale source, dropped query-log rows, forward and upstream failures,
  goroutine growth, and, with DNS over TLS on, certificate expiry and failed
  certificate reloads).
- `deploy/grafana-dashboard.json`: a dashboard for the `shole_*` metrics. Import it
  in Grafana (Dashboards > New > Import) and pick your Prometheus data source.

These are optional. They do not replace the built-in dashboard.

The default `api_listen` binds `127.0.0.1`, so Prometheus must run on the same
host. To scrape from another host, set `api_listen: "0.0.0.0:8080"` and use the
LAN IP as the target. Do not expose `/metrics` to the public internet: the admin
API is unauthenticated.

---

## Building from Source

```bash
# Current platform
make

# Cross-compilation targets
make pi          # Linux arm64 (Raspberry Pi 4 / 5)
make pi32        # Linux armv7 (Raspberry Pi 2 / 3)
make linux       # Linux amd64

# Clean
make clean
```

All targets produce a statically linked binary with debug info stripped (`-ldflags="-s -w"`). No CGO is required, because `modernc.org/sqlite` is a pure Go SQLite port.

On Windows without `make`, use PowerShell:

```powershell
$env:GOOS="linux"; $env:GOARCH="arm64"
go build -ldflags="-s -w" -o s-hole-linux-arm64 ./cmd/s-hole
$env:GOOS=""; $env:GOARCH=""
```

---

## Engineering highlights

*The parts worth reading the code for, and the process behind them.*

**In the code:**

- **A lock-free stats hot path with a proven concurrency invariant.** Per-query counters update without locks; `Snapshot` must read every counter a query touches *after* `total` *before* it reads `total`, or a dashboard ratio can momentarily exceed 100%. I hit that exact race on multiple counters, then encoded a standing load-order invariant plus a race-tested regression per counter so the next one can't slip in. ([`internal/stats`](internal/stats))
- **Suffix-match subdomain blocking** that walks a name's parent labels in `O(labels)` with zero per-query allocation, closing the subdomain-rotation hole that exact-match blockers leave open. ([`blocklist.Store.IsBlocked`](internal/blocklist/store.go))
- **Resilient upstream forwarding.** UDP with automatic TCP fallback on truncation, plus a health tracker that skips recently-failed resolvers and retries them only if every other upstream also failed.
- **RFC 6303 local PTR answering.** Private-range reverse queries are answered locally instead of leaking internal LAN addressing to the upstream resolver.
- **Deliberate non-decisions.** Case-insensitive caching was rejected because it would break dns-0x20 downstream resolvers; admin authentication was rejected in favour of a documented localhost-only scope. Knowing what *not* to build is recorded in [`docs/ROADMAP.md`](docs/ROADMAP.md).
- **A tiny dependency graph and pure-Go SQLite.** No CGO, so cross-compiling for every release target stays a one-liner and the binary is fully static.

**In the process,** built with the discipline of a long-lived, multi-maintainer codebase rather than a one-shot script:

- **A living design doc** ([`docs/DESIGN.md`](docs/DESIGN.md)) captures the rationale and the rejected alternatives behind each decision.
- **Every change is a small, self-contained change-list** with motivation, files touched, and testing notes ([`docs/cls/`](docs/cls)).
- **A bug tracker with priorities and structured root-cause/fix records** ([`docs/BUGS.md`](docs/BUGS.md)), including entries deliberately marked *Won't Fix (by design)*.
- **Documentation drift is treated as a bug.** Code and docs are updated in the same change.
- **CI gate on every push**: `gofmt`, `go vet`, `golangci-lint`, race-enabled tests, `govulncheck`, and a cross-compile of every release target. The core `internal/` packages meet the coverage targets (see the [targets under Development](#development)).

---

## Architecture

```
                   Client devices (DNS via DHCP)
                                │
                                │ UDP/TCP :53, DoT :853 (opt-in)
                                ▼
     ┌──────────────────────────────────────────────────────┐
     │                   s-hole process                     │
     │                                                      │
     │   ┌──────────────────────────────────────────────┐   │
     │   │  DNS Handler  (per query)                    │   │
     │   │    1. private PTR → local NXDOMAIN (RFC6303) │   │
     │   │    2. blocklist  → sinkhole reply            │   │
     │   │    3. cache hit  → cached reply              │   │
     │   │    4. cache miss → upstream forward + cache  │   │
     │   └──────────────────────────────────────────────┘   │
     │                                                      │
     │   ┌───────────┐   ┌──────────┐   ┌───────────┐       │
     │   │ Blocklist │   │  Stats   │   │ Querylog  │       │
     │   │   Store   │   │ Counter  │   │ file + DB │       │
     │   └───────────┘   └──────────┘   └───────────┘       │
     │                                                      │
     │   ┌──────────────────────────────────────────────┐   │
     │   │  Admin HTTP server (default localhost:8080)  │   │
     │   │   /api/* + web UI                            │   │
     │   │   /healthz   /readyz   /metrics              │   │
     │   │   /debug/pprof/* (opt-in)                    │   │
     │   └──────────────────────────────────────────────┘   │
     │                                                      │
     │   Signals: SIGINT/SIGTERM → shutdown                 │
     │            SIGHUP (Unix)  → reload (cert + lists)    │
     │   Timers : periodic refresh; periodic stats print    │
     └──────────────────────────────────────────────────────┘
                                │  on cache miss
                                │  ctx-bounded; 3 s per upstream
                                │  + 30 s health cooldown
                                ▼
                    Upstream DNS (1.1.1.1, 8.8.8.8)
```

### Repository layout

```
.
├── cmd/s-hole/        application entry point (main package)
├── internal/          implementation packages (not importable externally)
├── deploy/            systemd unit, Linux install/uninstall scripts, Prometheus/Grafana examples
├── docs/              DESIGN, CHANGELOG, BUGS, ROADMAP, and CL.md (index)
│   └── cls/           one file per CL (CL-01.md … CL-NN.md)
├── .github/           CI workflows, dependabot, CODEOWNERS, PR & issue templates
├── .golangci.yml      lint config
├── CLAUDE.md          AI-assistant guidance (commands, architecture, conventions)
├── config.yaml        default configuration
├── Dockerfile         multi-stage container build
├── Makefile           build + lint + test + install targets
├── CONTRIBUTING.md    development workflow + PR conventions
├── LICENSE            MIT
├── README.md          you are here
└── SECURITY.md        security disclosure policy
```

### Package layout

All implementation packages live under `internal/` so they cannot be imported by external modules.

| Package | Responsibility |
|---|---|
| `internal/blocklist` | Download, parse, cache, and serve the domain block set |
| `internal/cache` | TTL-based in-memory DNS response cache |
| `internal/dnsserver` | UDP/TCP server and the optional DNS-over-TLS listener (certificate reload and status), per-query handler, upstream forwarding with health tracking |
| `internal/querylog` | Async file and SQLite query loggers |
| `internal/stats` | Atomic counters; top-N domain/client tracking |
| `internal/api` | HTTP handlers and embedded web UI |
| `internal/config` | YAML loading with defaults and validation |
| `internal/service` | Windows Service integration (build-tagged) |

### Dependencies

The "afternoon's reading" claim extends to the dependency graph: a small set of direct modules linked into the binary, listed below, chosen where hand-rolling would be a source of subtle bugs and skipped everywhere else. (`go.uber.org/goleak` is a test-only direct module. It runs the suite under a goroutine-leak check and is never compiled into the shipped binary.)

| Module | Why it's a dependency |
|---|---|
| `github.com/miekg/dns` | Complete RFC-compliant DNS codec, server, and client; rolling our own would be a correctness minefield |
| `modernc.org/sqlite` | Pure-Go SQLite for the query log; no CGO, so cross-compilation stays a one-liner |
| `gopkg.in/yaml.v3` | Parses `config.yaml` |
| `golang.org/x/sys` | Windows Service Control Manager and Event Log integration |

The indirect modules in `go.mod` are almost all pulled in by the pure-Go SQLite port; none are used directly. Everything else is deliberately hand-rolled or omitted. The Prometheus exposition is written by hand rather than importing `client_golang`, the web UI is framework-free embedded HTML/CSS/JS, and the systemd integration is a static unit file rather than a service library. The reasoning behind each choice (and the alternatives rejected) is in `docs/DESIGN.md`. New dependencies need discussion first; see `CONTRIBUTING.md`.

---

## Development

The `Makefile` is the canonical entry point for every routine task. Run `make help` for the full list. The most useful targets:

```bash
make check       # gofmt + go vet + golangci-lint + shellcheck + go test
make test        # plain test run
make test-race   # tests under the race detector (CGO toolchain required)
make bench       # one iteration of each benchmark
make lint        # golangci-lint
make lint-sh     # shellcheck the deploy scripts
make vuln        # govulncheck: scan deps + code for known CVEs
make fmt         # gofmt -s -w
make install     # go install into $GOBIN
make version     # print the version that the next build would embed
```

Coverage targets (checked in review, not a strict CI gate; run
`go test -cover ./...` for the current numbers):

| Package | Target |
|---|---|
| `internal/stats`, `internal/config`, `internal/version` | 100 % |
| `internal/cache` | ≥ 94 % |
| `internal/api`, `internal/blocklist`, `internal/dnsserver`, `internal/querylog` | ≥ 85 % |

The `cmd/s-hole` bootstrap and the platform-specific `internal/service` glue sit
below these targets: the uncovered region is the `main()` wiring and the
Windows-only SCM and Event Log glue, which need a running binary or Windows and
are exercised by manual smoke tests, not unit tests. Run `go test -cover ./...`
for the current numbers.

The binary reports its build identity at any time:

```
$ s-hole -version
s-hole v1.0.0
  commit:  ab12cd3
  built:   2026-06-24T12:00:00Z
  go:      go1.26.0
  os/arch: linux/amd64
```

`s-hole -check-config -config <path>` loads and validates a config the same way startup does, then exits: `0` and a `config OK` line when it is valid, non-zero with the failing field otherwise. Use it to check an edit before restarting the service; the installer runs it automatically before the first start.

CI runs lint + `go mod verify` + race-enabled tests + `shellcheck` (deploy scripts) + `govulncheck` + cross-compile for `linux/{amd64,arm64,armv7}` and `windows/amd64` on every push and PR; see `.github/workflows/ci.yml`. The race-enabled run also exercises `go.uber.org/goleak`, which fails the goroutine-heavy packages (cache, querylog, dnsserver) if any goroutine outlives its tests. Dependabot keeps Go modules, GitHub Actions, and the Docker base image up to date.

Fuzz tests live alongside the unit tests for `blocklist.ValidDomain`, `blocklist.parseHostsFormat`, and `blocklist.cacheFilename`. Run them ad-hoc with `go test -fuzz=FuzzValidDomain -fuzztime=30s ./internal/blocklist/`.

A full end-to-end integration test (`internal/dnsserver/integration_test.go`) wires the store + cache + querylog + handler + DNS server + a mock UDP upstream together and exercises three real DNS queries through it, catching wiring bugs that unit tests miss.

---

## Security Notes

- s-hole is designed for **LAN deployment only**. Do not expose port 53 to the public internet. There is no rate limiting or source validation.
- The SQLite query log and flat log file contain full browsing history for all devices. Treat them as sensitive data. Use `log_queries: none` if you do not need query history.
- The admin UI has no authentication. Set `api_listen: "127.0.0.1:8080"` to restrict it to localhost, or use a firewall rule to limit access. The HTTP server enforces read/write/idle timeouts and a 64 KiB request body limit to defend against slowloris-style attacks from LAN peers, but these are no substitute for proper access control on a multi-user network.
- Blocklist URLs are operator-controlled. Use HTTPS URLs from sources you trust.
- The DoT private key (`tls_key`) lets anyone who holds it impersonate your resolver. Keep it readable only by root and the `s-hole` group (mode `640`). The DoT listener caps open connections and times out slow TLS handshakes, but like port 53 it is meant for the LAN only. A private CA that you install on clients is trusted for every website, so keep its key off the s-hole box, and never install the openssl test certificate as a trusted root (see [Make clients trust the certificate](#make-clients-trust-the-certificate)).

---

## License

[MIT](LICENSE). See the `LICENSE` file for the full text.
