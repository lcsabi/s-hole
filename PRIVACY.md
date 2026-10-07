# Privacy

s-hole sees every DNS query on the network it serves. A DNS log shows which
sites and apps each person in the household uses, and when. This page lists
every place s-hole keeps data or sends it, with the defaults, so you can see
exactly what a given configuration records.

The defaults are the most private choice for every setting. Each setting that
records more is an opt-in, and s-hole logs a warning for it at
`-check-config`, at startup, and with every stats line, and shows it on the
dashboard. You cannot turn these warnings off.

## What s-hole keeps

| Data | Where | Default | How long | Who can read it | How to delete it |
|---|---|---|---|---|---|
| Query history: time (UTC), domain, client (as `query_log.clients` allows), and outcome of each recorded query | SQLite file `query_log.database` | off | `query_log.retention_days`, default 7 days. Deleted rows are overwritten in the file | the s-hole user only (file mode `600`, data directory `700`); and anyone who can reach the dashboard | `s-hole -purge`, the dashboard's **Delete history** button on the s-hole host, or retention |
| Query lines: the same fields as text | `query_log.file`: a file, or standard output | off | a file: until you delete it. Standard output: the system journal or the container log keeps it under its own rules | a file: the s-hole user only (mode `600`). The journal: root and the `adm` and `systemd-journal` groups (on Raspberry Pi OS the first user is in `adm`) | a file: `s-hole -purge`. The journal: `journalctl --rotate && journalctl --vacuum-time=1s` (deletes every service's logs) |
| Top Domains and Top Clients | memory | follow `query_log.mode`; empty under `"none"` | until a restart or a purge | anyone who can reach the dashboard | restart, or purge |
| Per-minute graph: counts of queries, blocked, cached, and failed, with no domain or client | memory | on | 24 hours, and until a restart or a purge | anyone who can reach the dashboard | restart, or purge |
| Since-start counters (total, blocked, local answers, cache hits, failures) | memory | on | until a restart | anyone who can reach the dashboard or `/metrics` | restart |
| DNS response cache: recent answers, by name, type, and DNSSEC bits | memory | on (`dns.cache_entries`) | each answer's TTL, one day at most | nobody directly. A LAN device can query a name and tell from the response time whether another device queried it recently. The remaining TTL in the answer tells when. s-hole refuses a query that reads only the cache (RD=0), so each check also puts the name in the cache | restart, or purge |
| Application log: startup, reloads, errors | the system journal, standard output, or the Windows Event Log | on | the log's own rules | root and the log groups; on Windows, every interactive user | outside s-hole |
| Downloaded blocklists (public lists) | `blocking.cache_dir` | on | replaced on each download | the s-hole user only | `s-hole -purge` |
| Client labels (`query_log.client_names`): a name for each device or subnet address | `config.yaml` | none | until you edit the config | anyone who can reach the dashboard; the labels show on the dashboard, in the API, and in the query export | edit the config |
| Allowlist | `config.yaml`, and memory for runtime additions | as configured | config: until you edit it; runtime: until a restart | anyone who can reach the dashboard | edit the config; remove an entry in the dashboard |

The application log never holds a queried domain or a client address, with
two exceptions. Under `query_log.mode: "all"`, a warning about one failed
query can name its domain. An allowlist change through the API logs the
domain and the address of the device that made the change, as an audit line.

## What leaves the network

| To | What | When |
|---|---|---|
| The upstream resolvers (default: Quad9, then Cloudflare) | the name, type, and class of each allowed query that is not in the cache, in a new query that s-hole builds: the RD, CD, AD, and DO flags, a random query ID (ID 0 over DoH), and s-hole's own EDNS record with no options except padding. Nothing else from the device's query: no EDNS option (cookie, Client Subnet) and not its query ID. s-hole sends no cookie of its own | every cache miss. Encrypted (DoH) by default, padded to a multiple of 128 bytes. For a public name, a plain upstream is used only when every DoH upstream has failed, and s-hole logs a warning with the count, at most once a minute. A local name (below) goes only to an upstream on the LAN, which may use plain DNS |
| The blocklist hosts | an HTTPS request for each list, with `User-Agent: s-hole` | at startup and every `blocking.refresh_interval` |

s-hole sends nothing else: no telemetry, no update check, no crash report. The
dashboard loads nothing from another site.

Reverse lookups for private addresses stay on the LAN (`dns.local_ptr`, on by
default).

Names that only mean something on the LAN stay on the LAN too. s-hole sends a
single-label name (`printer`, `wpad`) and a name under `.local`, `home.arpa`,
`.internal`, `.test`, `.intranet`, `.private`, `.corp`, `.home`, `.lan`,
`.localdomain`, or a domain in `dns.local_domains` only to an upstream with a
LAN address, such as the router. With no such upstream, s-hole answers "no
such name" itself. A LAN upstream decides itself what it does with a name it
cannot answer; many routers forward it to the internet provider. s-hole
answers `localhost` names and names under `.onion`, `.invalid`, and `.alt`
itself and sends them nowhere. There is no setting to turn this off.

## Who can query s-hole

s-hole answers devices on the local network only: loopback, private IPv4
ranges, link-local, IPv6 unique-local addresses, and the subnets of its own
network interfaces. It refuses every other source without recording it.

## The dashboard and the API

The dashboard and the REST API have no login. By default they listen on
`127.0.0.1:8080`, this machine only. If you set `admin.listen` to a LAN
address, every device on the LAN can read the stored history and change the
allowlist, and s-hole warns. The server refuses requests addressed to a
foreign hostname and cross-site requests that change something, so a web page
cannot use your browser to read or change it. Every response carries
`Cache-Control: no-store`, so the browser does not keep query data on disk.
The query filter you type is kept for the browser tab only (sessionStorage).

## Backups, copies, and old rows

- An export from the dashboard is a copy outside s-hole. Retention and purge
  do not reach it.
- A backup of the data directory, a VM snapshot, or an SD-card image keeps the
  history as it was.
- On flash storage, a deleted block can stay on the medium. Only disk
  encryption makes sure deleted data cannot be recovered.
- A change to a more private setting applies to new rows only. s-hole warns
  about stored rows that hold more than the current settings, with the date
  retention removes them. Purge to remove them at once.

## Devices with their own encrypted DNS

Some devices and apps send DNS queries encrypted to their own provider:
Firefox with DNS over HTTPS, iCloud Private Relay, or Android Private DNS set
to another provider. s-hole does not see those queries, so it does not block
ads or trackers for them. s-hole does not try to stop these features: the
person who turned one on chose that privacy.

## Changes to this page

A change that adds, moves, or removes personal data updates this page in the
same change (see `CLAUDE.md`).
