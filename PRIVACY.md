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
| Query history: time (UTC), domain, client (as `query_log.clients` allows), and outcome of each recorded query | SQLite file `query_log.database` | off | `query_log.retention_days`, default 7 days. Deleted rows are overwritten in the file | the file: the s-hole user only (file mode `600`, data directory `700`; on Windows, SYSTEM, the Administrators group, and the service account, through the config folder's access list). The dashboard and the API: anyone who can reach them, by default every account and program on the s-hole host (see [The dashboard and the API](#the-dashboard-and-the-api)) | `s-hole -purge` (when s-hole is stopped, it overwrites the files with zeros before it deletes them), the dashboard's **Delete history** button on the s-hole host, or retention |
| Query lines: the same fields as text | `query_log.file`: a file, or standard output | off | a file: until you delete it. Standard output: the system journal or the container log keeps it under its own rules | a file: the s-hole user only (mode `600`; on Windows, the same accounts as the query history). The journal: root and the `adm` and `systemd-journal` groups (on Raspberry Pi OS the first user is in `adm`) | a file: `s-hole -purge`, which overwrites it with zeros before it empties or deletes it. The journal: `journalctl --rotate && journalctl --vacuum-time=1s` (deletes every service's logs) |
| Top Domains and Top Clients | memory | follow `query_log.mode`; empty under `"none"` | until a restart or a purge | anyone who can reach the dashboard | restart, or purge |
| Per-minute graph: counts of queries, blocked, cached, and failed, with no domain or client. The counts over time show when the household is active | memory | off (follows `query_log.mode`: empty under `"none"`, blocked queries only under `"blocked"`) | 24 hours, and until a restart or a purge | anyone who can reach the dashboard | restart, or purge |
| Since-start counters (total, blocked, local answers, cache hits, failures) | memory | on | until a restart | anyone who can reach the dashboard or `/metrics` | restart |
| DNS response cache: recent answers, by name, type, and DNSSEC bits | memory | on (`dns.cache_entries`) | each answer's TTL, one day at most | nobody directly. A LAN device can query a name and tell from the response time whether another device queried it recently. The remaining TTL in the answer tells when. s-hole refuses a query that reads only the cache (RD=0), so each check also puts the name in the cache | restart, or purge |
| Application log: startup (including the host's search domains that are not local and its interface subnets that are not LAN), reloads, errors, failure summaries, uptime, and allowlist changes. No queried domain or client address (one exception below), and no total query count | the system journal, standard output, or the Windows Event Log | on | the log's own rules | root and the log groups; on Windows, every interactive user | outside s-hole |
| Downloaded blocklists (public lists) | `blocking.cache_dir` | on | replaced on each download | the s-hole user only | `s-hole -purge` |
| Client labels (`query_log.client_names`): a name for each device or subnet address | `config.yaml` | none | until you edit the config | anyone who can reach the dashboard; the labels show on the dashboard, in the API, and in the query export | edit the config |
| Allowlist | `config.yaml`, and memory for runtime additions | as configured | config: until you edit it; runtime: until a restart | anyone who can reach the dashboard | edit the config; remove an entry in the dashboard |
| Counter history: the since-start counters over time, with no domain or client. The counts show when the household is active, also under `query_log.mode: "none"` | a Prometheus server that you set up to scrape `/metrics` | none: s-hole does not run Prometheus | Prometheus's own retention (15 days by default) | whoever can read the Prometheus server | outside s-hole: a purge and retention do not reach it. Delete it in Prometheus |

The application log never holds a queried domain or a client address, and
its periodic stats line holds only the uptime, not the query counts. The
dashboard and `/metrics` show the counts. Failures are counted in summaries
of at most one line a minute (queries that could not be resolved, replies
that could not be sent, queries sent unencrypted), with no domain and no
client. One exception: an allowlist change through the API logs the domain
as an audit line. The line has the address of the device that made the
change only while `query_log.mode` records queries (`"blocked"` or `"all"`),
masked by `query_log.clients`: no address under `"drop"`, the subnet under
`"subnet"`, and the address under `"full"`. Under the defaults the line holds
no address. The lines that the admin web server writes on its own (for
example, when a dashboard request fails with a program error) hold no address
either: s-hole writes `client` in its place.

## What leaves the network

| To | What | When |
|---|---|---|
| The upstream resolvers (default: Quad9, then Cloudflare) | the name, type, and class of each allowed query that is not in the cache, in a new query that s-hole builds: the RD, CD, AD, and DO flags, a random query ID (ID 0 over DoH), and s-hole's own EDNS record with no options except padding. Nothing else from the device's query: no EDNS option (cookie, Client Subnet) and not its query ID. s-hole sends no cookie of its own | every cache miss (except a query over the forward limit, which gets SERVFAIL and goes nowhere). Encrypted (DoH) by default, padded to a multiple of 128 bytes. For a public name, a plain upstream is used only when every DoH upstream has failed, and s-hole logs a warning with the count, at most once a minute. A local name (below) goes only to an upstream on the LAN, which may use plain DNS. s-hole does not follow a redirect from a DoH upstream, so a query goes to no other host |
| The blocklist hosts, and the hosts they redirect to | a request for each list, with `User-Agent: s-hole`. It uses HTTPS unless the list URL is `http://`, which s-hole warns about. s-hole does not follow a redirect from HTTPS to a URL that is not HTTPS | at startup and every `blocking.refresh_interval` |

s-hole sends nothing else: no telemetry, no update check, no crash report. The
dashboard loads nothing from another site.

Reverse lookups for LAN addresses stay on the LAN (`dns.local_ptr`, on by
default). s-hole answers "no such name" itself for the private and special
ranges (RFC 6303 and RFC 6598: `10/8`, `172.16/12`, `192.168/16`,
`100.64/10`, `127/8`, `169.254/16`, IPv6 unique-local and link-local, and
others) and for the public IPv6 prefix of its own network interfaces. An
IPv6 address made from a device's MAC address names that device, so a
reverse lookup for it does not go to the upstream or to the router. If
s-hole cannot read its interface addresses (it logs a WARN), it does not know
that prefix, and those lookups go to the upstream.

Names that only mean something on the LAN stay on the LAN too. s-hole sends a
single-label name (`printer`, `wpad`) and a name under `.local`, `home.arpa`,
`.internal`, `.test`, `.intranet`, `.private`, `.corp`, `.home`, `.lan`,
`.localdomain`, `fritz.box`, or a domain in `dns.local_domains` only to an
upstream with a LAN address, such as the router. With no such upstream, s-hole answers "no
such name" itself. A LAN upstream decides itself what it does with a name it
cannot answer; many routers forward it to the internet provider. s-hole
answers `localhost` names and names under `.onion`, `.invalid`, and `.alt`
itself and sends them nowhere. There is no setting to turn this off.

Devices add the router's search domain to short names, so a name such as
`laptop.home.example` reaches s-hole. If the search domain of the s-hole
host is not a local domain, s-hole logs an INFO line at startup that names
it. s-hole sends names under that domain to every upstream until you add it
to `dns.local_domains`. s-hole does not add it on its own: a search domain can
be a public domain that the router cannot answer.

## Who can query s-hole

s-hole answers devices on the local network only: loopback, private IPv4
ranges, link-local, IPv6 unique-local addresses, and the IPv6 subnets of its
own network interfaces. A public or shared (CGNAT, `100.64.0.0/10`) IPv4
subnet on an interface does not count: such a subnet usually faces the
internet provider or a VPN, and s-hole logs a WARN that names it. s-hole
refuses every other source, and every query whose source address it cannot
read, without recording it.

## The dashboard and the API

The dashboard and the REST API have no login. By default they listen on
`127.0.0.1:8080`, this machine only. But every account and every program on
the s-hole host can connect to that address. Each of them can read the stored
history, export it, delete it, and change the allowlist. The file mode `600`
of the query database does not stop this while s-hole runs. Run s-hole on a
dedicated host, such as a Raspberry Pi that no other person logs in to and
that runs only programs you trust. A program on the host can also read the
counters on `/metrics` again and again, and get the activity timeline that a
Prometheus server keeps (see the table above).

If you set `admin.listen` to a LAN address, every device on the LAN can read
the stored history and change the allowlist, and s-hole warns. The dashboard
uses plain HTTP, with no encryption. The history and the exports cross the
network as clear text, so another device on the network path can read them.
On a WPA2 Wi-Fi network with a shared password, every device that knows the
password can do this.

The server refuses requests addressed to a foreign hostname and requests
from another web site, so a web page cannot use your browser to reach it. A
link from another page can still open the dashboard. Browsers mark a request
from another site only when it goes to `localhost`, a loopback address, or
HTTPS, so this protects the default `127.0.0.1:8080`. A web page can still
send requests (but not read the replies) to a dashboard that you open by its
LAN address over plain HTTP. Every response carries `Cache-Control:
no-store`, so the browser does not keep query data on disk. The query filter
you type is kept for the browser tab only (sessionStorage).

A login for the dashboard is planned (device pairing, item 42 in
`docs/ROADMAP.md`). It will also cover requests from the s-hole host, and a
LAN address will need HTTPS.

## Backups, copies, and old rows

- An export from the dashboard is a copy outside s-hole. Retention and purge
  do not reach it.
- A backup of the data directory, a VM snapshot, or an SD-card image keeps the
  history as it was.
- A purge overwrites the query log file with zeros before it empties or
  deletes it. When s-hole is stopped, the purge also overwrites the query
  database files with zeros before it deletes them. When s-hole runs,
  `secure_delete` overwrites the deleted rows in the database file.
- SQLite keeps copies of the changed database pages in its write-ahead log
  (the `-wal` file next to the database). s-hole overwrites this file with
  zeros before it lets SQLite empty or delete it: when s-hole starts, after
  a retention prune, during a purge, and when s-hole stops. If another
  program reads or writes the database at that moment, or if the `-wal`
  file is a link, s-hole cannot do this safely. The data then stays in the
  file until the next try. At startup, after a prune, and at a stop, s-hole
  logs the WARN `query log WAL overwrite failed`; a purge reports the step
  as failed. If this occurs when s-hole stops, SQLite can delete the file
  later without the overwrite, when the last program closes the database.
- The overwrite is best effort. On flash storage and on a copy-on-write file
  system (Btrfs, ZFS), the zeros can go to new blocks, and a deleted block
  can stay on the medium. Reading free blocks needs access to the raw disk
  (root, or the disk or SD card itself). Only disk encryption makes sure
  deleted data cannot be recovered.
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
