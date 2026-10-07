# Troubleshooting

This page tells you which log lines to look for when s-hole does not work as
you expect. Each problem gives a command, the lines it can show, and what to
do next.

## Read the log

s-hole writes its log to stdout. Where you read it depends on how s-hole runs:

| s-hole runs as | Command |
|---|---|
| systemd service | `journalctl -u s-hole` |
| Docker container | `docker logs s-hole` |
| Windows service | Event Viewer, **Windows Logs > Application**, source **s-hole** |
| Program in a terminal | The terminal |

Useful `journalctl` options:

```bash
journalctl -u s-hole -f               # follow new lines
journalctl -u s-hole -b               # lines since the last boot
journalctl -u s-hole --since "1 hour ago"
```

On Windows, this PowerShell command shows the last 50 entries:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='s-hole'} -MaxEvents 50
```

### Line format

Each line is one event, written as `key=value` fields:

```
level=WARN msg="download failed, using stale cache" pkg=blocklist url=https://adaway.org/hosts.txt err="..."
```

- `level` is `INFO`, `WARN`, or `ERROR`.
- `msg` says what happened. To find an event, search for the text of its `msg`.
- `pkg` is the part of s-hole that wrote the line: `main`, `blocklist`,
  `dns`, `api`, `querylog`, or `stats`. Config problems come from `main`.
- `err` is the error, when there is one.
- `hint` says what to check, when s-hole knows.

In a terminal and in Docker, each line also starts with a `time=` field. Under
systemd, journald records the time, so the line has no `time=` field.

With `S_HOLE_LOG_FORMAT=json`, each line is a JSON object with the same fields.

The log also has two other kinds of lines:

- **Query lines.** Off by default. With `query_log.file: "stdout"` and
  `query_log.mode` set to `"all"` (or `"blocked"`), s-hole writes one line for
  each recorded query, such as `2026-09-29T10:51:19Z BLOCK 192.168.1.23 ads.example.com.`.
  These lines have no `level` field. s-hole cannot delete them from the
  journal, so turn them on only while you look into a problem.
- **The startup banner.** The "Router setup" box shows the address to enter
  in your router.

The application log holds no queried domain and no client address, except a
warning about one failed query under `query_log.mode: "all"` and the allowlist
audit lines.

### Show only problems

Under systemd, this command shows only warnings and errors:

```bash
journalctl -u s-hole -p warning
```

In Docker or a terminal, search for the level:

```bash
docker logs s-hole 2>&1 | grep -E 'level=(WARN|ERROR)'
```

### Read the counters

Every 5 minutes (`stats_interval`), s-hole writes one `msg=stats` line with
its counters:

```
level=INFO msg=stats pkg=stats uptime=2h5m0s queries=5120 blocked=812 blocked_pct=15.9 local_ptr=40 cache_hits=2310 cache_hit_pct=54.0 forward_failures=3 upstream_errors=0
```

If `forward_failures` or `upstream_errors` increases, read
[Some names do not resolve](#some-names-do-not-resolve).

After the stats line, s-hole writes one `msg="privacy and security warnings in
effect"` line when a setting is less private than its default. Read
[Privacy and security warnings](#privacy-and-security-warnings).

## s-hole does not start

Show the errors from the last start:

```bash
journalctl -u s-hole -b -p err
```

| You see | What it means | What to do |
|---|---|---|
| `msg="config load failed"` | The config file cannot be read or is not valid YAML, or one of the three settings that s-hole cannot work without is wrong: `dns.listen` is not `host:port`, every `dns.upstreams` entry is malformed, or DoT is on and its certificate does not load (`dns.dot_cert/dns.dot_key` in `err`). | Correct the setting. To check the file before a restart, run `sudo -u s-hole s-hole -check-config -config /etc/s-hole/config.yaml`. Other mistakes do not stop s-hole: read [A config setting has no effect](#a-config-setting-has-no-effect). |
| `msg="dns listen failed"` with `address already in use` (on Windows: `Only one usage of each socket address`) | Another program uses port 53. On many Linux systems, this is the `systemd-resolved` stub. | To find the program, run `sudo ss -lunp 'sport = :53'`. If the program is `systemd-resolved`, run the installer with `--free-port-53` to free the port. |
| `msg="dns listen failed"` with `permission denied` | s-hole cannot open a port below 1024 without root or the `CAP_NET_BIND_SERVICE` capability. | Run s-hole through the systemd unit that the installer writes, or set `dns.listen` to a port above 1024. |
| `msg="DoT listener failed"` | `dns.dot_listen` is set, but s-hole cannot open the DoT port. | Read `err` and `hint`. Look for another program on port 853, or correct `dns.dot_listen`. |

If the start fails, systemd tries again every 5 seconds. `systemctl status
s-hole` then shows `activating (auto-restart)`.

## s-hole stopped while it ran

```bash
journalctl -u s-hole -p err
```

In Docker or on Windows, read the log as [Read the log](#read-the-log) shows.

`msg="dns server failed"` means that a DNS listener stopped with an error
after startup. s-hole then stops in order and exits with an error. systemd
starts it again after 5 seconds. Docker starts it again if the container has a
restart policy, such as `--restart unless-stopped`. If its recovery actions
are set, a Windows service also starts again after 5 seconds.
[Windows (system service)](../README.md#windows-system-service) in the README
tells how to set them.

Read `err`. If the error comes back after each start, correct its cause. If
the error does not come back, the restart corrected the problem.

## Nothing is blocked

Check that the block set has entries:

```bash
curl -s localhost:8080/readyz
```

`ok` means that the block set has entries. `blocklist empty` means that it has
no entries. If you see `blocklist empty`, search the log:

```bash
journalctl -u s-hole | grep -E 'block set is empty|all sources failed|blocklist load failed|blocklist lines skipped|blocklist has no domains'
```

| You see | What it means | What to do |
|---|---|---|
| `msg="blocklist load failed" url=...` | s-hole cannot get this list, and it has no cached copy. | Read `err`. Check the URL, and check that the s-hole host can reach the internet. |
| `msg="blocklist lines skipped" url=... read=... skipped=...` | s-hole got the list, but could not read most of its lines. The list is usually in a format s-hole does not read, such as an Adblock list (`\|\|example.com^`). | Use the list's hosts or domains version. s-hole reads hosts lines (`0.0.0.0 example.com`), one domain per line, and `*.example.com` lines. |
| `msg="blocklist has no domains" url=...` | s-hole got the list, but it has only comments and blank lines. | Open the URL in a browser and check that it is the list you want. |
| `msg="all sources failed; keeping existing block set"` | No list loaded in this reload. s-hole keeps the domains it blocked before. | Correct the network or the URLs. The next reload tries again. |
| `msg="block set is empty"` | s-hole answers queries but blocks nothing. | Correct the cause that the other lines show. Then run `sudo systemctl reload s-hole`. |

A list can load and still give no domains while the other lists work, so
`/readyz` still says `ok`. Its `msg=loaded` line then shows `domains=0` or a
low count, and a `blocklist lines skipped` or `blocklist has no domains` line
follows it.

If the log shows no problem, check that the device uses s-hole. Read
[A device's queries do not reach s-hole](#a-devices-queries-do-not-reach-s-hole).

## The blocklists do not update

Each list writes one `msg=loaded` line when s-hole loads it:

```bash
journalctl -u s-hole | grep 'msg=loaded'
```

The `from` field tells where the list came from:

- `from=download`: s-hole downloaded the list. Every reload shows this value.
- `from=cache`: s-hole used its disk copy at startup, because the copy was less
  than 24 hours old.
- `from=stale_cache`: the download failed, so s-hole used an older disk copy.
  The dashboard shows the list as STALE.

A `from=stale_cache` line comes after a warning that gives the reason:

| You see | What it means |
|---|---|
| `msg="download failed, using stale cache"` | s-hole cannot connect to the server, or the download stopped before the end of the list. Read `err`. |
| `msg="non-200 response, using stale cache"` | The server answered with an error. `status` gives the HTTP status. |
| `msg="response truncated at cap, using stale cache"` | The list is larger than 256 MiB. s-hole does not use a partial list. |

To download the lists now, run `sudo systemctl reload s-hole`. The log then
shows `msg="refreshing blocklists"` and one `msg=loaded` line for each list.

`msg="blocklist cache could not be written"` means that s-hole used the
downloaded list but cannot keep a copy, so the next start downloads it again.
Read `hint`. The directory, or its files, belong to another user. In Docker,
the image runs as user 65532 since s-hole 2.0: on the host, run
`sudo chown -R 65532:65532` on the directory that is mounted at `/app`.

## Some names do not resolve

```bash
journalctl -u s-hole | grep 'queries could not be resolved'
```

`msg="queries could not be resolved"` comes once a minute while queries fail.
`queries` is how many failed, and `causes` gives the last error of each
upstream. The clients got SERVFAIL. The line names no domain, except
`last_domain` under `query_log.mode: "all"`.

- If `hint` names the system clock, an upstream's TLS certificate looks
  expired or not yet valid. The DoH upstreams use HTTPS, so a wrong clock
  stops them. Check the clock: `timedatectl` shows the time and whether NTP
  synchronized it. A Raspberry Pi 4 or older has no battery-backed clock, and
  after a long power-off it starts with an old time. Make sure the s-hole host
  does not use s-hole as its own DNS server, or it cannot reach its time
  server while DoH fails: read
  [This host uses s-hole as its own DNS server](#this-host-uses-s-hole-as-its-own-dns-server).
- Otherwise, s-hole cannot reach its upstreams. Send a query to an upstream
  from the s-hole host:

```bash
dig @9.9.9.9 example.com
dig +https @9.9.9.9 example.com      # DoH, with BIND dig 9.18 or later
```

If these queries fail too, check the network of the s-hole host. If they
succeed, check the `dns.upstreams` setting.

`msg="queries were sent unencrypted"` means that every DoH upstream failed, so
s-hole sent these queries to a plain upstream. Correct the DoH problem as
above. For DoH only, remove the plain upstreams from `dns.upstreams`.

At startup, s-hole writes a note about the upstream list: `single upstream
configured; no forwarding fallback if it fails`, that every upstream is DoH
(no fallback if TLS fails), or, with the default list, `plain upstreams are a
fallback; ...`. These are notes, not errors.

## A device's queries do not reach s-hole

By default s-hole records no query lines, so look at the counters. Send a
query from the device, then read the next `msg=stats` line: `queries` goes up
for every query that reaches s-hole. To see the device's own queries for a
short time, set `query_log.mode: "all"`, `query_log.clients: "full"`, and
`query_log.file: "stdout"`, restart s-hole, and search for the device's IP
address:

```bash
journalctl -u s-hole | grep ' 192.168.1.23 '
```

Set the three settings back when you are done; s-hole warns while they are on.

If you find no line, the query did not reach s-hole. Check the network path:
the router's DHCP DNS setting, a firewall, or a DNS setting on the device.
After a change on the router, the device uses s-hole from its next DHCP lease
renewal. A device with its own encrypted DNS (Firefox DNS over HTTPS, iCloud
Private Relay, or Android Private DNS with another provider) does not use
s-hole at all.

If the warnings line says `queries from outside the LAN were refused`, s-hole
answers only loopback, private, link-local, and unique-local addresses and the
subnets of its own interfaces. A device on a routed subnet with public IPv6
addresses, or behind a VPN with its own address range (such as Tailscale's
100.64.0.0/10), gets REFUSED. Give the device an address in a private range
or in one of the s-hole host's subnets.

## A domain is blocked, but you want to allow it

Ask s-hole why it blocks the domain:

```bash
curl -s 'localhost:8080/api/check?domain=example.com'
```

The answer shows the block entry that matched. To allow the domain now, add
it to the allowlist on the dashboard. This entry is lost when s-hole restarts.
To keep it, also add it to `blocking.allowlist` in the config file.

## The dashboard does not open

| You see | What it means | What to do |
|---|---|---|
| `msg="admin UI failed to bind; DNS still serving"` | Another program uses the `admin.listen` port. DNS still works. | Read `err`. Stop the other program, or change `admin.listen`. |
| `msg="admin UI listening" url=http://127.0.0.1:8080` | The dashboard runs, but only on the s-hole host. | Open it through an SSH tunnel: `ssh -L 8080:127.0.0.1:8080 <host>`. |
| The browser shows `421` and `s-hole answers only requests addressed to its IP address...` | You opened the dashboard by a name that is not the machine's own hostname, such as a name from your router (`pi.lan`). s-hole refuses other names, to stop DNS rebinding. | Open it by IP address, `localhost`, or the machine's hostname, such as `http://raspberrypi.local:8080`. |
| **Delete history** says `the query history can be deleted only from the s-hole host` | A purge is accepted only from the s-hole host itself. | Open the dashboard on the s-hole host, or run `s-hole -purge -config <config>` there. In a Docker bridge network, run `docker exec <container> s-hole -purge -config /app/config.yaml`. |

## DNS over TLS

| You see | What it means | What to do |
|---|---|---|
| `msg="DoT certificate expires soon"` | The certificate expires within 14 days. `expires` gives the date. | Renew the certificate. Then run `sudo systemctl reload s-hole`. |
| `msg="DoT certificate expired"` | Clients that check the certificate cannot connect. | Renew the certificate. Then reload. |
| `msg="DoT certificate reload failed; keeping the current certificate"` | A reload cannot read the new files, or the certificate and key do not match. s-hole still uses the old certificate. | Read `err`. Correct the files. Then reload. |
| `msg="DoT certificate reloaded"` | The reload loaded the files. `expires` gives the new expiry. | Nothing. |

## The query history is empty or has gaps

The query history is off by default. It needs `query_log.database` set to a
file and `query_log.mode` set to `"blocked"` or `"all"`. The dashboard header
shows `stored history off` while it is off.

| You see | What it means | What to do |
|---|---|---|
| `msg="query log database open failed"` | s-hole cannot open `query_log.database`. The dashboard history and the recent queries stay empty. | Read `err` and `hint`. Under systemd, keep the file in `/var/lib/s-hole`. Under a Windows service, a relative path is next to `config.yaml`. With `permission denied` in Docker, run `sudo chown -R 65532:65532` on the host directory mounted at `/app`. |
| `msg="query log commit failed, dropping batch"` | s-hole cannot write some queries to the database. | Read `err`. Check the free disk space. |
| `msg="query log file open failed; query lines are not written"` | s-hole cannot open `query_log.file`. It does not write the lines to standard output instead. | Read `err`. Check that the directory exists and s-hole can write to it. |

The metric `shole_query_log_dropped_total` counts queries that the database
dropped because it was busy; `shole_query_log_file_dropped_total` counts query
lines that the file output dropped.

## Privacy and security warnings

s-hole writes a `msg="privacy warning"` line at startup (and at
`-check-config`) for each setting that is less private or less secure than its
default, and repeats all of them in one `msg="privacy and security warnings in
effect"` line after every stats line. The dashboard shows the same list. You
cannot turn them off: they go away when you change the setting back.

| `key` | What it means | To remove the warning |
|---|---|---|
| `query_log.mode` | s-hole records queries | `query_log.mode: "none"` |
| `query_log.clients` | recorded queries keep the device address or subnet | `query_log.clients: "drop"` |
| `query_log.file` | query lines go to a file or to standard output | `query_log.file: "off"` |
| `query_log.retention_days` | the history is kept forever, or for more than 7 days | `query_log.retention_days: 7` |
| `query_log.database` | the database holds rows written under a less private setting, such as client addresses from before a switch to `"drop"` | wait for retention (the line gives the date), or run `s-hole -purge` |
| `admin.listen` | the dashboard listens on more than this machine | `admin.listen: "127.0.0.1:8080"` |
| `admin.pprof` | the profiler is exposed | `admin.pprof: false` |
| `dns.local_ptr` | reverse lookups for private addresses go upstream | `dns.local_ptr: true` |
| `dns.upstreams` | every upstream is plain DNS, or queries were sent unencrypted because every DoH upstream failed | put a DoH upstream first; for a fallback, read [Some names do not resolve](#some-names-do-not-resolve) |
| `blocking.lists` | a list is downloaded over plain HTTP | use the `https://` URL |
| `dns.listen` | queries from outside the LAN were refused | read [A device's queries do not reach s-hole](#a-devices-queries-do-not-reach-s-hole) |

## This host uses s-hole as its own DNS server

`msg="this host uses s-hole as its own DNS server"` comes at startup and
within an hour after the host's resolver changes, usually after the router
starts to hand out s-hole's address. While s-hole is down, this host cannot
resolve names: s-hole cannot download its blocklists, updates fail, and the
host may not reach its time server. Set the host's resolver by hand, as
[Keep the s-hole host off s-hole](../README.md#keep-the-s-hole-host-off-s-hole)
in the README shows. s-hole writes `this host no longer uses s-hole as its own
DNS server` after the change.

## A config setting has no effect

s-hole does not stop for a mistake in the config. For an unknown key, a key
renamed in s-hole 2.0, an invalid value, or an `S_HOLE_*` variable that is
unknown or renamed, it writes a warning and uses the default for that setting:

```bash
journalctl -u s-hole -b | grep 'msg="config problem"'
```

`key` names the setting or the variable, and `problem` says what is wrong and
what s-hole uses instead. A key from s-hole 1.x, such as `api_listen` or
`log_queries`, says which 2.0 key replaces it. `docs/CHANGELOG.md` has the full
mapping. An upstream entry in `problem` shows a user name, a password, or a
query string as `redacted`.

`s-hole -check-config -config /etc/s-hole/config.yaml` lists the same problems
and exits 1, so run it before a restart.

s-hole reads the config file only at startup. After you change it, run
`sudo systemctl restart s-hole`. A reload does not read the file again. The
systemd service does not get the `S_HOLE_*` variables from your shell.

## A reload does not seem to run

Each reload writes a line that tells what started it:

| You see | What started the reload |
|---|---|
| `msg="reload requested via timer"` | The `refresh_interval` timer |
| `msg="reload requested via API"` | The dashboard's Reload button or `POST /api/reload` |
| `msg="reload signal received"` | `systemctl reload s-hole` or SIGHUP |

If a reload is running already, s-hole writes `msg="reload queued until the
running reload ends"` once and queues one more reload. More requests during
the same reload add nothing. When the running reload ends, s-hole writes
`msg="queued reload started"` and does the reload again.

After s-hole starts to shut down, it does not start a new reload. A request then writes
`msg="reload refused during shutdown"`, and a queued reload does not run.

`msg="blocklist refresh failed"` means that no list loaded in that reload.
Read [Nothing is blocked](#nothing-is-blocked).
