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
- `pkg` is the part of s-hole that wrote the line: `main`, `config`,
  `blocklist`, `dns`, `api`, `querylog`, or `stats`.
- `err` is the error, when there is one.
- `hint` says what to check, when s-hole knows.

In a terminal and in Docker, each line also starts with a `time=` field. Under
systemd, journald records the time, so the line has no `time=` field.

With `S_HOLE_LOG_FORMAT=json`, each line is a JSON object with the same fields.

The log also has two other kinds of lines:

- **Query lines.** When `log_file` is empty and `log_queries` is `all`, s-hole
  writes one line for each DNS query, such as `2026-09-29T06:51:19-04:00 BLOCK 192.168.1.23 ads.example.com.`.
  These lines have no `level` field. To write fewer of them, set `log_queries`
  to `blocked` or `none`. To write them to a file, set `log_file`.
- **The startup banner.** The "Router setup" box shows the address to enter
  in your router.

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

## s-hole does not start

Show the errors from the last start:

```bash
journalctl -u s-hole -b -p err
```

| You see | What it means | What to do |
|---|---|---|
| `msg="config load failed"` | The config file has an error. `err` names the setting. A DoT certificate that does not load also shows here, with `tls_cert/tls_key` in `err`. | Correct the setting. To check the file before a restart, run `sudo -u s-hole s-hole -check-config -config /etc/s-hole/config.yaml`. |
| `msg="dns listen failed"` with `address already in use` (on Windows: `Only one usage of each socket address`) | Another program uses port 53. On many Linux systems, this is the `systemd-resolved` stub. | To find the program, run `sudo ss -lunp 'sport = :53'`. If the program is `systemd-resolved`, run the installer with `--free-port-53` to free the port. |
| `msg="dns listen failed"` with `permission denied` | s-hole cannot open a port below 1024 without root or the `CAP_NET_BIND_SERVICE` capability. | Run s-hole through the systemd unit that the installer writes, or set `listen` to a port above 1024. |
| `msg="DoT listener failed"` | `dot_listen` is set, but s-hole cannot open the DoT port. | Read `err` and `hint`. Look for another program on port 853, or correct `dot_listen`. |

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
journalctl -u s-hole | grep -E 'block set is empty|all sources failed|blocklist load failed'
```

| You see | What it means | What to do |
|---|---|---|
| `msg="blocklist load failed" url=...` | s-hole cannot get this list, and it has no cached copy. | Read `err`. Check the URL, and check that the s-hole host can reach the internet. |
| `msg="all sources failed; keeping existing block set"` | No list loaded in this reload. s-hole keeps the domains it blocked before. | Correct the network or the URLs. The next reload tries again. |
| `msg="block set is empty"` | s-hole answers queries but blocks nothing. | Correct the cause that the other lines show. Then run `sudo systemctl reload s-hole`. |

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
| `msg="download failed, using stale cache"` | s-hole cannot connect to the server, the download stopped before the end of the list, or s-hole cannot write the cache file. Read `err`. |
| `msg="non-200 response, using stale cache"` | The server answered with an error. `status` gives the HTTP status. |
| `msg="response truncated at cap, using stale cache"` | The list is larger than 256 MiB. s-hole does not use a partial list. |

To download the lists now, run `sudo systemctl reload s-hole`. The log then
shows `msg="refreshing blocklists"` and one `msg=loaded` line for each list.

## Some names do not resolve

```bash
journalctl -u s-hole | grep 'upstream forward failed'
```

`msg="upstream forward failed" domain=...` means that no upstream DNS server
answered this query, so the client got SERVFAIL. Read `err`. If this line
appears for many domains, s-hole cannot reach its upstreams. Send a query to
an upstream from the s-hole host:

```bash
dig @1.1.1.1 example.com
```

If this query fails too, check the network of the s-hole host. If it
succeeds, check the `upstreams` setting.

If you configured only one upstream, the log shows `msg="single upstream
configured; no forwarding fallback if it fails"` at startup. Add a second
upstream, so that DNS continues to work when one upstream fails.

## A device's queries do not reach s-hole

When `log_file` is empty and `log_queries` is `all`, s-hole writes one query
line for each query. Search for the device's IP address:

```bash
journalctl -u s-hole | grep ' 192.168.1.23 '
```

If you find no line, the query did not reach s-hole. Check the network path:
the router's DHCP DNS setting, a firewall, or a DNS setting on the device.
After a change on the router, the device uses s-hole from its next DHCP lease
renewal.

With `query_privacy: subnet`, query lines show the subnet (such as
`192.168.1.0`), not the device's address. With `query_privacy: drop`, they
show no client.

## A domain is blocked, but you want to allow it

Ask s-hole why it blocks the domain:

```bash
curl -s 'localhost:8080/api/check?domain=example.com'
```

The answer shows the block entry that matched. To allow the domain now, add
it to the whitelist on the dashboard. This entry is lost when s-hole restarts.
To keep it, also add it to `whitelist` in the config file.

## The dashboard does not open

| You see | What it means | What to do |
|---|---|---|
| `msg="admin UI failed to bind; DNS still serving"` | Another program uses the `api_listen` port. DNS still works. | Read `err`. Stop the other program, or change `api_listen`. |
| `msg="admin UI listening" url=http://127.0.0.1:8080` | The dashboard runs, but only on the s-hole host. | Open it through an SSH tunnel: `ssh -L 8080:127.0.0.1:8080 <host>`. |

## DNS over TLS

| You see | What it means | What to do |
|---|---|---|
| `msg="DoT certificate expires soon"` | The certificate expires within 14 days. `expires` gives the date. | Renew the certificate. Then run `sudo systemctl reload s-hole`. |
| `msg="DoT certificate expired"` | Clients that check the certificate cannot connect. | Renew the certificate. Then reload. |
| `msg="DoT certificate reload failed; keeping the current certificate"` | A reload cannot read the new files, or the certificate and key do not match. s-hole still uses the old certificate. | Read `err`. Correct the files. Then reload. |
| `msg="DoT certificate reloaded"` | The reload loaded the files. `expires` gives the new expiry. | Nothing. |

## The query history is empty or has gaps

| You see | What it means | What to do |
|---|---|---|
| `msg="query log database open failed"` | s-hole cannot open `query_db`. The dashboard history and the recent queries stay empty. | Read `err`. Under systemd, keep `query_db` in `/var/lib/s-hole`. Under a Windows service, a relative `query_db` is next to `config.yaml`. |
| `msg="query log commit failed, dropping batch"` | s-hole cannot write some queries to the database. | Read `err`. Check the free disk space. |

The metric `shole_query_log_dropped_total` counts queries that the query log
dropped because it was busy.

## A config setting has no effect

At startup, s-hole ignores some entries that are not correct, and writes a
warning for each:

```bash
journalctl -u s-hole -b | grep 'msg="ignoring'
```

| You see | What it means |
|---|---|
| `msg="ignoring invalid whitelist entry"` | The `whitelist` entry is not a valid domain. |
| `msg="ignoring client_names entry with invalid key"` | The `client_names` key is not an IP address or a CIDR. |
| `msg="ignoring malformed upstream"` | The `upstreams` entry is not `host:port` or a usable DoH URL. A DoH URL needs an IP host and a path, and must not contain a user name or password. `upstream` shows the entry, with a user name and password replaced by `redacted`. `hint` shows the correct form. |

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
