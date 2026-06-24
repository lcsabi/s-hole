# s-hole

A lightweight, self-contained DNS sinkhole for network-wide ad and tracker blocking. Deploy it on any always-on machine, point your router's DHCP DNS field at it, and every device on the network is protected — no per-device configuration required.

s-hole is intentionally small: a single binary, a single YAML config file, no runtime dependencies. The full codebase fits comfortably in an afternoon's reading.

---

## Features

- **Network-wide blocking** — blocks ads and trackers at the DNS layer before any connection is established
- **Community blocklists** — downloads and auto-refreshes hosts-file or plain-domain lists from any URL
- **DNS response cache** — serves repeat queries from memory; typical cache hit rates of 40–70% reduce upstream load and latency
- **Dual query log** — plain-text file for `grep`/`tail` and a SQLite database for historical queries
- **Admin web UI** — live stats, top blocked domains, recent query log, whitelist management; auto-refreshes every 5 seconds
- **REST API** — all UI data available as JSON; suitable for scripting and future integrations
- **Configurable sinkhole mode** — return `0.0.0.0` (default, silent failure) or `NXDOMAIN`
- **Cross-platform** — single binary for Windows, Linux x86-64, Linux arm64 (Pi 4/5), Linux armv7 (Pi 2/3)
- **Windows Service** — installs as an auto-start system service with one command
- **Linux systemd** — ships a hardened unit file with `CAP_NET_BIND_SERVICE` (no root required at runtime)
- **Docker** — multi-stage image, ~25 MB

---

## Quick Start

### Prerequisites

- Go 1.25 or later (for building from source)
- Port 53 available (requires Administrator on Windows, root or `CAP_NET_BIND_SERVICE` on Linux)

### Install via the Go toolchain

If your `$GOBIN` is on `PATH`, the latest commit can be fetched with:

```bash
go install github.com/laszlo/s-hole/cmd/s-hole@latest
```

### Run interactively

```bash
# Build from a local clone
go build -o s-hole ./cmd/s-hole

# Run (requires elevated privileges for port 53)
sudo ./s-hole -config config.yaml          # Linux / macOS
.\s-hole.exe -config config.yaml           # Windows (Administrator)
```

On first run, blocklists are downloaded (~150 000 domains by default) and cached to disk. Subsequent starts skip the download if the cache is less than 24 hours old.

### Point your router at it

In your router's DHCP settings, set the **DNS Server** field to the IP address of the machine running s-hole. All devices on the network will pick up the new DNS server on their next DHCP renewal (or immediately after reconnecting).

Keep a fallback upstream DNS as the secondary DNS entry (e.g. `1.1.1.1`) in case s-hole is unavailable.

### Verify it works

```
nslookup doubleclick.net <s-hole-ip>
# expected: Address: 0.0.0.0

nslookup google.com <s-hole-ip>
# expected: a real IP address
```

---

## Configuration

All configuration lives in `config.yaml`. Every field has a safe default; an empty file is valid.

| Field | Default | Description |
|---|---|---|
| `listen` | `0.0.0.0:53` | Address and port for DNS queries (UDP + TCP) |
| `upstreams` | `[1.1.1.1:53, 8.8.8.8:53]` | Upstream resolvers, tried in order |
| `blocklists` | StevenBlack + AdAway | List of URLs to download (hosts-file or plain-domain format) |
| `whitelist` | `[]` | Domains that are never blocked, regardless of blocklist membership |
| `refresh_interval` | `24h` | How often to re-download blocklists |
| `block_mode` | `zero` | Sinkhole reply: `zero` returns `0.0.0.0`/`::`, `nxdomain` returns NXDOMAIN |
| `block_ttl` | `300` | TTL (seconds) advertised on blocked replies |
| `log_file` | stdout | Path to the plain-text query log |
| `log_queries` | `all` | Which queries to write to logs: `all`, `blocked`, or `none` |
| `query_db` | `queries.db` | Path to the SQLite query log database (empty to disable) |
| `db_flush_interval` | `30s` | How often buffered queries are committed to SQLite |
| `cache_size` | `2000` | Maximum DNS responses held in the in-memory cache (0 to disable) |
| `stats_interval` | `5m` | How often stats are printed to stdout |
| `api_listen` | `127.0.0.1:8080` | Address for the admin web UI and REST API. Set to `0.0.0.0:8080` to expose to the LAN. |
| `cache_dir` | `.` | Directory for cached blocklist files |
| `query_db_retention_days` | `0` (forever) | Delete query-log rows older than this many days. `0` disables the prune. |

### Minimal config example

```yaml
upstreams:
  - "9.9.9.9:53"     # Quad9 — privacy-focused, malware-blocking
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
| `S_HOLE_LOG_FILE` | `log_file` |
| `S_HOLE_LOG_QUERIES` | `log_queries` |
| `S_HOLE_QUERY_DB` | `query_db` |
| `S_HOLE_CACHE_DIR` | `cache_dir` |
| `S_HOLE_BLOCK_MODE` | `block_mode` |
| `S_HOLE_REFRESH_INTERVAL` | `refresh_interval` |
| `S_HOLE_STATS_INTERVAL` | `stats_interval` |
| `S_HOLE_DB_FLUSH_INTERVAL` | `db_flush_interval` |
| `S_HOLE_CACHE_SIZE` | `cache_size` (integer) |
| `S_HOLE_BLOCK_TTL` | `block_ttl` (integer) |
| `S_HOLE_RETENTION_DAYS` | `query_db_retention_days` (integer) |
| `S_HOLE_LOG_FORMAT` | `text` (default) or `json` — controls slog handler |
| `S_HOLE_ASCII_BANNER` | set to `1` to use ASCII box-drawing on the startup banner |

### Recommended config for Raspberry Pi

```yaml
db_flush_interval: "60s"   # reduce SD card write frequency
cache_size: 5000            # more cache = fewer upstream queries
log_queries: blocked        # skip logging allowed queries to save writes
```

---

## REST API

The admin web UI is served at `http://<host>:8080` (default binds to `127.0.0.1`; set `api_listen` to `0.0.0.0:8080` to expose it to the LAN). All data is also available as JSON.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/stats` | Live stats: uptime, query totals, block rate, cache hit rate, top domains/clients |
| `GET` | `/api/queries?limit=N` | Last N queries from SQLite, newest first (default: 50) |
| `GET` | `/api/whitelist` | List all runtime-whitelisted domains |
| `POST` | `/api/whitelist` | Add a domain — body: `{"domain": "example.com"}` |
| `DELETE` | `/api/whitelist?domain=…` | Remove a domain from the runtime whitelist |
| `POST` | `/api/reload` | Trigger an immediate blocklist refresh — de-duplicated via single-flight mutex (returns `"reload already in progress"` if one is running) |
| `GET`  | `/healthz` | Liveness probe — always 200 OK while the HTTP server is responsive |
| `GET`  | `/metrics` | Prometheus text exposition: `shole_queries_total`, `shole_blocked_total`, `shole_cache_hits_total`, `shole_cache_misses_total`, `shole_cache_size`, `shole_blocklist_size`, `shole_whitelist_size` |

Runtime whitelist changes take effect immediately but do not persist across restarts. To make a whitelist entry permanent, add it to `config.yaml`.

---

## Deployment

### Raspberry Pi / Linux (systemd)

```bash
# Cross-compile on your development machine:
make pi          # arm64 — Pi 4, Pi 5
make pi32        # armv7 — Pi 2, Pi 3

# Copy binary, config, and install script to the Pi:
scp s-hole-linux-arm64 pi@raspberrypi.local:~/
scp config.yaml pi@raspberrypi.local:~/
scp deploy/install-linux.sh pi@raspberrypi.local:~/

# On the Pi — run the installer as root:
sudo bash install-linux.sh ./s-hole-linux-arm64 ./config.yaml
```

The installer creates a `s-hole` system user, places the binary at `/usr/local/bin/s-hole`, installs config to `/etc/s-hole/config.yaml`, and enables the service to start on boot.

After installation:

```bash
sudo systemctl status s-hole     # check running state
sudo systemctl stop s-hole       # stop the service
sudo systemctl start s-hole      # start the service
sudo systemctl restart s-hole    # restart (e.g. after editing config)
sudo systemctl disable s-hole    # don't start on boot
sudo systemctl enable s-hole     # re-enable autostart
journalctl -u s-hole -f          # follow logs live
```

To trigger an immediate blocklist refresh without restarting (Linux/macOS):

```bash
sudo systemctl kill -s HUP s-hole       # via systemd
sudo kill -HUP "$(pidof s-hole)"        # or directly
```

SIGHUP is honored on every non-Windows platform; it runs the same single-flight refresh as `POST /api/reload`.

The systemd unit runs with `CAP_NET_BIND_SERVICE` so it can bind port 53 without running as root. `ProtectSystem=strict` and `NoNewPrivileges` are set for defence in depth.

### Docker

**1. Create a data directory and place your config in it:**

```bash
mkdir -p data
cp config.yaml data/
```

The container runs as `/app` as its working directory and reads config from
`/app/config.yaml`. Mounting `./data` there keeps all persistent files — the
SQLite database, blocklist cache, and config — on the host so they survive
container restarts and image upgrades.

**2. Build the image:**

```bash
docker build -t s-hole .
```

**3. Run:**

```bash
docker run -d \
  --name s-hole \
  --restart unless-stopped \
  --cap-add=NET_BIND_SERVICE \
  -p 53:53/udp -p 53:53/tcp \
  -p 8080:8080 \
  -v "$(pwd)/data:/app" \
  s-hole
```

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

**On Windows (PowerShell), use backtick for line continuation and `${PWD}` for
the current directory:**

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

> **Note (Linux host):** port 53 is often already occupied by `systemd-resolved`.
> If `docker run` fails with "address already in use", disable it first:
> ```bash
> sudo systemctl disable --now systemd-resolved
> sudo rm /etc/resolv.conf
> echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
> ```
> Then re-run the `docker run` command.

### Windows (system service)

Run once as Administrator to register s-hole as an auto-start Windows Service:

```powershell
# Install (uses the config path you specify; must be absolute)
.\s-hole.exe -service install -config C:\s-hole\config.yaml

# Start / stop
.\s-hole.exe -service start
.\s-hole.exe -service stop

# Remove
.\s-hole.exe -service uninstall
```

The service can also be managed through the standard Windows Services panel (`services.msc`) or `sc.exe`.

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

All targets produce a statically linked binary with debug info stripped (`-ldflags="-s -w"`). No CGO is required — `modernc.org/sqlite` is a pure Go SQLite port.

On Windows without `make`, use PowerShell:

```powershell
$env:GOOS="linux"; $env:GOARCH="arm64"
go build -ldflags="-s -w" -o s-hole-linux-arm64 ./cmd/s-hole
$env:GOOS=""; $env:GOARCH=""
```

---

## Development

The `Makefile` is the canonical entry point for every routine task. Run `make help` for the full list. The most useful targets:

```bash
make check       # gofmt + go vet + golangci-lint + go test
make test        # plain test run
make test-race   # tests under the race detector (CGO toolchain required)
make bench       # one iteration of each benchmark
make lint        # golangci-lint
make fmt         # gofmt -s -w
make install     # go install into $GOBIN
make version     # print the version that the next build would embed
```

Coverage by package (after `go test -cover ./...`):

| Package | Coverage |
|---|---|
| `internal/stats` | 100 % |
| `internal/config` | 100 % |
| `internal/version` | 100 % |
| `internal/cache` | 94.8 % |
| `internal/api` | 91.9 % |
| `internal/blocklist` | 89.3 % |
| `internal/dnsserver` | 87.0 % |
| `internal/querylog` | 85.4 % |

The uncovered region is the `main()` bootstrap and the Windows-only SCM glue — both exercised by manual smoke tests, not unit tests.

The binary reports its build identity at any time:

```
$ s-hole -version
s-hole v1.0.0
  commit:  ab12cd3
  built:   2026-06-24T12:00:00Z
  go:      go1.25.0
  os/arch: linux/amd64
```

CI runs lint + race-enabled tests + cross-compile for `linux/{amd64,arm64,armv7}` and `windows/amd64` on every push and PR — see `.github/workflows/ci.yml`. Dependabot keeps Go modules, GitHub Actions, and the Docker base image up to date.

---

## Architecture

```
                   Client devices (DNS via DHCP)
                                │
                                │ UDP/TCP :53
                                ▼
     ┌──────────────────────────────────────────────────────┐
     │                   s-hole process                     │
     │                                                      │
     │   ┌──────────────────────────────────────────────┐   │
     │   │  DNS Handler  (per query)                    │   │
     │   │    1. blocklist  → sinkhole reply            │   │
     │   │    2. cache hit  → cached reply              │   │
     │   │    3. cache miss → upstream forward + cache  │   │
     │   └──────────────────────────────────────────────┘   │
     │                                                      │
     │   ┌───────────┐   ┌──────────┐   ┌───────────┐       │
     │   │ Blocklist │   │  Stats   │   │ Querylog  │       │
     │   │   Store   │   │ Counter  │   │ file + DB │       │
     │   └───────────┘   └──────────┘   └───────────┘       │
     │                                                      │
     │   ┌──────────────────────────────────────────────┐   │
     │   │  Admin HTTP server (default localhost:8080)  │   │
     │   │    /api/*   /healthz   /metrics   web UI     │   │
     │   └──────────────────────────────────────────────┘   │
     │                                                      │
     │   Signals: SIGINT/SIGTERM → shutdown                 │
     │            SIGHUP (Unix)  → blocklist refresh        │
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
├── deploy/            systemd unit + Linux install script
├── docs/              DESIGN, CHANGELOG, CL log, BUGS
├── .github/           CI workflows, dependabot, CODEOWNERS, PR & issue templates
├── .golangci.yml      lint config
├── config.yaml        default configuration
├── Dockerfile         multi-stage container build
├── Makefile           build + lint + test + install targets
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
| `internal/dnsserver` | UDP/TCP server, per-query handler, upstream forwarding with health tracking |
| `internal/querylog` | Async file and SQLite query loggers |
| `internal/stats` | Atomic counters; top-N domain/client tracking |
| `internal/api` | HTTP handlers and embedded web UI |
| `internal/config` | YAML loading with defaults and validation |
| `internal/service` | Windows Service integration (build-tagged) |

---

## Security Notes

- s-hole is designed for **LAN deployment only**. Do not expose port 53 to the public internet; there is no rate limiting or source validation.
- The SQLite query log and flat log file contain full browsing history for all devices. Treat them as sensitive data. Use `log_queries: none` if you do not need query history.
- The admin UI has no authentication. Set `api_listen: "127.0.0.1:8080"` to restrict it to localhost, or use a firewall rule to limit access. The HTTP server enforces read/write/idle timeouts and a 64 KiB request body limit to defend against slowloris-style attacks from LAN peers, but these are no substitute for proper access control on a multi-user network.
- Blocklist URLs are operator-controlled. Use HTTPS URLs from sources you trust.

---

## License

[MIT](LICENSE) — see the `LICENSE` file for the full text.
