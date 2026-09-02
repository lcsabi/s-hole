# s-hole Bug Tracker

Bugs are filed against s-hole as they are discovered. Each entry follows a
consistent issue-tracker convention: a monotonically increasing ID (`b/NNN`), a
priority (P0–P3), a component, a status, and a structured description.

**Priority scale**

| Priority | Meaning |
|----------|---------|
| P0 | Critical — data loss, security issue, or service cannot start |
| P1 | High — incorrect behaviour that will affect users in normal operation |
| P2 | Medium — should be fixed before a stable release; no data loss |
| P3 | Low — quality / polish; acceptable to defer |

---

## b/003 — dns: Start() silently drops second server error

**Priority:** P1
**Component:** dns
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

`dns.Server.Start()` launches UDP and TCP listeners in goroutines and reads one
value from an error channel. If both listeners fail concurrently, only the first
error is returned; the second is permanently lost. Additionally, if one server
crashes after a successful start, `Start()` returns the error — but only one
goroutine collects the second result, so it leaks until the process exits.

### Root Cause

`Start()` reads `<-errs` exactly once. The buffered channel (capacity 2) can
hold both errors, but the second is never drained.

### Fix

Send a value (nil or error) from every goroutine unconditionally so the caller
can always drain exactly two values. Read the first result; drain the second in a
short goroutine that logs any non-nil error so it is not silently lost.

---

## b/004 — querylog: stmt.Exec errors ignored in flush()

**Priority:** P1
**Component:** querylog
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

In `DBLogger.flush()`, each `stmt.Exec(...)` call discards its return value.
An individual row insert can fail (disk full, constraint violation) without
surfacing any diagnostic, and the enclosing transaction still commits, silently
dropping that row from the persistent log.

### Root Cause

`stmt.Exec(...)` is a multi-return function (`sql.Result, error`); the error
return is ignored at the call site.

### Fix

Check the error and log it: if the insert fails, print a diagnostic but allow
the loop to continue so the rest of the batch is not discarded.

---

## b/005 — querylog: Close() races with writer goroutine, causing final-flush data loss

**Priority:** P1
**Component:** querylog
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

`DBLogger.Close()` signals the writer goroutine via `close(d.done)` and
immediately calls `d.db.Close()`. The writer goroutine may still be inside
`flush()` (executing SQL statements) when the database is closed. This causes
the final batch of queries — typically the most recently logged ones — to be
silently lost on every clean shutdown.

### Root Cause

No synchronization exists between `Close()` and the writer goroutine's exit.
`close(d.done)` is not a blocking call; it only signals intent.

### Fix

Add a `sync.WaitGroup` to `DBLogger`. Increment it before starting the goroutine;
decrement it with `defer wg.Done()` at the top of `run()`. `Close()` waits with
`wg.Wait()` before calling `db.Close()`.

---

## b/006 — blocklist: HTTP download has no timeout or body size limit

**Priority:** P1
**Component:** blocklist
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

`fetchList` uses the default `http.Client` (no timeout) and streams the response
body directly to disk with no upper bound. A slow or adversarial server can hold
the download goroutine open indefinitely or write an arbitrarily large file,
potentially filling the disk.

### Root Cause

`http.Get(url)` uses the package-level default client, which has no timeout. The
response body is wrapped in `io.TeeReader` without a `io.LimitReader`.

### Fix

Use a package-level `http.Client` with a 60-second timeout. Wrap `resp.Body` in
`io.LimitReader(resp.Body, 256<<20)` (256 MB) before passing it to `TeeReader`.

---

## b/007 — blocklist: non-200 HTTP responses poison the on-disk cache

**Priority:** P1
**Component:** blocklist
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

`fetchList` does not check `resp.StatusCode`. A 404 or 503 response (typically
an HTML error page) is written to the cache file and then parsed as a domain
list. No domains match the parser's expected format, so the blocklist for that
URL becomes empty. Worse, the cache timestamp is updated, so the poisoned file is
reused for up to 24 hours on subsequent restarts.

### Root Cause

There is no `if resp.StatusCode != http.StatusOK` guard after `http.Get`.

### Fix

Check `resp.StatusCode` immediately after the HTTP call. On a non-200 response:
close the body, log the status code, fall back to the stale cache if one exists,
otherwise return an error. Do not write the error-page body to the cache file.

---

## b/008 — go.mod: all direct dependencies marked `// indirect`

**Priority:** P2
**Component:** build
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

Every entry in `go.mod` carries the `// indirect` comment, including
`github.com/miekg/dns`, `gopkg.in/yaml.v3`, and `modernc.org/sqlite`, all of
which are directly imported by the module. This misleads tooling (e.g. `go mod
why`) and suggests the module dependency graph was never tidied.

### Root Cause

`go mod tidy` was not run after packages were added.

### Fix

Run `go mod tidy`. The tool removes `// indirect` from direct imports and also
verifies that all transitive dependencies are correctly declared.

---

## b/009 — go.mod: `go 1.25.0` directive

**Priority:** P3
**Component:** build
**Status:** Not a Bug
**Filed:** 2026-06-24

### Description

The code review flagged `go 1.25.0` as a non-existent Go version. Investigation
confirms Go 1.25 was released in August 2025 per the standard six-month release
cadence; it is the minimum version required by `modernc.org/sqlite`. The directive
is correct and no change is needed.

---

## b/010 — cache: cache key omits Qclass

**Priority:** P2
**Component:** cache
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

The cache key is `<qname>\x00<qtype>`. DNS questions have three fields: `Qname`,
`Qtype`, and `Qclass`. Omitting `Qclass` means a `ClassCHAOS` query for
`version.bind. TXT` could receive a cached response from a `ClassINET` query for
the same name and type. Near-zero real-world impact, but technically incorrect.

### Root Cause

`key(q dns.Question)` in `internal/cache/cache.go` (formerly `cache/cache.go`)
does not include `q.Qclass`.

### Fix

Append `q.Qclass` (formatted via `dns.ClassToString`) to the key.

---

## b/011 — api: concurrent POST /api/reload requests can corrupt cache files

**Priority:** P2
**Component:** api
**Status:** Fixed in CL 7; mutex relocated to main.go in CL 8 (see b/022)
**Filed:** 2026-06-24

### Description

`handleReload` fires `go s.reloadFn()` unconditionally. If the endpoint is called
twice in quick succession, two concurrent `blocklist.Update` goroutines download
the same URLs and write to the same cache files simultaneously. Concurrent writes
to the same file are not atomic and can produce a corrupted cache entry.

### Root Cause

No guard prevents multiple concurrent reload goroutines.

### Fix

Add a `sync.Mutex` field (`reloadMu`) to `api.Server`. In `handleReload`, use
`TryLock`: if a reload is already running, return immediately with a
`"reload already in progress"` status; otherwise acquire the lock, run the reload,
and release the lock.

---

## b/012 — api: HTTP server not gracefully shut down on exit

**Priority:** P2
**Component:** api / main
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

`api.Server.ListenAndServe` uses the package-level `http.ListenAndServe`, which
returns no handle for graceful shutdown. `doStop()` in `main.go` calls
`os.Exit(0)` without draining in-flight HTTP requests, which can interrupt active
admin UI sessions mid-response.

### Root Cause

`ListenAndServe` does not expose a `*http.Server` for later shutdown.

### Fix

Change `api.Server` to hold an `*http.Server`. Add a `Shutdown(ctx)` method.
Call it from `doStop` with a 5-second context before proceeding to `os.Exit(0)`.
Suppress `http.ErrServerClosed` inside `ListenAndServe` so the goroutine in
`main.go` does not log a spurious error on clean shutdown.

---

## b/013 — dns: w.WriteMsg() errors silently ignored in handler

**Priority:** P2
**Component:** dns
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

All four `w.WriteMsg(...)` call sites in `internal/dnsserver/handler.go`
(formerly `dns/handler.go`) discard the returned
error. For TCP connections, a write failure indicates the client disconnected or
the send buffer is exhausted. Silently ignoring it makes network errors
undiagnosable from logs.

### Root Cause

`w.WriteMsg` is a single-return call in older versions of the code; the error
return was never wired up.

### Fix

Check each `w.WriteMsg` return value and log non-nil errors at the `[dns]` prefix.

---

## b/014 — blocklist: hand-rolled ASCII toLower instead of strings.ToLower

**Priority:** P2
**Component:** blocklist
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

`internal/blocklist/store.go` (formerly `blocklist/store.go`) contains a
private `toLower` function that manually iterates
bytes and converts A–Z to lowercase. Domain names are ASCII-only by spec so this
is functionally correct, but the function is non-idiomatic and adds cognitive
overhead for reviewers.

### Root Cause

The function predates the awareness of `strings.ToLower`'s performance on ASCII
strings.

### Fix

Replace `toLower(d)` with `strings.ToLower(d)` and delete the helper. Add
`"strings"` to the import block.

---

## b/015 — build: Makefile cross-compilation targets missing CGO_ENABLED=0

**Priority:** P2
**Component:** build
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

The `Dockerfile` sets `CGO_ENABLED=0` to ensure a fully static binary. The
`Makefile` targets (`pi`, `pi32`, `linux`, `all`) do not. On a host with CGO
enabled by default, the cross-compiled binary may pull in C runtime symbols and
fail to run on the target (especially when cross-compiling for ARM).

### Root Cause

`CGO_ENABLED=0` was added to the Dockerfile but not back-ported to the Makefile.

### Fix

Prefix all `go build` invocations in the Makefile with `CGO_ENABLED=0`.

---

## b/016 — querylog: channel drain in run() has a TOCTOU race

**Priority:** P2
**Component:** querylog
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

When the writer goroutine receives `<-d.done`, it drains remaining entries with:

```go
for len(d.ch) > 0 {
    batch = append(batch, <-d.ch)
}
```

`len(d.ch)` and the subsequent `<-d.ch` are not atomic. Between the length check
and the receive, another goroutine can drain the channel, making the length check
stale. The loop may also undercount: a new entry can be sent to the channel after
`len` returns 0 but before the loop exits, silently dropping it.

### Root Cause

`len` on a channel is a point-in-time snapshot; it is not synchronized with
subsequent receives.

### Fix

Use a non-blocking `select` loop to drain the channel:

```go
for {
    select {
    case e := <-d.ch:
        batch = append(batch, e)
    default:
        // channel empty
        goto flushed
    }
}
```

---

## b/017 — config: invalid block_mode and log_queries values accepted silently

**Priority:** P3
**Component:** config
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

`applyDefaults()` sets `BlockMode` to `"zero"` only when the field is empty.
Any other non-empty invalid value (e.g. `"NXDOMAIN"` or `"nullroute"`) is
passed through. In `internal/dnsserver/handler.go` (formerly `dns/handler.go`),
the guard is `if h.blockMode == "nxdomain"`,
so a typo silently falls back to `zero` with no diagnostic. Similarly,
`log_queries` accepts any string, and typos result in all queries being logged
regardless of operator intent.

### Root Cause

No validation step is run after `applyDefaults()`.

### Fix

Add a `Validate() error` method to `Config` that checks `BlockMode` and
`LogQueries` against their valid values and returns an error on mismatch. Call it
in `main.go` immediately after `config.Load`; treat an error as fatal.

---

## b/018 — cache: cleanup goroutine has no Close() method

**Priority:** P3
**Component:** cache
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

`cache.New()` starts a background goroutine (`runCleanup`) that runs a ticker
indefinitely. There is no way to stop it. In the current codebase the goroutine
is harmless because `os.Exit(0)` terminates the process. However, if `Cache` is
ever instantiated in a test or discarded at runtime (e.g. on a config reload),
the goroutine leaks permanently.

### Root Cause

`runCleanup` was written as a fire-and-forget loop with no stop channel.

### Fix

Add a `stop chan struct{}` field to `Cache`. `New()` initialises it;
`runCleanup` selects on it and returns when it fires. Add `Cache.Close()` which
closes the stop channel. Call `dnsCache.Close()` in `main.go`'s `doStop`.

---

## b/019 — Dockerfile: alpine:latest is unpinned

**Priority:** P3
**Component:** build
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

The runtime stage uses `FROM alpine:latest`. The `latest` tag resolves to a
different image digest on every pull. Two `docker build` invocations separated by
an Alpine point release will produce functionally different images with no change
to the source tree, making builds non-reproducible.

### Root Cause

The Dockerfile was written for convenience during development and was not pinned
before being checked in.

### Fix

Replace `alpine:latest` with a pinned minor version tag (`alpine:3.21`).

---

## b/020 — querylog: Multi uses anonymous interface instead of a named Logger type

**Priority:** P3
**Component:** querylog
**Status:** Fixed in CL 7
**Filed:** 2026-06-24

### Description

`querylog.Multi` holds a slice of an anonymous inline interface:

```go
loggers []interface {
    Log(clientIP, domain string, blocked bool)
}
```

There is no compile-time guarantee that `FileLogger`, `DBLogger`, and `Multi` all
implement the same named interface. If the `Log` signature is ever changed in one
type but not another, the mismatch will only surface when the caller tries to
construct a `Multi`, not at the point of the type definition.

### Root Cause

No named `Logger` interface was defined in the `querylog` package when `Multi` was
introduced.

### Fix

Define `type Logger interface { Log(clientIP, domain string, blocked bool) }` in
`internal/querylog/logger.go` (formerly `querylog/logger.go`). Change
`Multi.loggers` to `[]Logger`. Add compile-time
interface assertions for `FileLogger`, `DBLogger`, and `Multi`.

---

## b/021 — stats: Snapshot block percentage can briefly exceed 100%

**Priority:** P1
**Component:** stats
**Status:** Fixed in CL 8
**Filed:** 2026-06-24

### Description

Under sustained query load, `GET /api/stats` and the periodic `Print()` output
can report a `blocked_pct` greater than 100. Operators observing the admin UI
see "60% blocked" against a total query count smaller than the blocked count.

### Root Cause

`Counter.Snapshot()` reads `total` first and `blocked` second. `RecordQuery`
increments `total` (atomic) *before* taking the mutex and incrementing
`blocked`. Between the `total.Load()` and the `blocked.Load()`, more queries
can complete — each contributing to both counters — so `blocked.Load()`
includes increments whose corresponding `total.Load()` happened after the
snapshot.

### Fix

Swap the load order: read `blocked` first, then `total`. Because every
increment to `blocked` is preceded by an increment to `total`, the subsequent
`total.Load()` is guaranteed to be ≥ the earlier `blocked.Load()`. The
arithmetic invariant `blocked ≤ total` is restored.

---

## b/022 — main: periodic blocklist refresh races with /api/reload

**Priority:** P0
**Component:** main / api
**Status:** Fixed in CL 8
**Filed:** 2026-06-24

### Description

CL 7's b/011 fix added a `sync.Mutex` inside `api.Server` to prevent two
concurrent `POST /api/reload` requests from racing on cache file writes. The
periodic refresh ticker (`runTicker(refreshInterval, reloadFn)` in `main.go`)
calls the same `reloadFn` directly, bypassing the mutex. A timer-driven
refresh that overlaps with an API-driven refresh — or with itself, if a
prior refresh is still running — re-creates the original race. Both
goroutines call `os.Create` on the same cache file and the result is
non-deterministic.

### Root Cause

The mutex lives in the wrong layer. It guards the API entry point but not
the underlying operation, so any other caller of `reloadFn` is unprotected.

### Fix

Move the mutex into a closure in `main.go` that wraps `blocklist.Update`.
The closure tries to acquire the lock; if it fails, it returns `false`
synchronously. If it succeeds, it spawns a goroutine that runs the download
and releases the lock on completion. Both the API handler and the periodic
timer call this closure. The API handler reports
`"reload already in progress"` when the closure returns `false`; the timer
silently skips the tick.

---

## b/023 — querylog: flush() silently drops entire batch on Begin/Prepare/Commit failure

**Priority:** P1
**Component:** querylog
**Status:** Fixed in CL 8
**Filed:** 2026-06-24

### Description

`DBLogger.flush()` calls `tx.Begin`, `tx.Prepare`, and `tx.Commit` in sequence.
A failure on any of these three is logged as a one-line message that does not
reveal the size of the lost batch. On a disk-full event or extended lock
contention, hundreds of query rows can vanish per flush interval with no
indication of how much was lost.

### Root Cause

The error log lines (`"db begin: %v"`, `"db prepare: %v"`, `"db commit: %v"`)
omit `len(batch)`. CL 7's b/004 fix only covered the inner `stmt.Exec` errors.

### Fix

Include `len(batch)` in the error log on every batch-level failure path. Use
phrasing `"dropping N entries"` so an operator scanning logs can count total
loss across an outage.

---

## b/024 — blocklist: full-failure refresh wipes the block set; Update returns nil on failure

**Priority:** P0
**Component:** blocklist
**Status:** Fixed in CL 8
**Filed:** 2026-06-24

### Description

Two related defects in `blocklist.Update`:

1. If every configured URL fails (network outage, all CDN endpoints 5xx),
   the local variable `all` is `nil` and the function calls
   `store.Replace(nil)`. The blocked set becomes empty. Every ad is
   unblocked until the next refresh succeeds — potentially 24 hours later
   in the default config.
2. The function declares a `return error` signature but always returns
   `nil`, regardless of whether any URL was loaded. Callers cannot
   distinguish a successful refresh from a total failure.

### Root Cause

The function unconditionally calls `store.Replace(all)` and unconditionally
returns `nil`. There is no success-counting step.

### Fix

Track a `ok` counter and `lastErr` while iterating. If `ok == 0 &&
len(urls) > 0`, skip `store.Replace` (preserving the prior block set) and
return a wrapped error reporting the last failure. Log a one-line summary
noting that the existing block set is being kept and its current size.

---

## b/025 — api: HTTP server has no timeouts (slowloris exposure)

**Priority:** P2
**Component:** api
**Status:** Fixed in CL 8
**Filed:** 2026-06-24

### Description

`api.Server.ListenAndServe` constructs `&http.Server{Addr, Handler}` with no
`ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, or `IdleTimeout`. A LAN
peer that opens connections and sends headers at a single byte per minute
will tie up server goroutines indefinitely. The admin server has no
authentication and listens on `0.0.0.0:8080` by default, so any device on
the LAN can mount this attack.

### Root Cause

Default `http.Server` field values are zero, which Go interprets as "no
timeout."

### Fix

Set explicit timeouts on the `http.Server`:
`ReadHeaderTimeout=5s`, `ReadTimeout=15s`, `WriteTimeout=30s`, `IdleTimeout=60s`.
These are conservative for an admin UI that only issues short JSON requests.

---

## b/026 — api: /api/whitelist POST has no body size limit

**Priority:** P2
**Component:** api
**Status:** Fixed in CL 8
**Filed:** 2026-06-24

### Description

`handleWhitelistAdd` decodes `r.Body` directly via `json.NewDecoder` with no
size cap. A LAN attacker can stream an infinite JSON payload at the
unauthenticated server, exhausting memory. Even a 1 GB body of nested arrays
would trigger an OOM kill on a Raspberry Pi.

### Root Cause

`http.Request.Body` defaults to unbounded read. The decoder allocates
buffers proportional to input size.

### Fix

Wrap `r.Body` in `http.MaxBytesReader(w, r.Body, 64*1024)` before decoding.
64 KiB is large enough for any realistic whitelist entry and small enough
that malformed clients are rejected immediately.

---

## b/027 — docs: /api/reload incorrectly described as "idempotent"

**Priority:** P3
**Component:** docs
**Status:** Fixed in CL 8
**Filed:** 2026-06-24

### Description

`DESIGN.md` describes `POST /api/reload` as "idempotent if already running."
HTTP idempotence has a specific RFC-7231 meaning: the same request produces
the same server state regardless of the number of times it is executed.
`/api/reload` is not idempotent in that sense — it *de-duplicates*
concurrent requests via a single-flight mutex, which is a different
property. The first request triggers the refresh; subsequent concurrent
requests are no-ops.

### Root Cause

Imprecise terminology in the design doc.

### Fix

Replace "idempotent if already running" with "de-duplicated via
single-flight mutex" or equivalent phrasing in `DESIGN.md`.

---

## b/028 — config: Load returns io.EOF on an empty config file

**Priority:** P3
**Component:** config
**Status:** Fixed in CL 10
**Filed:** 2026-06-24

### Description

`../README.md` and the `config` package doc state "an empty config file is
valid" because every field has a safe default. In practice, `config.Load`
returned `io.EOF` when handed an empty file, refusing to start the
process. The bug was discovered by `TestLoad_EmptyAppliesDefaults` while
writing the unit test suite.

### Root Cause

`yaml.NewDecoder(f).Decode(&cfg)` returns `io.EOF` on a stream that
contains no YAML document. `Load` returned the error verbatim instead of
treating EOF as "no overrides" and falling through to `applyDefaults`.

### Fix

Wrap the decode error: `if err != nil && !errors.Is(err, io.EOF)`. Empty
files now load successfully and produce a Config with all defaults applied.

---

## b/029 — dnsserver tests: pickFreePort ignores per-protocol Windows port exclusions

**Priority:** P3
**Component:** dnsserver (tests)
**Status:** Fixed in CL 26
**Filed:** 2026-07-12

### Description

`TestServer_StartShutdownLifecycle` and `TestIntegration_FullPipeline`
began failing consistently on the Windows dev machine with
"server never accepted a query: udp probe timed out" — with no code
change (the working diff was an HTML-only dashboard edit). The same
suite had passed hours earlier. The failure was environmental and
latent since the tests were written; starting a VirtualBox VM that
afternoon shifted Windows' dynamic port reservations into the
triggering configuration.

### Root Cause

Two stacked problems:

1. `pickFreePort` bound a free **TCP** port and assumed the same port
   number was bindable for UDP. Windows reserves large contiguous
   port ranges *per protocol* (Hyper-V/WSL dynamic exclusions,
   `netsh int ipv4 show excludedportrange`); at failure time the TCP
   ephemeral allocator was parked inside a UDP-excluded block
   (63547–64346), so every picked port bound fine for TCP and failed
   for UDP. The first fix attempt (pick via UDP `:0`, verify TCP)
   revealed the mirror image: the UDP allocator sat inside the
   TCP-excluded block (61186–61985), and because Windows allocates
   ephemeral ports sequentially, retrying `:0` stayed stuck in the
   same 800-port block.
2. The lifecycle test's probe-timeout path never read the `startErr`
   channel, so `ListenAndServe`'s immediate bind error was reported as
   a generic probe timeout — masking the root cause.

### Fix

`pickFreePort` now probes random ports in 20000–47999 (below the
49152+ dynamic-reservation area) and requires a successful bind on
**both** transports before returning; random probes escape contiguous
excluded blocks immediately, where sequential retries could not. The
lifecycle test's timeout path now also drains and reports what
`Start` returned, so a future bind failure names itself instead of
masquerading as a timeout.

---

## b/030 — deploy: installer `systemctl start` is a no-op on upgrade

**Priority:** P2
**Component:** deploy
**Status:** Fixed in CL 36
**Filed:** 2026-08-17

Found by the CL 35 ultrareview (finding bug_002).

### Description

`install-linux.sh` ends with `systemctl start s-hole`. On a fresh install this
works. On a *re-run* to upgrade — the documented update path (ROADMAP #1: `scp`
a new binary, re-run the installer) — `install -m 755` replaces the binary at a
new inode but the running process keeps executing the old one, and
`systemctl start` on an already-active unit is a no-op. The service therefore
keeps running the **old** build while the "Installed build" box added in CL 35
prints the **new** version. That is worse than the pre-CL-35 silence: it turns
the stale-binary failure mode CL 35 exists to detect into a false "you are up to
date" signal.

### Root Cause

`systemctl start` does not restart an active unit, and nothing else in the
install flow (`daemon-reload`, `enable`) reacts to the binary inode change.

### Fix

Use `systemctl restart s-hole`. `restart` picks up the new binary on an active
unit and is equivalent to `start` on an inactive one, so no branching is needed.

---

## b/031 — deploy: installer admin-UI hint misclassifies non-`0.0.0.0` LAN binds

**Priority:** P3
**Component:** deploy
**Status:** Fixed in CL 36
**Filed:** 2026-08-17

Found by the CL 35 ultrareview (finding bug_001).

### Description

The end-of-install banner decides whether to print a LAN admin URL with
`grep -qE '0\.0\.0\.0'`, matching only the literal string `0.0.0.0`. An operator
who binds the admin UI to a specific interface (`api_listen: "192.168.1.10:8080"`),
a bare port (`":8080"`), or the IPv6 wildcard (`"[::]:8080"`) gets the misleading
"this machine only — set `api_listen: "0.0.0.0:8080"` for LAN access" note even
though the UI is LAN-reachable; for the specific-IP case, following the advice
would widen the bind. Cosmetic (installer output only) — the UI is functionally
reachable in every case.

### Root Cause

The shell check tested for one literal address instead of mirroring
`isLoopbackHost` in `cmd/s-hole/main.go` (the T4 fix it was meant to match),
which treats only `127.*` / `::1` / `localhost` as loopback.

### Fix

Parse `api_listen` into host and port (stripping the YAML key, quotes, and IPv6
brackets) and classify with a `case` that mirrors `isLoopbackHost`: an empty
host, `0.0.0.0`, `::`, or a specific address is LAN-visible; only `127.*` /
`::1` / `localhost` are loopback.

---

## b/032 — dnsserver: `isPrivatePTR` case-sensitive; mixed-case private PTR leaks upstream

**Priority:** P2
**Component:** dnsserver
**Status:** Fixed in CL 36
**Filed:** 2026-08-17

Found by the CL 35 ultrareview (finding bug_004).

### Description

`isPrivatePTR` compares the query name against the all-lowercase
`privateReverseZones` with `==` / `strings.HasSuffix`. DNS names are
case-insensitive (RFC 1035 §2.3.3) and miekg/dns preserves the wire-format case
verbatim, so a PTR query for `1.1.168.192.IN-ADDR.ARPA.` — as produced by a
dns-0x20 case-randomising forwarder (Unbound `use-caps-for-id`, PowerDNS
Recursor) chained in front of s-hole, or a mixed-case `dig` argument — bypasses
the RFC 6303 intercept. It then misses the blocklist and cache and reaches
`forward()`: the upstream returns NXDOMAIN (which the cache never stores), so
every repeat leaks the internal LAN address upstream and pays a round-trip —
exactly what CL 27 exists to prevent.

### Root Cause

The private-PTR path did not fold case before matching, unlike the sibling
blocklist path (`blocklist.normalize` lowercases).

### Fix

`strings.ToLower(name)` after the qtype guard in `isPrivatePTR`, so the fold only
allocates for actual PTR queries and the non-PTR hot path is untouched. Mixed-case
regression cases added to `TestIsPrivatePTR`.

---

## b/033 — stats: `Snapshot` reads `total` before `localPTR`; `local_ptr_count` can exceed `total_queries`

**Priority:** P2
**Component:** stats
**Status:** Fixed in CL 36
**Filed:** 2026-08-17

Found by the CL 35 ultrareview (finding bug_006). Same class as b/021, applied to
a new counter pair.

### Description

`Counter.Snapshot` read `total` before `localPTR`. The handler records a private
PTR as `RecordQuery` (bumps `total`) then `RecordLocalPTR` (bumps `localPTR`), so
`localPTR` is the strictly-later counter. Reading it after `total` means a
concurrent PTR query completing between the two atomic loads can make the observed
`localPTR` exceed the observed `total`. `/api/stats` can then transiently show
`local_ptr_count > total_queries`, and `forwardable = total − blocked − localPTR`
can go negative, making the Cache Hit Rate card flash 0.0 % during PTR bursts (no
crash — the `forwardable > 0` guard prevents the divide). Same defect as b/021
(`blocked` read after `total`), which was fixed for `blocked` but not extended to
`localPTR` when the local-PTR counter was added in CL 27.

### Root Cause

The b/021 load-order rule (read a counter that is incremented *after* `total`
*before* `total`) was applied to `blocked` but not to `localPTR`.

### Fix

Read `localPTR` before `total`. The docstring's rationale was rewritten to state
the general rule rather than the per-counter special case. Added
`TestCounter_LocalPTRNeverExceedsTotalUnderLoad`, a concurrent regression modelled
on the b/021 test; it passes under `-race`.

---

## b/034 — api: `/debug/pprof/symbol` GET-only rejects `go tool pprof` POST symbolization

**Priority:** P3
**Component:** api
**Status:** Fixed in CL 36
**Filed:** 2026-08-17

Found by the CL 35 ultrareview (finding bug_003).

### Description

`/debug/pprof/symbol` was registered as `GET /debug/pprof/symbol`.
`net/http/pprof.Symbol` reads program counters from the URL query on GET and from
the request body on POST, and `go tool pprof` symbolizes by POSTing the PC list
(a real profile's list does not fit in a URL). A GET-only pattern makes the mux
answer POST with 405, so remote symbolization — the stated reason CL 20 (R35)
exposed pprof — silently fails against the stripped binaries the Makefile ships.
Only relevant when `enable_pprof` is on (off by default).

### Root Cause

The route carried a `GET` method prefix. The obvious "drop the method prefix"
does not work: a method-less `/debug/pprof/symbol` conflicts with the GET-only
`/debug/pprof/` prefix under the Go 1.22 mux (more specific path but more
methods → the mux panics at registration).

### Fix

Register `/debug/pprof/symbol` for both GET and POST explicitly (the
conflict-free form). Added `TestPprof_SymbolAcceptsPOST`. The route stays behind
the `enable_pprof` opt-in, so the security posture is unchanged.

---

## b/035 — api (tests): DB-backed endpoint tests use a banned hardcoded flush-tick sleep

**Priority:** P3
**Component:** api (tests)
**Status:** Fixed in CL 36
**Filed:** 2026-08-17

Found by the CL 35 ultrareview (finding bug_005).

### Description

`TestTopBlockedEndpoint_WithRealDB` and `TestQueriesEndpoint_WithRealDB` (added in
CL 33) used `time.Sleep(150 * time.Millisecond)` to wait for the async SQLite
writer to flush — the exact anti-pattern CL 21 (S3) removed from
`internal/dnsserver/integration_test.go` and replaced with a poll loop. It is both
slow on a healthy runner (always waits the worst case) and flaky under CI
contention (a 50 ms flush tick plus the commit can straddle 150 ms, yielding zero
rows and a spurious failure).

### Root Cause

The CL 21 (S3) convention — poll for the expected row count instead of sleeping a
fixed interval — was not carried over to the new DB-backed tests in CL 33.

### Fix

Added a `waitForRows(t, db, n)` helper that polls `db.Recent` until at least `n`
rows are committed (2 s deadline), and used it in both tests. The top-blocked test
waits for all four rows so the per-domain counts it asserts are stable.

---

## b/036 — stats: Snapshot reads `cacheHit` after `total`; CacheHitPct can transiently exceed 100 %

**Priority:** P2
**Component:** stats
**Status:** Fixed in CL 37
**Filed:** 2026-08-17

Found by the CL 36 ultrareview (finding bug_001). Third instance of the b/021
load-order class, after b/033.

### Description

`Counter.Snapshot` read `cacheHit` *after* `total`. On the cache-hit path the
handler calls `RecordQuery` (bumps `total`) then `RecordCacheHit` (bumps
`cacheHit`), so `cacheHit` is a strictly-later counter — the same precondition as
`blocked` (b/021) and `localPTR` (b/033). Reading it after `total` lets a
concurrent cache-hit query complete between the two atomic loads, so the observed
`hits` can exceed `forwardable = total − blocked − localPTR`. `/api/stats`
`cache_hit_pct` and the CL 25 "Cache Hit Rate" dashboard card can then transiently
render above 100 %. No crash or data loss; `forwardable` stays non-zero on this
path so there is no divide-by-zero.

The irony: CL 36 rewrote this exact docstring to state the general rule ("every
counter incremented after `total` must be read before `total`") while fixing
`localPTR`, but left `cacheHit` on the wrong side of `total` — a doc-vs-code
contradiction.

### Root Cause

The b/021 load-order rule was applied to `blocked` (CL 8) and `localPTR` (CL 36)
but not to `cacheHit`, even though `cacheHit` satisfies the same
"incremented-after-`total`" condition on every cache hit.

### Fix

Read `cacheHit` before `total`. The docstring now names all three later-counters
(`blocked`, `localPTR`, `cacheHit`) as the general invariant. Added
`TestCounter_CacheHitRateNeverExceeds100UnderLoad`, a concurrent regression
modelled on the b/033 test; it passes under `-race`.

---

## b/037 — dnsserver/cache/stats/querylog: post-blocklist paths key on case-sensitive `q.Name`

**Priority:** P3
**Component:** dnsserver / cache / stats / querylog
**Status:** Won't Fix — by design (documented in CL 37)
**Filed:** 2026-08-17

Found by the CL 36 ultrareview (finding bug_002). Sibling of b/032.

### Description

DNS names are case-insensitive (RFC 1035 §2.3.3) and miekg/dns preserves the
wire-format case in `q.Name`. The blocklist and whitelist paths fold case
(`blocklist.normalize`), so **filtering is correct regardless of case**. The
post-blocklist bookkeeping paths do not fold: the cache key (`cache.key`), the
in-memory top-domains tally (`stats.RecordQuery`), and the persistent query log
(`queries.domain`, no `COLLATE NOCASE`) all key on the raw `q.Name`. So
`Google.com.` and `google.com.` produce distinct cache entries and distinct
dashboard rows. The only trigger is a dns-0x20 case-randomising resolver (Unbound
`use-caps-for-id`, PowerDNS Recursor) chained *in front of* s-hole; a normal LAN
of stub resolvers emits lowercase and never hits it.

### Resolution

**Working as intended — not changed.** The suggested fix (fold `q.Name` and reuse
it for the cache key and the returned response) would make a cache hit echo a
*different* case than the client sent, which **breaks the dns-0x20 spoofing check
in exactly the case-randomising downstream resolvers that are the only trigger for
this issue** — today's per-case cache entries always echo the client's exact case.
So the case-sensitive keys are a deliberate trade-off: correct case-echo for 0x20
downstreams, in exchange for a lower cache hit rate and possible dashboard
duplicate rows under that uncommon topology. On a normal LAN there is no
observable duplication. Filtering correctness is unaffected either way. Revisit
only if a case-insensitive-cache-with-case-preserving-response design is warranted
(store canonical, but rewrite the response's question/owner names back to the
client's case before sending) — more machinery than the nit justifies today.

---

## b/038 — querylog: retention prune races the writer on SQLITE_BUSY; pragmas apply to one pooled connection

**Priority:** P2
**Component:** querylog
**Status:** Fixed in CL 38
**Filed:** 2026-08-18

Surfaced as an intermittent CI failure of `TestDBLogger_RetentionPruneDeletesOldRows`
under the race detector.

### Description

`NewDBLogger` opened the SQLite database with `database/sql`'s default
connection pool (multiple connections). Two goroutines write: the async batch
writer (`run`) and the retention prune (`runPrune`, which prunes immediately on
startup and hourly). SQLite permits only one writer at a time, and no
`busy_timeout` was set, so when the two writers landed on different pooled
connections the second failed *immediately* with `SQLITE_BUSY`. `prune` logs a
WARN and returns on error, so the `DELETE` was silently skipped — old rows
survived. In the test, the startup prune, the seed transaction, and the explicit
`prune()` contended; one hit `SQLITE_BUSY`, so `old.com` was not deleted and the
assertion failed with "after prune got 2 rows, want 1". The race detector's
timing widened the window enough to make it fail on CI.

A second, latent defect: the per-connection pragmas (`synchronous`,
`cache_size`, `temp_store`, and a `busy_timeout` had one existed) were applied
via `db.Exec` on the pool, so they stuck only to whichever pooled connection
served that call — other connections ran without them.

### Root Cause

A multi-connection pool over an embedded single-writer database, with no
`busy_timeout` to serialise contending writers and no guarantee that
per-connection pragmas reach every connection.

### Fix

Pin the pool to one connection with `db.SetMaxOpenConns(1)`, so `database/sql`
queues callers instead of letting two writers collide, and so the pragmas apply
to the one connection that serves every query. Add `PRAGMA busy_timeout=5000`
as defence against an external process (e.g. the `sqlite3` CLI) holding the
lock. Verified with the previously-flaky test run 50× under `-race`, plus the
full race suite. At home-network query volume the lost read concurrency is
immaterial. The prune's WARN-and-skip-on-error behaviour is left as-is: with
contention removed it no longer fires, and a genuinely failed prune is still
best-effort (retried on the next tick).

---

## b/039 — deploy: Docker binary in /app is shadowed by the documented volume mount; container cannot start

**Priority:** P1
**Component:** deploy
**Status:** Fixed in CL 39
**Filed:** 2026-08-18

### Description

The runtime image copied the binary to `/app/s-hole` (`WORKDIR /app`, `COPY
--from=builder /build/s-hole .`, `ENTRYPOINT ["./s-hole"]`) while also declaring
`/app` a `VOLUME`. The README's documented `docker run` mounts a host data
directory over that same path (`-v "$(pwd)/data:/app"`). A bind mount replaces
the directory's contents, so the mount shadowed the binary: container init
failed with

```
exec: "./s-hole": stat ./s-hole: no such file or directory
```

Following the README exactly reproduced it — the container could not start at
all whenever a data volume was mounted (i.e. the recommended configuration). The
baked-in `/app/config.yaml` was shadowed by the same mechanism, but that is
intentional (operators supply their own config in the mounted directory); only
the binary being co-located in the volume was the defect.

### Root Cause

The executable was placed inside the directory that is declared a `VOLUME` and
documented as a bind-mount target. Anything under a bind-mounted path is hidden
by the host directory mounted over it, so the binary disappeared at runtime.

### Fix

Copy the binary to `/usr/local/bin/s-hole` (on `PATH`, outside `/app`) and
change the entrypoint to `["s-hole"]`. `/app` stays the `WORKDIR` and the data
`VOLUME`; the binary is now reachable no matter what the operator mounts over
`/app`. Verified by rebuilding and running the previously-failing
`-v "$(pwd)/data:/app"` command: the container starts, loads blocklists, serves
DNS + admin UI, and writes the blocklist cache and query DB into the host
directory.

---

## b/040 — blocklist: ValidDomain accepts a bare TLD with a trailing dot, so a whitelist typo can disable a whole TLD

**Priority:** P3
**Component:** blocklist
**Status:** Fixed in CL 42
**Filed:** 2026-08-19

### Description

`ValidDomain` gated its dot check with `strings.Contains(s, ".")`, so a bare
label with a trailing root dot passed: `"com."` is four characters, contains a
dot (the trailing one), and uses only allowed characters. The config `whitelist`
filter (`filterWhitelist`) and `POST /api/whitelist` both validate with
`ValidDomain`, so `whitelist: ["com."]` reached the store. `normalize` strips the
trailing dot and stores the bare label `"com"`. The CL 30 suffix walk in
`IsBlocked` then matches at the final label of every `.com` query, so all `.com`
domains were exempted, including any explicitly on the block set. No WARN fired
and `/readyz` stayed green.

The trigger is an uncommon operator typo (a bare TLD followed by a dot; `"com"`
alone was already rejected), so the impact is a silent defense-in-depth hole,
not a default-configuration failure. Found by ultrareview.

### Root Cause

The dot check counted a trailing root dot, so `ValidDomain` could not tell a real
two-label name from a single label written as an FQDN. The CL 31 guard caught the
no-dot form `"com"` but not `"com."`, one keystroke apart.

### Fix

Require an interior dot in `ValidDomain`: reject when the first dot is at index 0
(leading dot) or at the last index (trailing dot on a single label). A real FQDN
with a root dot (`"example.com."`) still has an interior dot and stays valid;
`normalize` strips its trailing dot as before. Regression cases added for
`"com."`, `"."`, `"a."`, and `".com"` in `TestValidDomain`, plus a `"com."` drop
case in `TestFilterWhitelist`.

---

## b/041 — config: applyEnvOverrides docstring claims the package "deliberately avoids logging"

**Priority:** P3
**Component:** config
**Status:** Fixed in CL 42
**Filed:** 2026-08-19

### Description

The `applyEnvOverrides` docstring justified silently ignoring malformed numeric
env values by stating "the config package deliberately avoids logging". That was
true when written, but CL 31 added a package logger (`var logger =
slog.With("pkg", "config")`) and a `logger.Warn` call in `Load` for invalid
whitelist entries. The stated rationale was therefore false. A future contributor
could either remove the CL 31 WARN (reading the package as log-free) or add a
WARN to the env path without knowing the silence was deliberate. Found by
ultrareview. Doc-vs-code drift, comment-only.

### Root Cause

The docstring was not updated when CL 31 introduced logging to the package.

### Fix

Replace the false parenthetical with the real policy: env overrides are
best-effort container knobs, so a per-typo WARN on every restart is noise, and
the only invariant is that a bad env var never blocks startup. The docstring now
also notes why the invalid-whitelist path in `Load` does WARN (a dropped
whitelist entry can widen blocking to a whole subtree).

---

## b/042 — docs: CL-32/33/34.md ended with leaked tool-call XML tags

**Priority:** P3
**Component:** docs
**Status:** Fixed (trailing tags trimmed; see Fix)
**Filed:** 2026-08-19

### Description

`docs/cls/CL-32.md`, `docs/cls/CL-33.md`, and `docs/cls/CL-34.md` each ended with
stray `</content>` and `</invoke>` tags. These are Write tool-call serialization
that leaked into the files when the CLs were authored, not intended Markdown. On
GitHub they render as literal text at the bottom of each CL page, which
contradicts the `CL.md` promise that each CL "renders as a properly-paginated page
on GitHub". Found by ultrareview.

### Root Cause

Tool-call output was copied into the file bodies at authoring time. No Markdown
linter runs in CI, so nothing caught it.

### Fix

Trim the trailing tag lines (two from CL-32, three each from CL-33 and CL-34); no
other content changed. CL files are immutable historical records, so this edit
was a one-time exception, approved by the maintainer, on the grounds that the
tags are accidental serialization garbage and never part of the record's content.
The narrative and decisions of each CL are untouched.

---

## b/043 — main: interactive shutdown races its own ordered teardown (data loss on `systemctl stop`)

**Priority:** P1
**Component:** main
**Status:** Fixed in CL 59
**Filed:** 2026-08-30

### Description

`doStop` ran `shutdown()` in the signal goroutine and then called `os.Exit(0)`.
Step 3 of `shutdown()` (`stopDNS`) unblocks `dnsServer.Start()` in the main
goroutine, so `main()` returns and the Go runtime terminates the process. Nothing
forced the remaining teardown steps (drain HTTP, wait for an in-flight reload,
close the cache and loggers, close the DB) to finish first. The main goroutine's
remaining work is trivial, so it usually won the race and those steps were
skipped.

The Linux binary takes this interactive path, so every `systemctl stop` or
restart sends SIGTERM into it. The DBLogger "final batch never lost on clean
exit" guarantee (R34) and the "wait for an in-flight reload so a refresh is not
killed mid os.Rename" guarantee (R53) were defeated in production, and in-flight
admin HTTP was not drained. Found by ultrareview. `-race` detects memory races,
not process-exit ordering, and `TestShutdown_TeardownOrder` calls `shutdown()`
directly, so it bypassed the `main`-return exit route.

### Root Cause

Two exit routes raced the same teardown: the `main`-return after `Start()`
unblocked, and `os.Exit(0)` in `doStop`. The teardown order in `shutdown()` was
correct, but nothing made the process wait for it to finish.

### Fix

Make `doStop` the sole exit authority. Run `dnsServer.Start()` in a goroutine and
block the interactive path (`blockUntilStopped`) on a `done` channel that `doStop`
closes only after `shutdown()` returns. Remove the `os.Exit(0)` from `doStop`. A
startup bind failure still exits non-zero via the serve-error channel. `doStop` is
wrapped in `sync.Once` so a second stop request cannot re-run teardown.
`waitForReload` also gets its own timeout budget so a slow HTTP drain cannot
starve it (open question B). Regression: `TestBlockUntilStopped_WaitsForTeardown`
asserts the last teardown step runs before the process is allowed to exit.

---

## b/044 — service (Windows): Execute relied on doStop calling os.Exit

**Priority:** P2
**Component:** service
**Status:** Fixed in CL 59
**Filed:** 2026-08-30

### Description

`handler.Execute` sent `StopPending`, called `h.stop()`, and never sent
`svc.Stopped`. It relied on `doStop` (via `h.stop()`) calling `os.Exit` to
terminate the process before `Execute` returned. The b/043 fix removes that
`os.Exit`, so `doStop` now returns instead of exiting. Without a change here, the
SCM would hang in `StopPending` after a stop control. Found by ultrareview
(coupled to b/043). Windows-only; not reachable on the Linux review host.

### Root Cause

`Execute` depended on a side effect (`os.Exit` inside `doStop`) for its state
machine to complete, instead of reporting the service state itself.

### Fix

After `h.stop()` returns, send `svc.Status{State: svc.Stopped}` and return from
`Execute`. The SCM then sees the service reach `Stopped`, `svc.Run` returns, and
`main` exits. Verify on a Windows/SCM host (part of the R58 checklist): a real
SCM stop reaches `Stopped` and does not hang in `StopPending`.

---

## b/045 — dnsserver: upstream second sweep re-tries the upstreams that just failed

**Priority:** P1
**Component:** dnsserver
**Status:** Fixed in CL 60
**Filed:** 2026-08-30

### Description

`forwardWith` runs two sweeps. Sweep 1 skips upstreams in cooldown and tries the
rest. Sweep 2 is meant to retry only the upstreams that were already in cooldown
at function entry. The sweep-2 gate reused the entry-time `now` in `shouldSkip`,
but sweep 1 records each fresh failure with `recordFailure(upstream, time.Now())`
at a time after `now`. So for an upstream that just failed in sweep 1,
`now.Sub(last)` is negative, `negative < 30s` is true, `shouldSkip` returns true,
and the gate re-exchanged it. Sweep 2 retried exactly the upstreams it was
written to skip. The comment claimed the entry-time `now` prevented this; it did
not. Found by ultrareview.

On a total upstream outage every upstream was contacted twice per query. With
timeout (black-hole) upstreams the query burned the full 10 s `queryDeadline` and
returned `context deadline exceeded` instead of the faster "all upstreams
failed". Doubled failure-path latency and upstream load during an outage. The
client-visible result was unchanged (SERVFAIL either way), so this was a
robustness and efficiency defect, not a resolution-correctness defect.

`TestForward_AllFailReturnsError` used connection-refused ports (instant) and
asserted only `err != nil`, so it could not see the double attempt.

### Root Cause

Sweep 2 re-derived "not yet tried" from timestamps that sweep 1 had just
mutated. The entry-time `now` was older than every fresh failure stamp, so the
just-failed upstreams read as still in cooldown.

### Fix

Track the set actually attempted in sweep 1 (`tried map[string]bool`) and skip
exactly that set in sweep 2, instead of re-deriving it from timestamps. Each
upstream is now contacted at most once per query. Regression:
`TestForward_AllFailContactsEachOnce` uses a counting fast-failing upstream and
asserts each is contacted exactly once on the all-fail path.

---

## b/046 — querylog/config: non-positive db_flush_interval panics the writer goroutine

**Priority:** P2
**Component:** querylog
**Status:** Fixed in CL 61
**Filed:** 2026-08-30

### Description

`config.ParsedDBFlushInterval` accepted a well-formed but non-positive duration
(`"0s"`, `"-5s"`), and `Validate()` never checked it. The value reached
`NewDBLogger`, which stores it and later calls `time.NewTicker(d.flushInterval)`
in the writer goroutine. `time.NewTicker` panics on a non-positive duration, so
the daemon crashed from a goroutine stack after the SQLite file was already open.
Every other malformed-config value does a clean log-and-exit; this one did not.
Found by ultrareview.

### Root Cause

The duration was parsed but never range-checked. A malformed string (`"abc"`) was
rejected at the config gate, but a well-formed non-positive value passed through
to the point of use, where `time.NewTicker` enforces the constraint by panicking.

### Fix

Reject a non-positive interval in `ParsedDBFlushInterval` so main's config-error
path logs and exits cleanly, consistent with how a malformed duration string is
handled. Guard `NewDBLogger` too (defense-in-depth) so the type can never panic
its goroutine regardless of caller. Tests:
`TestParsedDBFlushInterval_RejectsNonPositive` and
`TestNewDBLogger_NonPositiveFlushIntervalErrors`.

---

## b/047 — config: S_HOLE_LOCAL_PTR case-sensitive parse silently disables a default-on feature

**Priority:** P2
**Component:** config
**Status:** Fixed in CL 61
**Filed:** 2026-08-30

### Description

`applyEnvOverrides` set `c.LocalPTR = v == "1" || v == "true" || v == "yes"`.
The check was case-sensitive with no fallback, so `TRUE`, `On`, `enabled`, and a
present-but-empty value all evaluated to false. `LocalPTR` defaults to true, so an
operator who set the var intending to keep local PTR on instead flipped it off:
local PTR answering stopped and LAN reverse-DNS queries leaked upstream, the exact
thing the feature prevents, with no warning. `S_HOLE_ENABLE_PPROF` used the same
pattern; its default is false, so its direction was harmless. Found by
ultrareview.

### Root Cause

A hand-rolled truthy check matched three exact lowercase tokens and treated
everything else, including unrecognised-but-truthy input, as false. For a
default-on setting that is fail-unsafe.

### Fix

Add `parseBoolEnv(v, def)`: it accepts the documented tokens (1/true/yes and
0/false/no) case-insensitively and returns the default on anything else, so an
unrecognised value never flips the setting. Use it for both `S_HOLE_LOCAL_PTR` and
`S_HOLE_ENABLE_PPROF`. `strconv.ParseBool` was not used: it rejects `yes`/`no`,
which the README documents for these vars, so it would break documented input.
Tests updated: the empty and unrecognised cases now assert the default is kept.

---

## b/048 — docs: DESIGN mis-states the stats counter load order (b/033 hazard in prose)

**Priority:** P3
**Component:** docs
**Status:** Fixed in CL 61
**Filed:** 2026-08-30

### Description

`docs/DESIGN.md` (Statistics section) said `Snapshot` loads `blocked` before
`total`, then `localPTR` after `total`, and justified it with "`total >= localPTR`
always holds". Reading `localPTR` after `total` is exactly the b/033 regression:
two atomics read at different instants can yield `local_ptr/total > 100%`. The
code is correct (it reads `blocked`, `localPTR`, and `cacheHit` all before
`total`, per the b/036 general invariant) and its comments agree; the DESIGN
sentence contradicted the code. CLAUDE.md treats doc-vs-code drift as a bug. Found
by ultrareview. Doc-only.

### Root Cause

The DESIGN prose was not updated when b/033 (localPTR) and b/036 (cacheHit)
generalised the load-order rule to every counter incremented after `total`.

### Fix

State that `Snapshot` loads `blocked`, `localPTR`, and `cacheHit` all before
`total`, and that each is read before `total` because each is incremented after
it. Drop the false "`total >= localPTR` always holds" justification. No code
change.

---

## b/049 — blocklist: Sources() returns nil, not the documented empty slice

**Priority:** P3
**Component:** blocklist
**Status:** Fixed in CL 62
**Filed:** 2026-08-30

### Description

`Store.Sources()` documents "an empty slice before the first Update" but returned
`nil`. Marshaled by `/api/stats`, a `nil` slice serializes as JSON `null`, not
`[]`, so in the brief pre-first-refresh window a client that expects an array sees
a different type. Doc-vs-code drift, which CLAUDE.md treats as a bug. Found by
ultrareview.

### Root Cause

The zero-value return path used `return nil` instead of an empty slice literal.

### Fix

Return `[]SourceStatus{}` when no snapshot has loaded. The existing
`TestStore_SourcesEmptyBeforeUpdate` used `len() != 0`, which passes for `nil`
too, so it did not guard this; it now also asserts the result is non-nil.

---

## b/050 — blocklist: cacheFilename is many-to-one (URL collision)

**Priority:** P3
**Component:** blocklist
**Status:** Fixed in CL 62
**Filed:** 2026-08-30

### Description

`cacheFilename` collapsed `://`, `/`, `.`, `?`, `&`, `=`, and `:` all to `_`. Two
source URLs that differ only in those characters mapped to the same cache file
and overwrote each other's `os.Rename`, silently breaking the per-source stale
fallback (each source is supposed to keep its own on-disk cache to serve when a
fetch fails). Low likelihood, but silent. Found by ultrareview.

### Root Cause

The character-replacement scheme was not injective: distinct URLs could produce
the same filename.

### Fix

Hash the URL: `blocklist_` + hex(sha256(url)) + `.txt`. The mapping is injective
in practice, so distinct URLs get distinct files. The output keeps the
`blocklist_` prefix and contains only hex characters, so `FuzzCacheFilename`
stays green (and the NTFS-rename concern the old colon-escape addressed is gone).
Existing cache files under the old naming are re-downloaded once under the new
name, the same cost as a cache miss. Test:
`TestCacheFilename_DistinctURLsDistinctFiles`.

---

## b/051 — blocklist: over-cap source is silently truncated and cached as fresh

**Priority:** P3
**Component:** blocklist
**Status:** Fixed in CL 62
**Filed:** 2026-08-30

### Description

`fetchList` streamed the body through `io.LimitReader(resp.Body, maxBodyBytes)`
with a 256 MiB cap. If a source exceeded the cap, the reader stopped at the cap
with no error, `parseHostsFormat` parsed the truncated bytes, and the result was
renamed in as a fresh cache with `stale: false`. The operator got a partial
blocklist presented as healthy, with no signal. Theoretical at real blocklist
sizes. Raised as open question A by ultrareview.

### Root Cause

`io.LimitReader` truncates silently; nothing checked whether the source had more
bytes than the cap allowed.

### Fix

After `parseHostsFormat` drains the LimitReader, probe `resp.Body` for one more
byte. If a byte is readable, the body was truncated: remove the `.tmp` and take
the same fallback as a non-200 response (serve the previous cache marked stale
and WARN if one exists, else return an error). A truncated 200 is thus handled
like any other unusable 200. `maxBodyBytes` became a package var so a test can
lower it. Docs: the README blocklist section documents the cap and the truncation
behavior. Tests: `TestFetchList_TruncatedAtCapFallsBackToStale` and
`TestFetchList_TruncatedAtCapNoCacheErrors`.

---

## b/052 — main: admin-server bind failure degrades silently

**Priority:** P3
**Component:** main
**Status:** Fixed in CL 63
**Filed:** 2026-08-30

### Description

`api.Server.ListenAndServe` bound the socket and served, both inside the
background goroutine in main. So a bind failure (a bad `api_listen`, a port
conflict, a privileged port) was only visible to that goroutine, which logged one
ERROR line and exited while DNS kept serving. By then main had already printed
the startup banner advertising the admin UI, so the banner and the goroutine's
ERROR line raced and the banner advertised a UI that was not there. The admin
server also serves `/healthz`, `/readyz`, and `/metrics`, so a bind failure
silently removed the health and metrics surface while DNS looked healthy. Raised
as P4 #10 by ultrareview.

### Root Cause

Bind and serve were coupled in one call inside a goroutine, so the bind result
never reached main. main had no chance to react before advertising the UI.

### Fix

Split bind from serve. `api.Server` gains `Serve(net.Listener)`; `ListenAndServe`
is reimplemented as `net.Listen` then `Serve`. main now binds `api_listen`
synchronously before backgrounding the serve loop. On failure it logs a WARN with
remediation, keeps DNS serving (fail-open: the optional admin surface must not
take DNS down), and the banner reports the admin UI as unavailable instead of
advertising a dead URL. Tests: `TestServe_OnBoundListener`,
`TestListenAndServe_BindFailureSurfaces`, and
`TestPrintNetworkHint_AdminDownShowsUnavailable`.

---

## b/053 — api: admin http.Server field is read/written across goroutines unsynchronized

**Priority:** P4
**Component:** api
**Status:** Fixed in CL 64
**Filed:** 2026-08-30

### Description

`api.Server.httpServer` is written by `Serve` and read by `Shutdown` from two
different goroutines with no synchronization. `main` runs `Serve` in a background
goroutine (`go apiServer.Serve(apiLn)`), and `doStop` calls `Shutdown` from the
signal goroutine, so the assignment in `Serve` races the read in `Shutdown`. With
a plain `*http.Server` field this is a data race that `-race` flags. The race
predates the CL 59-63 series (the old `ListenAndServe` set the field the same way
inside the same background goroutine), so it is pre-existing, not a regression.
Raised by the CL 59-63 ultrareview follow-up.

### Root Cause

A shared struct field (`httpServer`) was written on the serve goroutine and read
on the shutdown goroutine with no memory barrier. The nil-check in `Shutdown` also
meant a stop that arrived before `Serve` stored the server would read the zero
value and no-op, skipping the in-flight-request drain; CL 63's synchronous bind
makes that window tiny, but the field race is real regardless of timing.

### Fix

Change the field to `atomic.Pointer[http.Server]`. `Serve` stores with `Store`;
`Shutdown` reads with `Load` and treats a nil result as "nothing to drain". This
makes `Server` race-free regardless of how the caller sequences `Serve` and
`Shutdown`, so a later change to main's startup order cannot reintroduce the race.
The public API is unchanged. Test: `TestServe_ConcurrentShutdownIsRaceFree` drives
`Serve` and `Shutdown` concurrently and is clean under `-race`.

---

## b/054 — api: a Shutdown before Serve stores the server drops the stop and leaks the serve loop

**Priority:** P4
**Component:** api
**Status:** Fixed in CL 65
**Filed:** 2026-08-30

### Description

CL 64 made `api.Server.httpServer` an `atomic.Pointer`, which removed the data
race on the field. A second-order timing gap survived. `main` binds the listener
synchronously (CL 63) and then runs `Serve` in a background goroutine, so a stop
signal can arrive in the small window after the goroutine starts but before
`Serve` stores the server. In that window `Shutdown` loads a nil pointer and
no-ops, and `Serve` then calls `hs.Serve(ln)` and blocks in Accept with no one
left to drain or stop it. The process is exiting, so the leaked goroutine is
reaped by process exit and the drain has nothing in flight to lose. The gap is
therefore harmless in practice, but it is a real ordering hazard that a future
change to the drain path could make matter. Raised as the open question in the
CL 64 code review.

### Root Cause

`Shutdown` and `Serve` coordinated only through the `httpServer` pointer, which is
nil until `Serve` stores it. A stop that read that nil had no other record that a
stop had been requested, so `Serve` could not know it should not start serving.

### Fix

Add a second field, `shutdownRequested atomic.Bool`, as a double-check.
`Shutdown` sets it before it loads `httpServer`; `Serve` checks it right after it
stores the server. The two set/load pairs cross, so a stop in the window cannot
be lost: either `Shutdown` loads the stored pointer and drains it, or `Serve`
sees the flag and closes the listener instead of blocking in Accept. Go's atomics
are sequentially consistent, so no both-miss interleaving exists. The public API
is unchanged. Test: `TestShutdown_BeforeServeStopsTheServeLoop` calls `Shutdown`
before `Serve` to hit the window deterministically and asserts `Serve` returns.

## b/055 — config: non-positive refresh_interval / stats_interval panic a ticker goroutine at startup and pass -check-config

**Priority:** P2
**Component:** config
**Status:** Fixed in CL 68
**Filed:** 2026-09-03

### Description

`refresh_interval` and `stats_interval` accept a well-formed but non-positive
duration such as `"0s"` or `"-5s"`. Both values feed `time.NewTicker` in
`runTicker`, which panics on a non-positive duration. `Validate()` checks only
the `block_mode` and `log_queries` enums, so a non-positive interval passes
`config.LoadAndValidate`. The new `-check-config` flag (CL 66) then prints
`config OK` and exits `0`, and the running service panics a ticker goroutine at
startup. The panic is unrecovered: `runTickerOnce`'s `recover` runs only inside
the loop, after `time.NewTicker` has already returned.

Found by the two-axis code review of the CL 59-67 range.

### Root Cause

b/046 added the `d <= 0` guard to `ParsedDBFlushInterval` only. The two sibling
parsers, `ParsedRefreshInterval` and `ParsedStatsInterval`, were left unguarded,
so the same `time.NewTicker` panic path stayed reachable for the other two
duration fields. CL 66's `-check-config` promise (a config the dry-run accepts is
one the service starts on) made the gap sharper: for these two fields the dry-run
reported a crash-on-start config as valid.

### Fix

Reject a non-positive value in `ParsedRefreshInterval` and `ParsedStatsInterval`,
the same way `ParsedDBFlushInterval` already does, so all three duration fields
fail `-check-config` and startup cleanly instead of crashing a ticker goroutine.
Tests: `TestParsedRefreshStatsInterval_RejectNonPositive` (per-parser rejection of
`0s` and `-5s`) and non-positive `refresh_interval`/`stats_interval` cases in
`TestLoadAndValidate_RejectsEachStage`.
