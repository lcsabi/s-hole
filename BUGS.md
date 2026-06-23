# s-hole Bug Tracker

Bugs are filed against s-hole as they are discovered. Each entry follows the
Google Buganizer convention: a monotonically increasing ID (`b/NNN`), a priority
(P0–P3), a component, a status, and a structured description.

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

`key(q dns.Question)` in `cache/cache.go` does not include `q.Qclass`.

### Fix

Append `q.Qclass` (formatted via `dns.ClassToString`) to the key.

---

## b/011 — api: concurrent POST /api/reload requests can corrupt cache files

**Priority:** P2
**Component:** api
**Status:** Fixed in CL 7
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

All four `w.WriteMsg(...)` call sites in `dns/handler.go` discard the returned
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

`blocklist/store.go` contains a private `toLower` function that manually iterates
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
passed through. In `dns/handler.go`, the guard is `if h.blockMode == "nxdomain"`,
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
`querylog/logger.go`. Change `Multi.loggers` to `[]Logger`. Add compile-time
interface assertions for `FileLogger`, `DBLogger`, and `Multi`.
