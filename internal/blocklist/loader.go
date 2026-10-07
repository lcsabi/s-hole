package blocklist

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lcsabi/s-hole/internal/logging"
	"github.com/lcsabi/s-hole/internal/redact"
)

var logger = logging.For("blocklist")

const cacheMaxAge = 24 * time.Hour

// httpClient has a generous timeout to handle slow mirrors; 256 MiB cap prevents
// a runaway download from filling the disk.
var httpClient = &http.Client{Timeout: 60 * time.Second}

// maxBodyBytes caps a single source download. It is a var, not a const, so a
// test can lower it; production always uses 256 MiB and never writes it.
//
// Only tests mutate this, and blocklist tests run sequentially (none call
// t.Parallel), so the fetch-path read never races a test's write. The same
// no-parallel rule protects the logger swaps (swapLogger and captureLogs) in
// loader_test.go. Keep it that way: if a blocklist test ever needs t.Parallel,
// pass the cap in explicitly rather than mutating this global, or the mutation
// races the read under -race.
var maxBodyBytes int64 = 256 << 20 // 256 MiB

// Mode says whether Update may serve a fresh on-disk cache instead of
// downloading.
type Mode int

const (
	// CacheFirst loads a source from a cache file younger than cacheMaxAge
	// without a download. Startup uses it, so a restart does not re-fetch
	// every list.
	CacheFirst Mode = iota
	// DownloadFirst always tries the download and uses the cache only as the
	// stale fallback. Every reload uses it. With CacheFirst, a reload one
	// refresh_interval after the last download found a cache just under 24
	// hours old, so the default 24h refresh downloaded only every 48 hours
	// (b/060).
	DownloadFirst
)

// Update downloads (or loads from cache, see Mode) all lists and replaces
// the store. If every configured URL fails (network outage, all servers
// down), the existing block set is preserved rather than being replaced with
// an empty slice; otherwise a transient outage would silently unblock every
// ad until the next successful refresh.
func Update(store *Store, urls []string, cacheDir string, mode Mode) error {
	var all []string
	var ok int
	var lastErr error
	sources := make([]SourceStatus, 0, len(urls))
	for _, u := range urls {
		domains, meta, err := fetchList(u, cacheDir, mode)
		if err != nil {
			lastErr = err
			logger.Warn("blocklist load failed", "url", redact.URL(u), "err", err)
			// Record the failure so a down source is visible by URL, instead
			// of hiding behind a drop in the aggregate. Zero LastRefresh
			// distinguishes a never-loaded source from a stale-cache fallback.
			sources = append(sources, SourceStatus{URL: u, Stale: true})
			continue
		}
		ok++
		all = append(all, domains...)
		sources = append(sources, SourceStatus{
			URL:         u,
			Count:       len(domains),
			LastRefresh: meta.snapshot,
			Stale:       meta.from == fromStaleCache,
		})
		logger.Info("loaded", "url", redact.URL(u), "domains", len(domains), "from", meta.from)
		warnUnreadList(u, len(domains), meta.skipped)
	}
	// Publish per-source health even when every source failed, so the
	// dashboard shows the outage rather than the last good snapshot.
	store.setSources(sources)
	if ok == 0 && len(urls) > 0 {
		logger.Error("all sources failed; keeping existing block set",
			"sources", len(urls), "current", store.Len())
		warnIfEmpty(store)
		return fmt.Errorf("all blocklists failed: %w", lastErr)
	}
	store.Replace(all)
	logger.Info("blocklist updated", "total", store.Len())
	warnIfEmpty(store)
	return nil
}

// warnUnreadList warns about a list that loaded but gave s-hole little or
// nothing to block: an empty list, or one where most lines were skipped. The
// usual cause is a format s-hole does not read, such as an Adblock list
// (EasyList gives one stray match in 80,000 lines), so a zero-only check
// would miss it. A hosts list skips only a few lines (localhost,
// broadcasthost), far fewer than it reads.
func warnUnreadList(url string, read, skipped int) {
	const hint = "s-hole reads hosts lines (0.0.0.0 example.com), one domain per line, and *.example.com lines. Use the list's hosts or domains version"
	switch {
	case read == 0 && skipped == 0:
		logger.Warn("blocklist has no domains", "url", redact.URL(url), "hint", hint)
	case skipped > read:
		logger.Warn("blocklist lines skipped", "url", redact.URL(url), "read", read, "skipped", skipped, "hint", hint)
	}
}

// warnIfEmpty raises a loud alarm when the block set is empty after an
// update. An empty store means s-hole is answering queries but blocking
// nothing, typically a first run that could reach no blocklist URL (and had
// no disk cache to fall back on), or a source that returned 200 but parsed to
// zero valid domains. /readyz reports this as 503, but that signal is easy to
// miss on a headless box, so the state is surfaced here at WARN as well.
func warnIfEmpty(store *Store) {
	if store.Len() == 0 {
		logger.Warn("block set is empty",
			"hint", "s-hole blocks no domains. Check the blocklist URLs and the network connection")
	}
}

// Values of sourceMeta.from, logged as the "from" attribute of the "loaded"
// line so an operator can tell a download from a cache load in the journal.
const (
	fromDownload   = "download"    // fetched now
	fromCache      = "cache"       // CacheFirst only: cache younger than cacheMaxAge; no fetch tried
	fromStaleCache = "stale_cache" // on-disk cache served because the fetch failed
)

// sourceMeta carries the per-source health that Update records alongside the
// domains. from says where the served data came from (see the from*
// constants); only fromStaleCache marks the source stale. snapshot is when the
// served data was fetched: the cache file's mtime for a cache load,
// or now for a fresh download.
type sourceMeta struct {
	from     string
	snapshot time.Time
	skipped  int // non-comment lines that gave no domain (see parseHostsFormat)
}

func fetchList(url, cacheDir string, mode Mode) ([]string, sourceMeta, error) {
	cachePath := filepath.Join(cacheDir, cacheFilename(url))

	if info, err := os.Stat(cachePath); err == nil && mode == CacheFirst {
		if time.Since(info.ModTime()) < cacheMaxAge {
			domains, skipped, loadErr := loadFromFile(cachePath)
			return domains, sourceMeta{from: fromCache, snapshot: info.ModTime(), skipped: skipped}, loadErr
		}
	}

	req, err := http.NewRequest(http.MethodGet, url, nil) //nolint:gosec // URL comes from operator config
	if err != nil {
		// The parse error repeats the raw URL, user name and password
		// included; redact it like a transport error.
		return nil, sourceMeta{}, fmt.Errorf("%q: %w", redact.URL(url), redactURLError(err))
	}
	// A fixed User-Agent with no version: Go's default names the Go release,
	// which tells the list host more about this machine than it needs.
	req.Header.Set("User-Agent", "s-hole")
	resp, err := httpClient.Do(req)
	err = redactURLError(err)
	if err != nil {
		// Fall back to stale cache if download fails.
		if info, statErr := os.Stat(cachePath); statErr == nil {
			logger.Warn("download failed, using stale cache", "url", redact.URL(url), "err", err)
			domains, skipped, loadErr := loadFromFile(cachePath)
			return domains, sourceMeta{from: fromStaleCache, snapshot: info.ModTime(), skipped: skipped}, loadErr
		}
		return nil, sourceMeta{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Do not write the error-page body to the cache file.
		if info, statErr := os.Stat(cachePath); statErr == nil {
			logger.Warn("non-200 response, using stale cache", "url", redact.URL(url), "status", resp.StatusCode)
			domains, skipped, loadErr := loadFromFile(cachePath)
			return domains, sourceMeta{from: fromStaleCache, snapshot: info.ModTime(), skipped: skipped}, loadErr
		}
		return nil, sourceMeta{}, fmt.Errorf("%q: HTTP %d", redact.URL(url), resp.StatusCode)
	}

	// Atomic write: stream to a sibling .tmp file, then os.Rename on success.
	// A connection drop or process kill mid-download leaves only the .tmp
	// behind; the previous cachePath stays usable (and its mtime stays old
	// so the next start re-attempts the download).
	//
	// The cache only saves a download at the next start. If the cache file
	// cannot be created (most often a data directory that belongs to another
	// user, such as root-owned files from an older Docker image), the list is
	// still parsed from the download and used, with a WARN: before, the
	// source failed and s-hole could start with no blocklist at all.
	//
	// A cache_dir that does not exist yet is created owner-only (b/089). If
	// that fails, os.Create fails too and reports it.
	_ = os.MkdirAll(cacheDir, 0o700)
	tmpPath := cachePath + ".tmp"
	body := io.LimitReader(resp.Body, maxBodyBytes)
	f, err := os.Create(tmpPath)
	if err != nil {
		warnCacheWrite(cacheDir, err)
		f = nil
	} else {
		body = io.TeeReader(body, f)
	}

	domains, skipped, parseErr := parseHostsFormat(body)
	var closeErr error
	if f != nil {
		closeErr = f.Close()
	}
	// The .tmp removals below are best-effort cleanup on failure paths; a
	// leftover .tmp is harmless (ignored by loads, overwritten by the next
	// download).
	//
	// parseErr or closeErr here means the download broke after the 200
	// status (a connection reset, or the client timeout during the body), or
	// the write to the .tmp file failed (the TeeReader returns a write error
	// as a read error). Either way the download failed, so take the same
	// stale-cache fallback as a connection error. Before, this returned an error, and a reload dropped
	// the list's domains from the block set although a cache file was on
	// disk (b/068).
	readErr := parseErr
	if readErr == nil {
		readErr = closeErr
	}
	if readErr != nil {
		_ = os.Remove(tmpPath)
		if info, statErr := os.Stat(cachePath); statErr == nil {
			logger.Warn("download failed, using stale cache", "url", redact.URL(url), "err", readErr)
			domains, skipped, loadErr := loadFromFile(cachePath)
			return domains, sourceMeta{from: fromStaleCache, snapshot: info.ModTime(), skipped: skipped}, loadErr
		}
		return nil, sourceMeta{}, readErr
	}
	// Detect a source that exceeded the cap. parseHostsFormat drained the
	// LimitReader, so any byte still readable from resp.Body means the body was
	// truncated. A truncated body is unusable like a non-200 response, so take
	// the same stale-cache fallback rather than renaming a partial list in as
	// fresh (b/051).
	var probe [1]byte
	if n, _ := io.ReadFull(resp.Body, probe[:]); n > 0 {
		_ = os.Remove(tmpPath)
		if info, statErr := os.Stat(cachePath); statErr == nil {
			logger.Warn("response truncated at cap, using stale cache", "url", redact.URL(url), "cap_bytes", maxBodyBytes)
			domains, skipped, loadErr := loadFromFile(cachePath)
			return domains, sourceMeta{from: fromStaleCache, snapshot: info.ModTime(), skipped: skipped}, loadErr
		}
		return nil, sourceMeta{}, fmt.Errorf("%q: response exceeded %d-byte cap", redact.URL(url), maxBodyBytes)
	}
	if f != nil {
		if err := os.Rename(tmpPath, cachePath); err != nil {
			_ = os.Remove(tmpPath)
			warnCacheWrite(cacheDir, err)
		}
	}
	return domains, sourceMeta{from: fromDownload, snapshot: time.Now(), skipped: skipped}, nil
}

// warnCacheWrite reports a blocklist cache file that could not be written.
// The list is still used; only the next start has to download it again.
func warnCacheWrite(cacheDir string, err error) {
	hint := "the list is used, but the next start downloads it again. Check that s-hole can write to blocking.cache_dir"
	if errors.Is(err, fs.ErrPermission) {
		hint = "the list is used, but the next start downloads it again. The directory or its files belong to another user. " +
			"In Docker the image runs as user 65532 since s-hole 2.0: on the host, run sudo chown -R 65532:65532 on the directory that is mounted at /app"
	}
	logger.Warn("blocklist cache could not be written", "dir", cacheDir, "err", err, "hint", hint)
}

func loadFromFile(path string) ([]string, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	return parseHostsFormat(f)
}

// parseHostsFormat handles the hosts-file format ("0.0.0.0 domain.com"), the
// plain domain-per-line format, and wildcard lines ("*.domain.com", as in
// oisd's "domains (wildcards)" lists). A wildcard line means the domain and
// every subdomain, which is what the store's suffix walk already does for a
// plain entry, so "*." is dropped and the rest stored as a plain domain.
// Tokens that fail ValidDomain are silently dropped to keep one malformed
// list line from polluting the store; see R14. A "*.com" line fails it too
// (no interior dot), so a wildcard line cannot block a whole TLD. skipped
// counts the non-blank, non-comment lines that gave no domain, so Update can
// warn about a list in a format s-hole does not read.
func parseHostsFormat(r io.Reader) (domains []string, skipped int, err error) {
	scanner := bufio.NewScanner(r)
	// bufio.Scanner's default 64 KiB token cap would abort the whole list
	// with ErrTooLong on one overlong line (a mis-served binary, a
	// minified HTML error page) even when every other line is fine. Raise
	// the cap to 1 MiB; garbage lines are still dropped one at a time by
	// ValidDomain (T5).
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		n := len(domains)
		switch len(fields) {
		case 1:
			d := strings.TrimPrefix(fields[0], "*.")
			if ValidDomain(d) {
				domains = append(domains, d)
			}
		default:
			// hosts format: first field is IP, second is domain
			ip := fields[0]
			if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::" {
				domain := fields[1]
				if domain != "localhost" && domain != "0.0.0.0" && ValidDomain(domain) {
					domains = append(domains, domain)
				}
			}
		}
		if len(domains) == n {
			skipped++
		}
	}
	return domains, skipped, scanner.Err()
}

// ValidDomain rejects obvious garbage: empty strings, anything over
// the 253-character DNS name limit, names without a dot (we don't block
// bare TLDs), and names with characters that cannot legally appear in a
// DNS label (whitespace, control chars, slashes, etc.), empty labels, and
// labels that start or end with a hyphen. It is deliberately lenient
// otherwise: IDN punycode and underscore-prefixed service labels pass.
//
// Exported so the api package can validate user-supplied allowlist
// entries with the same rules the loader applies to blocklist files.
func ValidDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	// Require an interior dot. A bare label ("com") has none, and a bare
	// label with a trailing root dot ("com.") would pass a plain Contains
	// check, but normalize strips the dot and stores the bare label. A
	// allowlist typo like "com." would then exempt an entire TLD through the
	// CL 30 suffix walk (b/040). Leading dots (".com") are rejected too. A
	// real FQDN with a root dot ("example.com.") still has an interior dot
	// and stays valid.
	if i := strings.IndexByte(s, '.'); i <= 0 || i >= len(s)-1 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	// No empty label ("a..com") and no label that starts or ends with a
	// hyphen: DNS names cannot have either, so such a line is list junk, such
	// as the EasyList URL rule "-728.90.". The root dot of an FQDN leaves an
	// empty last label, which is allowed.
	name := strings.TrimSuffix(s, ".")
	prev := byte('.') // a label starts here
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c == '.' && (prev == '.' || prev == '-')) || (c == '-' && prev == '.') {
			return false
		}
		prev = c
	}
	return prev != '.' && prev != '-'
}

// PurgeCache deletes the downloaded blocklists in cacheDir: every
// blocklist_<hash>.txt file and any .tmp file a download left behind. It
// removes only files with that name pattern, never anything else in the
// directory. The block set in memory is untouched; the next reload downloads
// the lists again. It returns the number of files it removed.
func PurgeCache(cacheDir string) (int, error) {
	matches, err := filepath.Glob(filepath.Join(cacheDir, "blocklist_*.txt*"))
	if err != nil {
		return 0, err
	}
	removed := 0
	var firstErr error
	for _, m := range matches {
		base := filepath.Base(m)
		if !strings.HasSuffix(base, ".txt") && !strings.HasSuffix(base, ".txt.tmp") {
			continue
		}
		if err := os.Remove(m); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		removed++
	}
	return removed, firstErr
}

// redactURLError hides the secret parts of the URL inside an HTTP client
// error: *url.Error prints the full URL, query string included, and the
// error is logged and shown on the dashboard.
func redactURLError(err error) error {
	var ue *neturl.Error
	if errors.As(err, &ue) {
		cp := *ue
		cp.URL = redact.URL(ue.URL)
		return &cp
	}
	return err
}

// cacheFilename maps a URL to a stable, collision-free cache filename by
// hashing it. The old character-replacement scheme collapsed ".", "/", ":",
// "?", "&", and "=" all to "_", so two similar URLs could map to one file and
// clobber each other's cache, breaking the per-source stale fallback (b/050).
// A sha256 hex digest is injective in practice and filesystem-safe on every
// target OS (hex has no path separators, so the NTFS-rename concern is gone).
func cacheFilename(url string) string {
	sum := sha256.Sum256([]byte(url))
	return "blocklist_" + hex.EncodeToString(sum[:]) + ".txt"
}
