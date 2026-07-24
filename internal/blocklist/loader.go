package blocklist

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var logger = slog.With("pkg", "blocklist")

const cacheMaxAge = 24 * time.Hour

// httpClient has a generous timeout to handle slow mirrors; 256 MB cap prevents
// a runaway download from filling the disk.
var httpClient = &http.Client{Timeout: 60 * time.Second}

const maxBodyBytes = 256 << 20 // 256 MB

// Update downloads (or loads from cache) all lists and replaces the store.
// If every configured URL fails (network outage, all servers down), the
// existing block set is preserved rather than being replaced with an empty
// slice — otherwise a transient outage would silently unblock every ad until
// the next successful refresh.
func Update(store *Store, urls []string, cacheDir string) error {
	var all []string
	var ok int
	var lastErr error
	for _, u := range urls {
		domains, err := fetchList(u, cacheDir)
		if err != nil {
			lastErr = err
			logger.Warn("failed to load", "url", u, "err", err)
			continue
		}
		ok++
		all = append(all, domains...)
		logger.Info("loaded", "url", u, "domains", len(domains))
	}
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

// warnIfEmpty raises a loud alarm when the block set is empty after an
// update. An empty store means s-hole is answering queries but blocking
// nothing — typically a first run that could reach no blocklist URL (and had
// no disk cache to fall back on), or a source that returned 200 but parsed to
// zero valid domains. /readyz reports this as 503, but that signal is easy to
// miss on a headless box, so the state is surfaced here at WARN as well.
func warnIfEmpty(store *Store) {
	if store.Len() == 0 {
		logger.Warn("block set is EMPTY: s-hole is running but blocking no domains — " +
			"check the blocklist URLs and network connectivity")
	}
}

func fetchList(url, cacheDir string) ([]string, error) {
	cachePath := filepath.Join(cacheDir, cacheFilename(url))

	if info, err := os.Stat(cachePath); err == nil {
		if time.Since(info.ModTime()) < cacheMaxAge {
			return loadFromFile(cachePath)
		}
	}

	resp, err := httpClient.Get(url) //nolint:gosec // URL comes from operator config
	if err != nil {
		// Fall back to stale cache if download fails.
		if _, statErr := os.Stat(cachePath); statErr == nil {
			logger.Warn("download failed, using stale cache", "url", url, "err", err)
			return loadFromFile(cachePath)
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Do not write the error-page body to the cache file.
		if _, statErr := os.Stat(cachePath); statErr == nil {
			logger.Warn("non-200 response, using stale cache", "url", url, "status", resp.StatusCode)
			return loadFromFile(cachePath)
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Atomic write: stream to a sibling .tmp file, then os.Rename on success.
	// A connection drop or process kill mid-download leaves only the .tmp
	// behind; the previous cachePath stays usable (and its mtime stays old
	// so the next start re-attempts the download).
	tmpPath := cachePath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return nil, err
	}

	tee := io.TeeReader(io.LimitReader(resp.Body, maxBodyBytes), f)
	domains, parseErr := parseHostsFormat(tee)
	closeErr := f.Close()
	// The .tmp removals below are best-effort cleanup on paths that
	// already return an error; a leftover .tmp is harmless (ignored by
	// loads, overwritten by the next download).
	if parseErr != nil {
		_ = os.Remove(tmpPath)
		return nil, parseErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return nil, closeErr
	}
	if err := os.Rename(tmpPath, cachePath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	return domains, nil
}

func loadFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseHostsFormat(f)
}

// parseHostsFormat handles both hosts-file format ("0.0.0.0 domain.com")
// and plain domain-per-line format. Tokens that fail ValidDomain are
// silently dropped to keep one malformed list line from polluting the
// store — see R14.
func parseHostsFormat(r io.Reader) ([]string, error) {
	var domains []string
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
		switch len(fields) {
		case 1:
			if ValidDomain(fields[0]) {
				domains = append(domains, fields[0])
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
	}
	return domains, scanner.Err()
}

// ValidDomain rejects obvious garbage: empty strings, anything over
// the 253-character DNS name limit, names without a dot (we don't block
// bare TLDs), and names with characters that cannot legally appear in a
// DNS label (whitespace, control chars, slashes, etc.). It is deliberately
// lenient: IDN punycode and underscore-prefixed service labels pass.
//
// Exported so the api package can validate user-supplied whitelist
// entries with the same rules the loader applies to blocklist files.
func ValidDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if !strings.Contains(s, ".") {
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
	return true
}

// cacheFilename converts a URL to a safe filename.
//
// Colon escapes are important: a bare ":" in the URL (e.g. an embedded
// port like "127.0.0.1:8080") is a path-separator character on Windows
// and would make the file impossible to rename across NTFS streams.
func cacheFilename(url string) string {
	r := strings.NewReplacer(
		"://", "_",
		"/", "_",
		".", "_",
		"?", "_",
		"&", "_",
		"=", "_",
		":", "_",
	)
	return "blocklist_" + r.Replace(url) + ".txt"
}
