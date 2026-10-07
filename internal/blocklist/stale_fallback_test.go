package blocklist

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/redact"
)

// The b/095 tests: when a download fails, the stale-cache fallback reads the
// cached copy before it logs a "using stale cache" WARN. A copy that cannot
// be read fails the list instead.

// cachedList is the cached copy of the failing list. goodList is a second
// list that works; it stays under the 32-byte cap of the over-cap case.
const (
	cachedList = "0.0.0.0 cached.example.com\n"
	goodList   = "0.0.0.0 good.example.com\n"
)

// staleFallbackCase is one of the four ways a download can fail.
type staleFallbackCase struct {
	name   string
	lowCap bool                      // lower maxBodyBytes to 32 for the test
	start  func(t *testing.T) string // starts the failing source; returns its URL
	warn   string                    // the WARN for a readable copy
	attr   string                    // the WARN attribute that names the failure
	value  any                       // its value; nil means a string that holds dlText
	dlText string                    // text of the download failure in the error
	dlIs   func(error) bool          // nil, or a check that the error wraps the download error
}

func staleFallbackCases() []staleFallbackCase {
	big := "0.0.0.0 " + strings.Repeat("a", 100) + ".example.com\n"
	return []staleFallbackCase{
		{
			name:   "connection error",
			start:  closedURL,
			warn:   "download failed, using stale cache",
			attr:   "err",
			dlText: "dial tcp",
			dlIs: func(err error) bool {
				var ue *neturl.Error
				return errors.As(err, &ue)
			},
		},
		{
			name: "non-200",
			start: func(t *testing.T) string {
				srv, _ := countingServerStatus(t, http.StatusServiceUnavailable)
				return srv.URL
			},
			warn:   "non-200 response, using stale cache",
			attr:   "status",
			value:  float64(http.StatusServiceUnavailable),
			dlText: "HTTP 503",
		},
		{
			name:   "broken body",
			start:  func(t *testing.T) string { return midBodyResetServer(t).URL },
			warn:   "download failed, using stale cache",
			attr:   "err",
			dlText: "unexpected EOF",
			dlIs:   func(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) },
		},
		{
			name:   "over cap",
			lowCap: true,
			start: func(t *testing.T) string {
				srv, _ := countingServer(t, big)
				return srv.URL
			},
			warn:   "response truncated at cap, using stale cache",
			attr:   "cap_bytes",
			value:  float64(32),
			dlText: "response exceeded 32-byte cap",
		},
	}
}

// fallbackMode is a load mode and the age of the cached copy.
type fallbackMode struct {
	name          string
	mode          Mode
	age           time.Duration
	wantCacheRead bool // CacheFirst tries to read a fresh copy first (b/092)
}

var (
	// downloadModes reach the download with any copy.
	downloadModes = []fallbackMode{
		{name: "DownloadFirst", mode: DownloadFirst, age: 10 * time.Second},
		{name: "CacheFirst/old copy", mode: CacheFirst, age: 48 * time.Hour},
	}
	// CacheFirst with a fresh copy downloads only when the copy cannot be read.
	freshCacheFirst = fallbackMode{name: "CacheFirst/fresh copy", mode: CacheFirst, age: time.Minute, wantCacheRead: true}
)

// unusableCopy is a cached copy that loadFromFile cannot read to the end.
type unusableCopy struct {
	name     string
	seed     func(t *testing.T, dir, url string)
	readText string // text of the read failure in the error
	readIs   error  // the cause that errors.Is must find in the error
}

var unusableCopies = []unusableCopy{
	{
		// A root-owned copy after a reinstall (b/092).
		name: "mode 0000",
		seed: func(t *testing.T, dir, url string) {
			needFilePermissions(t)
			seedUnreadableCache(t, dir, url, cachedList)
		},
		readText: "permission denied",
		readIs:   fs.ErrPermission,
	},
	{
		// The read breaks after one valid line, so the copy gives a partial
		// list together with the error. This case needs no file mode, so it
		// also runs as root.
		name: "read breaks after a valid line",
		seed: func(t *testing.T, dir, url string) {
			seedCache(t, dir, url, cachedList+strings.Repeat("x", 2<<20)+"\n", time.Minute)
		},
		readText: "token too long",
		readIs:   bufio.ErrTooLong,
	},
}

// ageCopy sets the cached copy's mtime to now minus age and returns it.
// The owner can set the times of a mode 0000 file.
func ageCopy(t *testing.T, dir, url string, age time.Duration) time.Time {
	t.Helper()
	p := filepath.Join(dir, cacheFilename(url))
	ts := time.Now().Add(-age)
	if err := os.Chtimes(p, ts, ts); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.ModTime()
}

func lowerCap(t *testing.T) {
	t.Helper()
	orig := maxBodyBytes
	maxBodyBytes = 32
	t.Cleanup(func() { maxBodyBytes = orig })
}

// staleWarns returns every record, at any level, that says s-hole uses the
// stale cache.
func staleWarns(recs []map[string]any) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if msg, _ := r["msg"].(string); strings.Contains(msg, "using stale cache") {
			out = append(out, r)
		}
	}
	return out
}

// recordsFor returns the records with message msg for url.
func recordsFor(recs []map[string]any, msg, url string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["msg"] == msg && r["url"] == url {
			out = append(out, r)
		}
	}
	return out
}

// assertNoListDomains checks that text names no domain from the cached copy
// or the downloaded lists: a log line or an error carries no domain.
func assertNoListDomains(t *testing.T, where, text string) {
	t.Helper()
	for _, d := range []string{"cached.example.com", "good.example.com", "partial.example.com", "aaaa"} {
		if strings.Contains(text, d) {
			t.Errorf("%s names the list domain %q:\n%s", where, d, text)
		}
	}
}

func TestUpdate_StaleFallbackReadableCopy(t *testing.T) {
	// b/095 negative: with a readable copy, each of the four failed-download
	// paths is unchanged. It logs its WARN once, with the redacted URL and the
	// attribute that names the failure. The list comes from the copy, and the
	// source is stale with the copy's mtime as LastRefresh.
	for _, fc := range staleFallbackCases() {
		for _, m := range downloadModes {
			t.Run(fc.name+"/"+m.name, func(t *testing.T) {
				if fc.lowCap {
					lowerCap(t)
				}
				url := withSecrets(fc.start(t))
				shown := redact.URL(url)
				dir := t.TempDir()
				seedCache(t, dir, url, cachedList, m.age)
				mtime := ageCopy(t, dir, url, m.age)
				records := captureLogs(t)

				store := NewStore()
				if err := Update(store, []string{url}, dir, m.mode); err != nil {
					t.Fatalf("Update = %v, want nil: the copy serves the list", err)
				}
				recs := records()

				stale := staleWarns(recs)
				if len(stale) != 1 {
					t.Fatalf("got %d stale-cache records, want 1: %v", len(stale), recs)
				}
				w := stale[0]
				if w["level"] != "WARN" || w["msg"] != fc.warn || w["url"] != shown {
					t.Errorf("stale-cache record = %v, want WARN %q with url %q", w, fc.warn, shown)
				}
				if fc.value != nil {
					if w[fc.attr] != fc.value {
						t.Errorf("WARN %s = %v, want %v", fc.attr, w[fc.attr], fc.value)
					}
				} else if s, _ := w[fc.attr].(string); !strings.Contains(s, fc.dlText) {
					t.Errorf("WARN %s = %v, want the download failure (%q)", fc.attr, w[fc.attr], fc.dlText)
				}
				for key := range w {
					switch key {
					case "time", "level", "msg", "url", fc.attr:
					default:
						t.Errorf("WARN has an unexpected attribute %q = %v", key, w[key])
					}
				}
				if n := len(recordsFor(recs, "blocklist load failed", shown)); n != 0 {
					t.Errorf("got %d blocklist load failed lines, want 0", n)
				}
				if got := loadedFrom(t, recs)[shown]; got != "stale_cache" {
					t.Errorf("from = %q, want stale_cache", got)
				}
				if !store.IsBlocked("cached.example.com") || store.Len() != 1 {
					t.Errorf("store has %d domains, want only the copy's cached.example.com", store.Len())
				}
				src := sourceByURL(store)[url]
				if !src.Stale || src.Count != 1 || !src.LastRefresh.Equal(mtime) {
					t.Errorf("source status = %+v, want stale with 1 domain and LastRefresh %v", src, mtime)
				}
				assertNoSecrets(t, "the log", logText(t, recs))
				assertNoListDomains(t, "the log", logText(t, recs))
			})
		}
	}
}

func TestUpdate_StaleFallbackUnusableCopyFailsList(t *testing.T) {
	// b/095: when the download fails and the cached copy cannot be read, no
	// "using stale cache" WARN appears. The list fails: one "blocklist load
	// failed" line, none of the copy's domains, and an error that wraps both
	// the download failure and the read failure. A second list still loads;
	// when the failing list is the only one, the existing block set is kept.
	// With CacheFirst and a fresh copy, the b/092 "blocklist cache could not
	// be read" WARN comes first, and then the same rule applies.
	modes := append(append([]fallbackMode(nil), downloadModes...), freshCacheFirst)
	for _, fc := range staleFallbackCases() {
		for _, uc := range unusableCopies {
			for _, m := range modes {
				t.Run(fc.name+"/"+uc.name+"/"+m.name, func(t *testing.T) {
					if fc.lowCap {
						lowerCap(t)
					}
					url := withSecrets(fc.start(t))
					shown := redact.URL(url)
					good, _ := countingServer(t, goodList)
					dir := t.TempDir()
					uc.seed(t, dir, url)
					ageCopy(t, dir, url, m.age)

					// A second list works: Update succeeds without the failing list.
					records := captureLogs(t)
					store := NewStore()
					if err := Update(store, []string{url, good.URL}, dir, m.mode); err != nil {
						t.Fatalf("Update = %v, want nil: one list works", err)
					}
					recs := records()
					if stale := staleWarns(recs); len(stale) != 0 {
						t.Errorf("got stale-cache records for a copy that cannot be read: %v", stale)
					}
					failed := recordsFor(recs, "blocklist load failed", shown)
					if len(failed) != 1 {
						t.Fatalf("got %d blocklist load failed lines for the failing list, want 1: %v", len(failed), recs)
					}
					e, _ := failed[0]["err"].(string)
					if !strings.Contains(e, fc.dlText) || !strings.Contains(e, uc.readText) {
						t.Errorf("load failed err = %q, want the download failure (%q) and the read failure (%q)", e, fc.dlText, uc.readText)
					}
					cacheRead := recordsFor(recs, cacheReadWarn, shown)
					switch {
					case !m.wantCacheRead && len(cacheRead) != 0:
						t.Errorf("got %d %q lines, want 0: no read was tried before the download", len(cacheRead), cacheReadWarn)
					case m.wantCacheRead && len(cacheRead) != 1:
						t.Errorf("got %d %q lines, want 1 (b/092)", len(cacheRead), cacheReadWarn)
					}
					if _, loaded := loadedFrom(t, recs)[shown]; loaded {
						t.Error("the failing list has a loaded line")
					}
					if !store.IsBlocked("good.example.com") || store.Len() != 1 {
						t.Errorf("store has %d domains, want only the working list's good.example.com", store.Len())
					}
					if store.IsBlocked("cached.example.com") {
						t.Error("a domain from the copy that cannot be read is in the block set")
					}
					if src := sourceByURL(store)[url]; !src.Stale || src.Count != 0 || !src.LastRefresh.IsZero() {
						t.Errorf("failing source status = %+v, want failed (stale, no domains, never refreshed)", src)
					}
					assertNoSecrets(t, "the log", logText(t, recs))
					assertNoListDomains(t, "the log", logText(t, recs))

					// The failing list is the only one: Update fails, keeps the
					// existing block set, and its error wraps both failures.
					records = captureLogs(t)
					store = NewStore()
					store.Replace([]string{"old.example.com"})
					err := Update(store, []string{url}, dir, m.mode)
					if err == nil {
						t.Fatal("Update = nil, want an error: the only list failed")
					}
					recs = records()
					if stale := staleWarns(recs); len(stale) != 0 {
						t.Errorf("got stale-cache records for a copy that cannot be read: %v", stale)
					}
					if n := len(recordsFor(recs, "blocklist load failed", shown)); n != 1 {
						t.Errorf("got %d blocklist load failed lines, want 1", n)
					}
					if !errors.Is(err, uc.readIs) {
						t.Errorf("errors.Is(err, %v) = false, want the read failure wrapped: %v", uc.readIs, err)
					}
					if fc.dlIs != nil && !fc.dlIs(err) {
						t.Errorf("the error does not wrap the download failure: %v", err)
					}
					if !strings.Contains(err.Error(), fc.dlText) || !strings.Contains(err.Error(), uc.readText) {
						t.Errorf("err = %q, want the download failure (%q) and the read failure (%q)", err, fc.dlText, uc.readText)
					}
					if !store.IsBlocked("old.example.com") || store.Len() != 1 {
						t.Errorf("store has %d domains, want only the existing old.example.com", store.Len())
					}
					assertNoSecrets(t, "the returned error", err.Error())
					assertNoListDomains(t, "the returned error", err.Error())
					assertNoSecrets(t, "the log", logText(t, recs))
				})
			}
		}
	}
}

func TestUpdate_StaleFallbackCacheFirstReadWarnComesFirst(t *testing.T) {
	// b/095 with b/092: at startup (CacheFirst) with a fresh copy that cannot
	// be read, s-hole logs "blocklist cache could not be read" before it
	// downloads. When the download then fails, the list fails after that
	// WARN, and no line says that s-hole uses the stale cache.
	needFilePermissions(t)
	srv, hits := countingServerStatus(t, http.StatusServiceUnavailable)
	dir := t.TempDir()
	seedUnreadableCache(t, dir, srv.URL, cachedList)
	records := captureLogs(t)

	store := NewStore()
	store.Replace([]string{"old.example.com"})
	if err := Update(store, []string{srv.URL}, dir, CacheFirst); err == nil {
		t.Fatal("Update = nil, want an error: the only list failed")
	}
	recs := records()
	if n := hits.Load(); n != 1 {
		t.Errorf("list server got %d requests, want 1 (the download is tried)", n)
	}
	var order []string
	for _, r := range recs {
		msg, _ := r["msg"].(string)
		switch {
		case msg == cacheReadWarn, msg == "blocklist load failed", strings.Contains(msg, "using stale cache"):
			order = append(order, msg)
		}
	}
	want := []string{cacheReadWarn, "blocklist load failed"}
	if !equalSlices(order, want) {
		t.Errorf("log order = %q, want %q", order, want)
	}
	if !store.IsBlocked("old.example.com") || store.Len() != 1 {
		t.Errorf("store has %d domains, want only the existing old.example.com", store.Len())
	}
}
