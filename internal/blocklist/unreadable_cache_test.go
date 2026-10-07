package blocklist

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The b/092 tests: a fresh cache file that s-hole cannot read, and the
// ownership advice in the permission hints.

// Ownership advice that a permission hint must give (b/092): the fix after
// the Linux installer, and the fix for a Docker volume.
const (
	linuxOwnerAdvice  = "sudo chown -R s-hole:s-hole /var/lib/s-hole"
	dockerOwnerAdvice = "sudo chown -R 65532:65532"
)

const cacheReadWarn = "blocklist cache could not be read"

// needFilePermissions skips a test that needs a file mode to stop a read.
// Root reads a mode 0000 file anyway, and Windows ignores the Unix mode.
func needFilePermissions(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs Unix file permissions: Windows does not use the Unix mode to stop a read")
	}
	if os.Geteuid() == 0 {
		t.Skip("runs as root: root can read a mode 0000 file, so the cache cannot be made unreadable")
	}
}

// seedUnreadableCache writes body as a fresh cache file for url and makes it
// unreadable (mode 0000), as a root-owned 0600 file is to the s-hole user
// after a reinstall (b/092). The cleanup gives the owner access again.
func seedUnreadableCache(t *testing.T, dir, url, body string) string {
	t.Helper()
	seedCache(t, dir, url, body, time.Minute)
	p := filepath.Join(dir, cacheFilename(url))
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(p, 0o600) })
	if f, err := os.Open(p); err == nil {
		f.Close()
		t.Skip("the mode 0000 cache file can still be opened; this file system does not apply the mode")
	}
	return p
}

// countingServerStatus answers every request with status and counts the
// requests.
func countingServerStatus(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// closedURL returns an http URL on a port with no listener.
func closedURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := "http://" + ln.Addr().String()
	ln.Close()
	return u
}

func TestUpdate_UnreadableFreshCacheDownloadsInstead(t *testing.T) {
	// b/092: at startup (CacheFirst), a fresh cache file that cannot be read
	// does not fail the list. s-hole logs one WARN with a permission hint
	// that names both ownership fixes, downloads the list, uses it, and
	// replaces the cache file, so the next start loads from the cache.
	needFilePermissions(t)
	srv, hits := countingServer(t, "0.0.0.0 network.example.com\n0.0.0.0 tracker.example.net\n")
	dir := t.TempDir()
	cachePath := seedUnreadableCache(t, dir, srv.URL, "0.0.0.0 cached.example.com\n")
	records := captureLogs(t)
	start := time.Now()

	store := NewStore()
	if err := Update(store, []string{srv.URL}, dir, CacheFirst); err != nil {
		t.Fatalf("Update = %v, want nil: the download works", err)
	}
	recs := records()

	if n := hits.Load(); n != 1 {
		t.Errorf("list server got %d requests, want 1 (the download replaces the unreadable cache)", n)
	}
	if got := loadedFrom(t, recs)[srv.URL]; got != "download" {
		t.Errorf("from = %q, want download", got)
	}
	if !store.IsBlocked("network.example.com") || !store.IsBlocked("tracker.example.net") {
		t.Error("the downloaded domains are not in the block set")
	}
	if store.IsBlocked("cached.example.com") {
		t.Error("a domain from the unreadable cache file is in the block set")
	}
	src := sourceByURL(store)[srv.URL]
	if src.Stale || src.Count != 2 || src.LastRefresh.Before(start) {
		t.Errorf("source status = %+v, want fresh with 2 domains, refreshed now", src)
	}
	if n := len(warnRecords(recs, "blocklist load failed")); n != 0 {
		t.Errorf("got %d blocklist load failed lines, want 0", n)
	}

	warns := warnRecords(recs, cacheReadWarn)
	if len(warns) != 1 {
		t.Fatalf("got %d %q WARN lines, want 1: %v", len(warns), cacheReadWarn, recs)
	}
	w := warns[0]
	if w["url"] != srv.URL {
		t.Errorf("WARN url = %v, want %q", w["url"], srv.URL)
	}
	if e, _ := w["err"].(string); !strings.Contains(e, "permission denied") {
		t.Errorf("WARN err = %v, want the permission error", w["err"])
	}
	hint, _ := w["hint"].(string)
	if !strings.HasPrefix(hint, "s-hole downloads the list instead") {
		t.Errorf("hint = %q, want it to start with %q", hint, "s-hole downloads the list instead")
	}
	for _, advice := range []string{linuxOwnerAdvice, dockerOwnerAdvice} {
		if !strings.Contains(hint, advice) {
			t.Errorf("hint = %q, want it to contain %q", hint, advice)
		}
	}

	// The download replaced the cache file, although s-hole could not read
	// the old one.
	body, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("the cache file is still unreadable after the download: %v", err)
	}
	if !strings.Contains(string(body), "network.example.com") || strings.Contains(string(body), "cached.example.com") {
		t.Errorf("cache file = %q, want the downloaded list", body)
	}

	// The next start loads the new cache file with no request and no WARN.
	records = captureLogs(t)
	store2 := NewStore()
	if err := Update(store2, []string{srv.URL}, dir, CacheFirst); err != nil {
		t.Fatalf("second Update = %v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("list server got %d requests after the second start, want 1", n)
	}
	if got := loadedFrom(t, records())[srv.URL]; got != "cache" || !store2.IsBlocked("network.example.com") {
		t.Errorf("second start: from = %q, want cache with the downloaded list", got)
	}
	if n := len(warnRecords(records(), cacheReadWarn)); n != 0 {
		t.Errorf("second start: got %d %q WARN lines, want 0", n, cacheReadWarn)
	}
}

func TestUpdate_UnreadableCacheWarnHidesURLSecrets(t *testing.T) {
	// b/092 privacy: the new WARN names the list URL only through
	// redact.URL (no user name, password, or query string), and carries no
	// attribute other than the URL, the file error, and the hint.
	needFilePermissions(t)
	srv, _ := countingServer(t, "0.0.0.0 network.example.com\n")
	url := withSecrets(srv.URL)
	dir := t.TempDir()
	seedUnreadableCache(t, dir, url, "0.0.0.0 cached.example.com\n")
	records := captureLogs(t)

	store := NewStore()
	if err := Update(store, []string{url}, dir, CacheFirst); err != nil {
		t.Fatalf("Update = %v, want nil", err)
	}
	if !store.IsBlocked("network.example.com") {
		t.Error("the downloaded list is not in use")
	}
	recs := records()
	warns := warnRecords(recs, cacheReadWarn)
	if len(warns) != 1 {
		t.Fatalf("got %d %q WARN lines, want 1: %v", len(warns), cacheReadWarn, recs)
	}
	want := "http://redacted@" + strings.TrimPrefix(srv.URL, "http://") + "/hosts.txt?redacted"
	if warns[0]["url"] != want {
		t.Errorf("WARN url = %v, want %q", warns[0]["url"], want)
	}
	for key := range warns[0] {
		switch key {
		case "time", "level", "msg", "url", "err", "hint":
		default:
			t.Errorf("WARN has an unexpected attribute %q = %v", key, warns[0][key])
		}
	}
	assertNoSecrets(t, "the log", logText(t, recs))
}

func TestUpdate_UnreadableCacheAndFailedDownloadFailsList(t *testing.T) {
	// b/092: if the download fails after the cache could not be read, the
	// list fails as before ("blocklist load failed"), and no domain from it
	// reaches the block set. A second list that works is still used.
	needFilePermissions(t)
	good, _ := countingServer(t, "0.0.0.0 good.example.com\n")
	notFound, notFoundHits := countingServerStatus(t, 500)
	cases := map[string]string{
		"HTTP 500":          notFound.URL,
		"connection failed": closedURL(t),
	}
	for name, broken := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			seedUnreadableCache(t, dir, broken, "0.0.0.0 cached.example.com\n")
			records := captureLogs(t)

			store := NewStore()
			if err := Update(store, []string{broken, good.URL}, dir, CacheFirst); err != nil {
				t.Fatalf("Update = %v, want nil: one list works", err)
			}
			recs := records()
			if !hasWarn(recs, cacheReadWarn, broken) {
				t.Errorf("no %q WARN for the broken list: %v", cacheReadWarn, recs)
			}
			if !hasWarn(recs, "blocklist load failed", broken) {
				t.Errorf("no blocklist load failed WARN for the broken list: %v", recs)
			}
			if _, loaded := loadedFrom(t, recs)[broken]; loaded {
				t.Error("the broken list has a loaded line")
			}
			if store.IsBlocked("cached.example.com") {
				t.Error("a domain from the unreadable cache file is in the block set")
			}
			if !store.IsBlocked("good.example.com") || store.Len() != 1 {
				t.Errorf("store has %d domains, want only the working list's 1", store.Len())
			}
			if src := sourceByURL(store)[broken]; !src.Stale || src.Count != 0 || !src.LastRefresh.IsZero() {
				t.Errorf("broken source status = %+v, want failed (stale, no domains, never refreshed)", src)
			}
		})
	}
	if notFoundHits.Load() != 1 {
		t.Errorf("the HTTP 500 server got %d requests, want 1 (the download is tried)", notFoundHits.Load())
	}
}

func TestUpdate_UnreadableCacheOnlyListFailsKeepsBlockSet(t *testing.T) {
	// b/092: when the only list has an unreadable cache and its download
	// fails, Update reports the failure and keeps the existing block set.
	needFilePermissions(t)
	url := closedURL(t)
	dir := t.TempDir()
	seedUnreadableCache(t, dir, url, "0.0.0.0 cached.example.com\n")
	captureLogs(t)

	store := NewStore()
	store.Replace([]string{"old.example.com"})
	if err := Update(store, []string{url}, dir, CacheFirst); err == nil {
		t.Fatal("Update = nil, want an error: the only list failed")
	}
	if !store.IsBlocked("old.example.com") || store.IsBlocked("cached.example.com") || store.Len() != 1 {
		t.Errorf("store has %d domains, want only the existing old.example.com", store.Len())
	}
}

func TestUpdate_ReadableFreshCacheNoRequestNoWarn(t *testing.T) {
	// b/092 negative: a readable fresh cache file is still used at startup
	// with no HTTP request and no WARN of any kind.
	srv, hits := countingServer(t, "0.0.0.0 network.example.com\n")
	dir := t.TempDir()
	seedCache(t, dir, srv.URL, "0.0.0.0 cached.example.com\n", time.Minute)
	if err := os.Chmod(filepath.Join(dir, cacheFilename(srv.URL)), 0o600); err != nil {
		t.Fatal(err)
	}
	records := captureLogs(t)

	store := NewStore()
	if err := Update(store, []string{srv.URL}, dir, CacheFirst); err != nil {
		t.Fatalf("Update = %v", err)
	}
	recs := records()
	if n := hits.Load(); n != 0 {
		t.Errorf("list server got %d requests, want 0", n)
	}
	if got := loadedFrom(t, recs)[srv.URL]; got != "cache" {
		t.Errorf("from = %q, want cache", got)
	}
	if !store.IsBlocked("cached.example.com") || store.IsBlocked("network.example.com") {
		t.Error("the list did not come from the cache file")
	}
	for _, r := range recs {
		if r["level"] == "WARN" || r["level"] == "ERROR" {
			t.Errorf("unexpected %v line: %v", r["level"], r)
		}
	}
}

func TestUpdate_CacheReadErrorWithoutPermissionProblem(t *testing.T) {
	// b/092: a fresh cache that cannot be read for another reason (here, a
	// directory has the cache file's name) also falls back to the download.
	// The hint starts with "s-hole downloads the list instead" and gives no
	// ownership advice, because the error is not a permission error.
	srv, hits := countingServer(t, "0.0.0.0 network.example.com\n")
	dir := t.TempDir()
	cachePath := filepath.Join(dir, cacheFilename(srv.URL))
	if err := os.MkdirAll(filepath.Join(cachePath, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	records := captureLogs(t)

	store := NewStore()
	if err := Update(store, []string{srv.URL}, dir, CacheFirst); err != nil {
		t.Fatalf("Update = %v, want nil", err)
	}
	recs := records()
	if n := hits.Load(); n != 1 {
		t.Errorf("list server got %d requests, want 1", n)
	}
	if got := loadedFrom(t, recs)[srv.URL]; got != "download" || !store.IsBlocked("network.example.com") {
		t.Errorf("from = %q, want download with the downloaded list in use", got)
	}
	warns := warnRecords(recs, cacheReadWarn)
	if len(warns) != 1 {
		t.Fatalf("got %d %q WARN lines, want 1: %v", len(warns), cacheReadWarn, recs)
	}
	hint, _ := warns[0]["hint"].(string)
	if !strings.HasPrefix(hint, "s-hole downloads the list instead") {
		t.Errorf("hint = %q, want it to start with %q", hint, "s-hole downloads the list instead")
	}
	if strings.Contains(hint, "chown") {
		t.Errorf("hint = %q, want no ownership advice for an error that is not a permission error", hint)
	}
}

func TestUpdate_DownloadFirstUnreadableCacheUnchanged(t *testing.T) {
	// b/092: DownloadFirst (every reload) is unchanged. It downloads, uses
	// the list, and replaces the cache file without trying to read the
	// unreadable one, so it logs no "blocklist cache could not be read".
	needFilePermissions(t)
	srv, hits := countingServer(t, "0.0.0.0 network.example.com\n")
	dir := t.TempDir()
	cachePath := seedUnreadableCache(t, dir, srv.URL, "0.0.0.0 cached.example.com\n")
	records := captureLogs(t)

	store := NewStore()
	if err := Update(store, []string{srv.URL}, dir, DownloadFirst); err != nil {
		t.Fatalf("Update = %v", err)
	}
	recs := records()
	if n := hits.Load(); n != 1 {
		t.Errorf("list server got %d requests, want 1", n)
	}
	if got := loadedFrom(t, recs)[srv.URL]; got != "download" || !store.IsBlocked("network.example.com") {
		t.Errorf("from = %q, want download with the downloaded list in use", got)
	}
	if n := len(warnRecords(recs, cacheReadWarn)); n != 0 {
		t.Errorf("got %d %q WARN lines, want 0", n, cacheReadWarn)
	}
	if body, err := os.ReadFile(cachePath); err != nil || !strings.Contains(string(body), "network.example.com") {
		t.Errorf("the download did not replace the cache file: %q, %v", body, err)
	}
}

func TestUpdate_DownloadFirstUnreadableCacheFailedDownloadUnchanged(t *testing.T) {
	// b/092: under DownloadFirst, a failed download with an unreadable
	// cache fails the list, as before the fix, with no "blocklist cache
	// could not be read" WARN.
	needFilePermissions(t)
	url := closedURL(t)
	dir := t.TempDir()
	seedUnreadableCache(t, dir, url, "0.0.0.0 cached.example.com\n")
	records := captureLogs(t)

	store := NewStore()
	if err := Update(store, []string{url}, dir, DownloadFirst); err == nil {
		t.Fatal("Update = nil, want an error: the only list failed")
	}
	recs := records()
	if !hasWarn(recs, "blocklist load failed", url) {
		t.Errorf("no blocklist load failed WARN: %v", recs)
	}
	if n := len(warnRecords(recs, cacheReadWarn)); n != 0 {
		t.Errorf("got %d %q WARN lines, want 0", n, cacheReadWarn)
	}
	if store.IsBlocked("cached.example.com") {
		t.Error("a domain from the unreadable cache file is in the block set")
	}
}

func TestUpdate_UnreadableCacheInReadOnlyDirStillUsesDownload(t *testing.T) {
	// b/092: when the cache file cannot be read and the directory cannot be
	// written, the downloaded list is still used. Both WARNs give the
	// ownership advice; the cache file stays as it was.
	needFilePermissions(t)
	srv, _ := countingServer(t, "0.0.0.0 network.example.com\n")
	dir := t.TempDir()
	cachePath := seedUnreadableCache(t, dir, srv.URL, "0.0.0.0 cached.example.com\n")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	records := captureLogs(t)

	store := NewStore()
	if err := Update(store, []string{srv.URL}, dir, CacheFirst); err != nil {
		t.Fatalf("Update = %v, want nil", err)
	}
	recs := records()
	if got := loadedFrom(t, recs)[srv.URL]; got != "download" || !store.IsBlocked("network.example.com") {
		t.Errorf("from = %q, want download with the downloaded list in use", got)
	}
	for _, msg := range []string{cacheReadWarn, "blocklist cache could not be written"} {
		warns := warnRecords(recs, msg)
		if len(warns) != 1 {
			t.Errorf("got %d %q WARN lines, want 1", len(warns), msg)
			continue
		}
		hint, _ := warns[0]["hint"].(string)
		for _, advice := range []string{linuxOwnerAdvice, dockerOwnerAdvice} {
			if !strings.Contains(hint, advice) {
				t.Errorf("%q hint = %q, want it to contain %q", msg, hint, advice)
			}
		}
	}
	if fi, err := os.Stat(cachePath); err != nil || fi.Mode().Perm() != 0 {
		t.Errorf("the cache file changed in a read-only directory: %v, %v", fi, err)
	}
}

func TestWarnCacheWrite_PermissionHintNamesBothFixes(t *testing.T) {
	// b/092: the "blocklist cache could not be written" WARN for a
	// permission error names the fix after the Linux installer and the fix
	// for Docker.
	needFilePermissions(t)
	srv, _ := countingServer(t, "0.0.0.0 network.example.com\n")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	records := captureLogs(t)

	if err := Update(NewStore(), []string{srv.URL}, dir, DownloadFirst); err != nil {
		t.Fatalf("Update = %v, want nil", err)
	}
	warns := warnRecords(records(), "blocklist cache could not be written")
	if len(warns) != 1 {
		t.Fatalf("got %d cache WARN lines, want 1", len(warns))
	}
	hint, _ := warns[0]["hint"].(string)
	for _, advice := range []string{linuxOwnerAdvice, dockerOwnerAdvice} {
		if !strings.Contains(hint, advice) {
			t.Errorf("hint = %q, want it to contain %q", hint, advice)
		}
	}
}

func TestWarnCacheWrite_OtherErrorHasNoOwnershipAdvice(t *testing.T) {
	// b/092: a cache write error that is not a permission error (here, a
	// directory has the cache file's name, so the rename fails) keeps the
	// general hint and gives no ownership advice.
	srv, _ := countingServer(t, "0.0.0.0 network.example.com\n")
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, cacheFilename(srv.URL), "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	records := captureLogs(t)

	if err := Update(NewStore(), []string{srv.URL}, dir, DownloadFirst); err != nil {
		t.Fatalf("Update = %v, want nil", err)
	}
	warns := warnRecords(records(), "blocklist cache could not be written")
	if len(warns) != 1 {
		t.Fatalf("got %d cache WARN lines, want 1", len(warns))
	}
	hint, _ := warns[0]["hint"].(string)
	if !strings.Contains(hint, "blocking.cache_dir") || strings.Contains(hint, "chown") {
		t.Errorf("hint = %q, want the blocking.cache_dir advice and no chown", hint)
	}
}
