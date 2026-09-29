package blocklist

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseHostsFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "hosts format",
			input: "0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.net\n",
			want:  []string{"ads.example.com", "tracker.example.net"},
		},
		{
			name:  "plain domain format",
			input: "ads.example.com\ntracker.example.net\n",
			want:  []string{"ads.example.com", "tracker.example.net"},
		},
		{
			name:  "comments and blanks ignored",
			input: "# header\n\nads.example.com\n  # mid-list\n",
			want:  []string{"ads.example.com"},
		},
		{
			name:  "localhost and 0.0.0.0 self-entries dropped",
			input: "0.0.0.0 localhost\n0.0.0.0 0.0.0.0\n0.0.0.0 ads.example.com\n",
			want:  []string{"ads.example.com"},
		},
		{
			name:  "non-sinkhole IP rows ignored",
			input: "1.2.3.4 example.com\n0.0.0.0 ads.example.com\n",
			want:  []string{"ads.example.com"},
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseHostsFormat(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("parseHostsFormat: %v", err)
			}
			if !equalSlices(got, tc.want) {
				t.Errorf("parseHostsFormat = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseHostsFormat_LongLineDoesNotAbortList(t *testing.T) {
	// T5 regression: a single line past bufio.Scanner's default 64 KiB
	// token cap used to abort the entire list with ErrTooLong. The line
	// itself is garbage (dropped by ValidDomain); the surrounding valid
	// entries must survive.
	input := "ads.example.com\n" +
		strings.Repeat("x", 100*1024) + "\n" +
		"tracker.example.net\n"
	got, err := parseHostsFormat(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseHostsFormat: %v", err)
	}
	if !equalSlices(got, []string{"ads.example.com", "tracker.example.net"}) {
		t.Errorf("parseHostsFormat = %v, want the two valid domains", got)
	}
}

func TestFetchList_DownloadAndCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	domains, meta, err := fetchList(srv.URL, dir)
	if err != nil {
		t.Fatalf("fetchList: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("got %d domains, want 2", len(domains))
	}
	if meta.from == fromStaleCache {
		t.Error("fresh download reported stale")
	}
	if meta.snapshot.IsZero() {
		t.Error("fresh download has zero snapshot time")
	}

	// Cache file should now exist.
	want := filepath.Join(dir, cacheFilename(srv.URL))
	if _, err := os.Stat(want); err != nil {
		t.Errorf("cache file not created at %s: %v", want, err)
	}
}

func TestFetchList_Non200FallsBackToStaleCache(t *testing.T) {
	// Regression for b/007: a 503 response must not overwrite the cache
	// with an HTML error page; instead the stale cache should be served.
	dir := t.TempDir()

	// Pre-populate the cache with a valid list.
	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0.0.0.0 ads.example.com\n"))
	}))
	url := srvOK.URL
	if _, _, err := fetchList(url, dir); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	srvOK.Close()

	// Re-fetch from a server that returns 503 at the same URL path.
	// We need the URL to match cacheFilename, so we just write a stale-
	// looking mtime onto the cache and use a *different* URL that maps to
	// a new cache file. Simpler approach: serve 503 directly and expire
	// the original cache by overwriting its mtime to be older than 24h.
	// Easiest: just call fetchList against a brand-new 503 server with
	// the cache file pre-seeded under its filename.
	srv503 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "<html>down</html>", http.StatusServiceUnavailable)
	}))
	defer srv503.Close()

	// Seed the cache file under the 503 server's URL filename.
	cachePath := filepath.Join(dir, cacheFilename(srv503.URL))
	if err := os.WriteFile(cachePath, []byte("0.0.0.0 ads.example.com\n"), 0644); err != nil {
		t.Fatalf("seed cache file: %v", err)
	}
	// Make the cache stale so it must re-download.
	staleTime := mustOldTime(t)
	if err := os.Chtimes(cachePath, staleTime, staleTime); err != nil {
		t.Fatalf("backdate cache mtime: %v", err)
	}

	domains, meta, err := fetchList(srv503.URL, dir)
	if err != nil {
		t.Fatalf("expected fallback to stale cache, got error: %v", err)
	}
	if len(domains) != 1 || domains[0] != "ads.example.com" {
		t.Errorf("stale cache not served: got %v", domains)
	}
	// The fallback must be flagged stale and report the cached snapshot's
	// mtime (the backdated time), not "now".
	if meta.from != fromStaleCache {
		t.Error("stale-cache fallback not flagged stale")
	}
	if meta.snapshot.After(time.Now().Add(-time.Hour)) {
		t.Errorf("stale snapshot = %v, want the backdated cache mtime", meta.snapshot)
	}

	// Cache file must not have been overwritten with the 503 body.
	body, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if strings.Contains(string(body), "<html>") {
		t.Errorf("cache file was overwritten with error-page body: %q", string(body))
	}
}

func TestFetchList_TruncatedAtCapFallsBackToStale(t *testing.T) {
	// b/051: a body larger than the cap is truncated. It must not be renamed in
	// as a fresh cache. With a prior cache present, serve that (stale) and WARN,
	// mirroring the non-200 fallback.
	orig := maxBodyBytes
	maxBodyBytes = 32
	t.Cleanup(func() { maxBodyBytes = orig })

	dir := t.TempDir()
	// Body well over the 32-byte cap.
	big := "0.0.0.0 " + strings.Repeat("a", 100) + ".example.com\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(big))
	}))
	defer srv.Close()

	// Seed a stale cache file under this URL's filename.
	cachePath := filepath.Join(dir, cacheFilename(srv.URL))
	if err := os.WriteFile(cachePath, []byte("0.0.0.0 cached.example.com\n"), 0644); err != nil {
		t.Fatalf("seed cache file: %v", err)
	}
	staleTime := mustOldTime(t)
	if err := os.Chtimes(cachePath, staleTime, staleTime); err != nil {
		t.Fatalf("backdate cache mtime: %v", err)
	}

	domains, meta, err := fetchList(srv.URL, dir)
	if err != nil {
		t.Fatalf("expected stale-cache fallback, got error: %v", err)
	}
	if meta.from != fromStaleCache {
		t.Error("truncated fallback not flagged stale")
	}
	if len(domains) != 1 || domains[0] != "cached.example.com" {
		t.Errorf("stale cache not served: got %v", domains)
	}
	// The truncated body must not have overwritten the cache.
	body, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if strings.Contains(string(body), "aaaa") {
		t.Errorf("cache overwritten with truncated body: %q", string(body))
	}
}

func TestFetchList_TruncatedAtCapNoCacheErrors(t *testing.T) {
	// b/051: a body over the cap with no prior cache is a hard failure, not a
	// fresh cache of the truncated content.
	orig := maxBodyBytes
	maxBodyBytes = 32
	t.Cleanup(func() { maxBodyBytes = orig })

	dir := t.TempDir()
	big := "0.0.0.0 " + strings.Repeat("b", 100) + ".example.com\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(big))
	}))
	defer srv.Close()

	_, _, err := fetchList(srv.URL, dir)
	if err == nil {
		t.Error("expected error on over-cap body with no cache, got nil")
	}
	// The error names the failing URL, so a caller that logs only the error
	// still identifies the source (parity with the non-200 error path).
	if err != nil && !strings.Contains(err.Error(), srv.URL) {
		t.Errorf("error %q does not name the URL %q", err, srv.URL)
	}
	// No cache file should have been left behind.
	if _, err := os.Stat(filepath.Join(dir, cacheFilename(srv.URL))); err == nil {
		t.Error("truncated body was written to the cache file")
	}
}

func TestUpdate_PreservesStoreOnFullFailure(t *testing.T) {
	// Regression for b/024: if every URL fails AND there is no usable
	// cache, Update must not call store.Replace(nil); it must preserve
	// the existing block set.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	store := NewStore()
	store.Replace([]string{"old.example.com"})

	dir := t.TempDir()
	err := Update(store, []string{srv.URL}, dir)
	if err == nil {
		t.Fatal("Update with all-failing URLs must return an error")
	}
	if store.Len() != 1 {
		t.Errorf("store was wiped: Len=%d, want 1", store.Len())
	}
	if !store.IsBlocked("old.example.com") {
		t.Error("existing block entry lost after failed refresh")
	}
}

func TestUpdate_EmptyBlockSetWarns(t *testing.T) {
	// A reachable source that returns 200 but only comments parses to zero
	// domains. Update must NOT report an error (the source responded), but it
	// must raise the empty-block-set alarm so an operator notices s-hole is
	// running with nothing to block; otherwise the "blocklist updated
	// total=0" Info line would look like a normal refresh.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("# only comments, no domains\n\n"))
	}))
	defer srv.Close()

	var buf bytes.Buffer
	restore := swapLogger(&buf)
	defer restore()

	store := NewStore()
	if err := Update(store, []string{srv.URL}, t.TempDir()); err != nil {
		t.Fatalf("Update with an empty-but-reachable source returned error: %v", err)
	}
	if store.Len() != 0 {
		t.Fatalf("store should be empty, got Len=%d", store.Len())
	}
	if !strings.Contains(buf.String(), "block set is EMPTY") {
		t.Errorf("expected empty-block-set alarm in logs, got: %q", buf.String())
	}
}

func TestUpdate_NonEmptyBlockSetDoesNotWarn(t *testing.T) {
	// The alarm must stay silent on a normal refresh that loads domains,
	// otherwise it would train operators to ignore it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0.0.0.0 ads.example.com\n"))
	}))
	defer srv.Close()

	var buf bytes.Buffer
	restore := swapLogger(&buf)
	defer restore()

	store := NewStore()
	if err := Update(store, []string{srv.URL}, t.TempDir()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if strings.Contains(buf.String(), "block set is EMPTY") {
		t.Errorf("alarm fired on a non-empty refresh; logs: %q", buf.String())
	}
}

func TestUpdate_PartialSuccessReplaces(t *testing.T) {
	// One URL succeeds, another fails: Update should still call
	// store.Replace with whatever it loaded.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0.0.0.0 fresh.example.com\n"))
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	store := NewStore()
	store.Replace([]string{"old.example.com"})

	if err := Update(store, []string{ok.URL, bad.URL}, t.TempDir()); err != nil {
		t.Fatalf("Update partial success returned error: %v", err)
	}
	if store.IsBlocked("old.example.com") {
		t.Error("old domain should have been replaced")
	}
	if !store.IsBlocked("fresh.example.com") {
		t.Error("fresh domain missing after partial-success refresh")
	}
}

func TestUpdate_RecordsPerSourceStatus(t *testing.T) {
	// One healthy source contributes a pre-dedup count; one hard-failing
	// source (no cache to fall back to) is recorded as stale with a zero
	// LastRefresh. Sources() must report both.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Two lines, one a duplicate of a domain the other source would also
		// carry; Count is pre-dedup, so it counts both this source's lines.
		w.Write([]byte("0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n"))
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	badURL := bad.URL
	bad.Close() // force a hard connection failure with no cache

	store := NewStore()
	if err := Update(store, []string{ok.URL, badURL}, t.TempDir()); err != nil {
		t.Fatalf("Update: %v", err)
	}

	sources := store.Sources()
	if len(sources) != 2 {
		t.Fatalf("Sources() len = %d, want 2", len(sources))
	}

	byURL := map[string]SourceStatus{}
	for _, s := range sources {
		byURL[s.URL] = s
	}
	healthy, gotOK := byURL[ok.URL]
	if !gotOK {
		t.Fatalf("healthy source %q missing from Sources()", ok.URL)
	}
	if healthy.Count != 2 {
		t.Errorf("healthy Count = %d, want 2 (pre-dedup)", healthy.Count)
	}
	if healthy.Stale {
		t.Error("healthy source flagged stale")
	}
	if healthy.LastRefresh.IsZero() {
		t.Error("healthy source has zero LastRefresh")
	}

	failed, gotBad := byURL[badURL]
	if !gotBad {
		t.Fatalf("failed source %q missing from Sources()", badURL)
	}
	if failed.Count != 0 {
		t.Errorf("failed Count = %d, want 0", failed.Count)
	}
	if !failed.Stale {
		t.Error("failed source not flagged stale")
	}
	if !failed.LastRefresh.IsZero() {
		t.Errorf("failed source LastRefresh = %v, want zero (never loaded)", failed.LastRefresh)
	}
}

func TestStore_SourcesEmptyBeforeUpdate(t *testing.T) {
	s := NewStore()
	got := s.Sources()
	if got == nil {
		// b/049: must be an empty slice, not nil, so /api/stats emits [] not
		// null. len(nil) == 0, so the length check alone would not catch this.
		t.Fatal("Sources() before Update = nil, want empty slice")
	}
	if len(got) != 0 {
		t.Errorf("Sources() before Update = %v, want empty", got)
	}
}

func TestCacheFilename_Deterministic(t *testing.T) {
	a := cacheFilename("https://example.com/list.txt")
	b := cacheFilename("https://example.com/list.txt")
	if a != b {
		t.Errorf("cacheFilename not deterministic: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "blocklist_") {
		t.Errorf("cacheFilename = %q, want blocklist_ prefix", a)
	}
}

func TestCacheFilename_DistinctURLsDistinctFiles(t *testing.T) {
	// b/050: URLs differing only in characters the old scheme collapsed to "_"
	// (".", "/", ":", "?", "&", "=") must map to distinct cache files, or one
	// source clobbers another's cache and breaks the per-source stale fallback.
	urls := []string{
		"https://a.example.com/list.txt",
		"https://a-example.com/list.txt",
		"https://a.example.com/list?txt",
		"https://a.example.com:8080/list.txt",
		"https://a.example.com/list.txt?v=1",
		"https://a.example.com/list.txt?v=2",
	}
	seen := make(map[string]string, len(urls))
	for _, u := range urls {
		name := cacheFilename(u)
		if prev, ok := seen[name]; ok {
			t.Errorf("cache filename collision: %q and %q both map to %q", prev, u, name)
		}
		seen[name] = u
	}
}

func TestValidDomain(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"a-b.example.com", true},
		{"_dmarc.example.com", true},
		{"example.com.", true}, // FQDN with a root dot; normalize strips it
		{"", false},
		{"example", false}, // no dot, bare TLD
		{"com.", false},    // b/040: bare TLD with a trailing root dot
		{".", false},       // b/040: dot only
		{"a.", false},      // b/040: single label, trailing dot
		{".com", false},    // leading dot, no label before it
		{"has space.com", false},
		{"slash/path.com", false},
		{"control\x00char.com", false},
		{strings.Repeat("a", 250) + ".com", false}, // > 253 chars
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := ValidDomain(tc.in); got != tc.want {
				t.Errorf("ValidDomain(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestFetchList_AtomicRename(t *testing.T) {
	// R9: a successful download writes via .tmp + os.Rename. A naive
	// torn-write would leave the cache with a partial body and a fresh
	// mtime; the rename approach guarantees readers see either the old
	// content or the full new content.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0.0.0.0 fresh.example.com\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	domains, _, err := fetchList(srv.URL, dir)
	if err != nil {
		t.Fatalf("fetchList: %v", err)
	}
	if len(domains) != 1 || domains[0] != "fresh.example.com" {
		t.Errorf("domains = %v, want [fresh.example.com]", domains)
	}

	// No .tmp left over after a successful download.
	tmpPath := filepath.Join(dir, cacheFilename(srv.URL)+".tmp")
	if _, err := os.Stat(tmpPath); err == nil {
		t.Errorf(".tmp file leaked: %s", tmpPath)
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustOldTime(t *testing.T) (oldTime time.Time) {
	t.Helper()
	return time.Now().Add(-48 * time.Hour)
}

// swapLogger redirects the package logger to buf for the duration of a test
// and returns a restore func. Tests run sequentially within the package
// (none call t.Parallel), so mutating the package-level logger is safe.
func swapLogger(buf *bytes.Buffer) (restore func()) {
	prev := logger
	logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return func() { logger = prev }
}

// BenchmarkParseHostsFormat measures parse throughput over a blocklist the size
// of the real default lists. Parsing runs on startup and every refresh, so this
// guards against an accidental O(n^2) in the parse or validation path.
func BenchmarkParseHostsFormat(b *testing.B) {
	const lines = 100_000
	var sb strings.Builder
	for i := 0; i < lines; i++ {
		sb.WriteString("0.0.0.0 ad")
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString(".example.com\n")
	}
	data := sb.String()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseHostsFormat(strings.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

// captureLogs redirects the package logger to a JSON handler at INFO level
// (swapLogger filters at WARN, which hides the "loaded" line) and returns a
// func that parses every record written so far. Safe only because blocklist
// tests run sequentially.
func captureLogs(t *testing.T) (records func() []map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	prev := logger
	logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	t.Cleanup(func() { logger = prev })
	return func() []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("parse log line %q: %v", line, err)
			}
			out = append(out, rec)
		}
		return out
	}
}

// loadedFrom returns the "from" attribute of each "loaded" record, keyed by
// url. It fails the test if a url has more than one "loaded" line, or if a
// line lacks a string "from" or a numeric "domains".
func loadedFrom(t *testing.T, recs []map[string]any) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, r := range recs {
		if r["msg"] != "loaded" {
			continue
		}
		url, _ := r["url"].(string)
		from, ok := r["from"].(string)
		if !ok {
			t.Errorf("loaded line for %q has no string from attribute: %v", url, r)
		}
		if _, ok := r["domains"].(float64); !ok {
			t.Errorf("loaded line for %q has no numeric domains attribute: %v", url, r)
		}
		if _, dup := got[url]; dup {
			t.Errorf("more than one loaded line for %q", url)
		}
		got[url] = from
	}
	return got
}

// hasWarn reports whether recs hold a WARN record with message msg for url.
func hasWarn(recs []map[string]any, msg, url string) bool {
	for _, r := range recs {
		if r["level"] == "WARN" && r["msg"] == msg && r["url"] == url {
			return true
		}
	}
	return false
}

// seedCache writes body as the cache file for url and sets its mtime to
// now minus age.
func seedCache(t *testing.T, dir, url, body string, age time.Duration) {
	t.Helper()
	p := filepath.Join(dir, cacheFilename(url))
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	ts := time.Now().Add(-age)
	if err := os.Chtimes(p, ts, ts); err != nil {
		t.Fatalf("age cache: %v", err)
	}
}

func sourceByURL(store *Store) map[string]SourceStatus {
	m := map[string]SourceStatus{}
	for _, s := range store.Sources() {
		m[s.URL] = s
	}
	return m
}

func TestUpdate_LoadedFromDownload(t *testing.T) {
	// CL 88: a fetch with no cache logs from=download, writes the cache, and
	// is not stale.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n"))
	}))
	defer srv.Close()
	records := captureLogs(t)
	dir := t.TempDir()
	store := NewStore()
	if err := Update(store, []string{srv.URL}, dir); err != nil {
		t.Fatalf("Update: %v", err)
	}
	recs := records()
	if got := loadedFrom(t, recs)[srv.URL]; got != "download" {
		t.Errorf("from = %q, want download", got)
	}
	for _, r := range recs {
		if r["msg"] == "loaded" && r["domains"] != float64(2) {
			t.Errorf("domains = %v, want 2", r["domains"])
		}
	}
	if sourceByURL(store)[srv.URL].Stale {
		t.Error("fresh download flagged stale")
	}
	if _, err := os.Stat(filepath.Join(dir, cacheFilename(srv.URL))); err != nil {
		t.Errorf("download did not write the cache file: %v", err)
	}
}

func TestUpdate_LoadedFromFreshCacheMakesNoRequest(t *testing.T) {
	// CL 88: a cache file younger than 24 hours is served with from=cache and
	// no HTTP request. The 23-hour age sits just inside the window.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write([]byte("0.0.0.0 network.example.com\n"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	seedCache(t, dir, srv.URL, "0.0.0.0 cached.example.com\n", 23*time.Hour)
	records := captureLogs(t)
	store := NewStore()
	if err := Update(store, []string{srv.URL}, dir); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := loadedFrom(t, records())[srv.URL]; got != "cache" {
		t.Errorf("from = %q, want cache", got)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("fresh cache made %d HTTP requests, want 0", n)
	}
	if !store.IsBlocked("cached.example.com") || store.IsBlocked("network.example.com") {
		t.Error("list did not come from the cache file")
	}
	if sourceByURL(store)[srv.URL].Stale {
		t.Error("fresh cache load flagged stale")
	}
}

func TestUpdate_OldCacheRefetchedLogsDownload(t *testing.T) {
	// CL 88: an old cache does not decide the origin. If the fetch succeeds,
	// the list is a download, not a cache or stale_cache load.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0.0.0.0 network.example.com\n"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	seedCache(t, dir, srv.URL, "0.0.0.0 cached.example.com\n", 48*time.Hour)
	records := captureLogs(t)
	store := NewStore()
	if err := Update(store, []string{srv.URL}, dir); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := loadedFrom(t, records())[srv.URL]; got != "download" {
		t.Errorf("from = %q, want download", got)
	}
	if !store.IsBlocked("network.example.com") {
		t.Error("list did not come from the download")
	}
	if sourceByURL(store)[srv.URL].Stale {
		t.Error("successful refetch flagged stale")
	}
}

func TestUpdate_LoadedFromStaleCache(t *testing.T) {
	// CL 88: each kind of failed fetch with an old cache logs
	// from=stale_cache, keeps its fallback WARN, and marks the source stale.
	cases := []struct {
		name    string
		handler http.HandlerFunc
		closed  bool // close the server first to force a connection error
		lowCap  bool // lower maxBodyBytes so the body is over the cap
		warn    string
	}{
		{
			name:   "connection error",
			closed: true,
			warn:   "download failed, using stale cache",
		},
		{
			name: "non-200",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "down", http.StatusServiceUnavailable)
			},
			warn: "non-200 response, using stale cache",
		},
		{
			name: "over cap",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte("0.0.0.0 " + strings.Repeat("a", 100) + ".example.com\n"))
			},
			lowCap: true,
			warn:   "response truncated at cap, using stale cache",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.lowCap {
				orig := maxBodyBytes
				maxBodyBytes = 32
				t.Cleanup(func() { maxBodyBytes = orig })
			}
			h := tc.handler
			if h == nil {
				h = func(http.ResponseWriter, *http.Request) {}
			}
			srv := httptest.NewServer(h)
			url := srv.URL
			if tc.closed {
				srv.Close()
			} else {
				defer srv.Close()
			}
			dir := t.TempDir()
			seedCache(t, dir, url, "0.0.0.0 cached.example.com\n", 48*time.Hour)
			records := captureLogs(t)
			store := NewStore()
			if err := Update(store, []string{url}, dir); err != nil {
				t.Fatalf("Update: %v", err)
			}
			recs := records()
			if got := loadedFrom(t, recs)[url]; got != "stale_cache" {
				t.Errorf("from = %q, want stale_cache", got)
			}
			if !hasWarn(recs, tc.warn, url) {
				t.Errorf("missing WARN %q; logs: %v", tc.warn, recs)
			}
			if !store.IsBlocked("cached.example.com") {
				t.Error("list did not come from the old cache file")
			}
			if !sourceByURL(store)[url].Stale {
				t.Error("stale-cache fallback not flagged stale")
			}
		})
	}
}

func TestUpdate_MixedOriginsOneLoadedLinePerSource(t *testing.T) {
	// CL 88: in one Update, each source logs its own origin, a source that
	// fails with no cache logs no loaded line, and Stale agrees with from for
	// every loaded source.
	ok := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(body))
		}))
	}
	dl := ok("0.0.0.0 dl.example.com\n")
	defer dl.Close()
	cached := ok("0.0.0.0 unused.example.com\n")
	defer cached.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer down.Close()
	gone := ok("")
	goneURL := gone.URL
	gone.Close()

	dir := t.TempDir()
	seedCache(t, dir, cached.URL, "0.0.0.0 c.example.com\n", time.Hour)
	seedCache(t, dir, down.URL, "0.0.0.0 s.example.com\n", 48*time.Hour)
	records := captureLogs(t)
	store := NewStore()
	if err := Update(store, []string{dl.URL, cached.URL, down.URL, goneURL}, dir); err != nil {
		t.Fatalf("Update: %v", err)
	}
	recs := records()
	got := loadedFrom(t, recs)
	want := map[string]string{
		dl.URL:     "download",
		cached.URL: "cache",
		down.URL:   "stale_cache",
	}
	if len(got) != len(want) {
		t.Errorf("loaded lines = %v, want %v", got, want)
	}
	srcs := sourceByURL(store)
	for u, w := range want {
		if got[u] != w {
			t.Errorf("from for %q = %q, want %q", u, got[u], w)
		}
		if srcs[u].Stale != (w == "stale_cache") {
			t.Errorf("Stale for %q = %v, want %v", u, srcs[u].Stale, w == "stale_cache")
		}
	}
	if _, found := got[goneURL]; found {
		t.Error("failed source with no cache logged a loaded line")
	}
	if !hasWarn(recs, "failed to load", goneURL) {
		t.Error("failed source with no cache did not log failed to load")
	}
	for _, d := range []string{"dl.example.com", "c.example.com", "s.example.com"} {
		if !store.IsBlocked(d) {
			t.Errorf("%s missing: a failed source broke the others", d)
		}
	}
}
