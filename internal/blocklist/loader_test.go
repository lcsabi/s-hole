package blocklist

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestFetchList_DownloadAndCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	domains, err := fetchList(srv.URL, dir)
	if err != nil {
		t.Fatalf("fetchList: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("got %d domains, want 2", len(domains))
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
	if _, err := fetchList(url, dir); err != nil {
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

	domains, err := fetchList(srv503.URL, dir)
	if err != nil {
		t.Fatalf("expected fallback to stale cache, got error: %v", err)
	}
	if len(domains) != 1 || domains[0] != "ads.example.com" {
		t.Errorf("stale cache not served: got %v", domains)
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

func TestUpdate_PreservesStoreOnFullFailure(t *testing.T) {
	// Regression for b/024: if every URL fails AND there is no usable
	// cache, Update must not call store.Replace(nil) — it must preserve
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

func TestValidDomain(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"a-b.example.com", true},
		{"_dmarc.example.com", true},
		{"", false},
		{"example", false}, // no dot — bare TLD
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
	domains, err := fetchList(srv.URL, dir)
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
