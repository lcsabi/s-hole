//go:build !windows

package blocklist

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// withUmask022 sets the usual umask for the test, so a mode check proves the
// code asked for 0700 and did not rely on a strict umask.
func withUmask022(t *testing.T) {
	t.Helper()
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
}

func TestUpdate_CreatesMissingCacheDir(t *testing.T) {
	// b/089: a blocking.cache_dir that does not exist, with missing parents,
	// is created owner-only (0700) and the cache file is written there, so
	// the next CacheFirst start loads the list from the cache without a
	// download.
	withUmask022(t)
	srv, hits := countingServer(t, "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n")
	base := t.TempDir()
	dir := filepath.Join(base, "a", "b", "cache")
	records := captureLogs(t)

	store := NewStore()
	if err := Update(store, []string{srv.URL}, dir, DownloadFirst); err != nil {
		t.Fatalf("Update = %v", err)
	}
	if store.Len() != 2 {
		t.Errorf("store has %d domains, want 2", store.Len())
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		t.Fatalf("cache_dir was not created: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("cache_dir mode = %o, want 700", got)
	}
	for _, p := range []string{filepath.Join(base, "a"), filepath.Join(base, "a", "b")} {
		if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
			t.Errorf("parent %s was not created: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, cacheFilename(srv.URL))); err != nil {
		t.Errorf("the cache file was not written: %v", err)
	}
	if n := len(warnRecords(records(), "blocklist cache could not be written")); n != 0 {
		t.Errorf("got %d cache WARN lines, want 0", n)
	}

	// The next start (CacheFirst) loads from the cache and downloads nothing.
	records = captureLogs(t)
	store2 := NewStore()
	if err := Update(store2, []string{srv.URL}, dir, CacheFirst); err != nil {
		t.Fatalf("second Update = %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("list server got %d requests, want 1 (the second start uses the cache)", hits.Load())
	}
	if got := loadedFrom(t, records())[srv.URL]; got != "cache" || store2.Len() != 2 {
		t.Errorf("second start: from = %q with %d domains, want cache with 2", got, store2.Len())
	}
}

func TestUpdate_KeepsExistingCacheDirMode(t *testing.T) {
	// b/089: an existing cache directory keeps its mode.
	withUmask022(t)
	for _, mode := range []os.FileMode{0o755, 0o750, 0o711} {
		srv, _ := countingServer(t, "0.0.0.0 ads.example.com\n")
		dir := filepath.Join(t.TempDir(), "cache")
		if err := os.Mkdir(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := Update(NewStore(), []string{srv.URL}, dir, DownloadFirst); err != nil {
			t.Fatalf("Update = %v", err)
		}
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != mode {
			t.Errorf("existing cache_dir mode changed from %o to %o", mode, got)
		}
		if _, err := os.Stat(filepath.Join(dir, cacheFilename(srv.URL))); err != nil {
			t.Errorf("mode %o: the cache file was not written: %v", mode, err)
		}
	}
}
