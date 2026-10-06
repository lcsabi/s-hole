package blocklist

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestPurgeCache_DeletesOnlyBlocklistFiles(t *testing.T) {
	// B1: PurgeCache deletes the files named blocklist_*.txt and
	// blocklist_*.txt.tmp in the directory, nothing else, and returns how many
	// it deleted.
	dir := t.TempDir()
	url := "https://lists.example/hosts.txt"
	remove := []string{
		cacheFilename(url),
		cacheFilename(url) + ".tmp",
		"blocklist_other.txt",
	}
	keep := []string{
		"config.yaml",
		"queries.db",
		"queries.log",
		"blocklist.txt",
		"myblocklist_a.txt",
		"blocklist_a.txt.bak",
		"blocklist_a.txt.tmp.1",
		"blocklist_a.TXT",
		"notes.txt",
		filepath.Join("sub", "blocklist_b.txt"),
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(append([]string{}, remove...), keep...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	n, err := PurgeCache(dir)
	if err != nil || n != len(remove) {
		t.Errorf("PurgeCache = (%d, %v), want (%d, nil)", n, err, len(remove))
	}
	for _, name := range remove {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s still exists", name)
		}
	}
	for _, name := range keep {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was deleted: %v", name, err)
		}
	}

	if n, err := PurgeCache(dir); n != 0 || err != nil {
		t.Errorf("second PurgeCache = (%d, %v), want (0, nil)", n, err)
	}
}

func TestPurgeCache_ReportsFailure(t *testing.T) {
	// A file that cannot be deleted is an error, and it is not counted.
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix directory permissions and a user other than root")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "blocklist_a.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	n, err := PurgeCache(dir)
	if err == nil || n != 0 {
		t.Errorf("PurgeCache on a read-only directory = (%d, %v), want (0, an error)", n, err)
	}
}

func listServer(t *testing.T, body string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var agents []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		agents = append(agents, r.Header.Get("User-Agent"))
		mu.Unlock()
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), agents...)
	}
}

func warnRecords(recs []map[string]any, msg string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["level"] == "WARN" && r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

func TestUpdate_CacheDirNotWritableStillUsesList(t *testing.T) {
	// B2: when the cache file cannot be created, the downloaded list is still
	// parsed and used, with a WARN. A permission error's hint names
	// chown -R 65532:65532.
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix directory permissions and a user other than root")
	}
	srv, _ := listServer(t, "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	records := captureLogs(t)
	store := NewStore()
	if err := Update(store, []string{srv.URL}, dir, DownloadFirst); err != nil {
		t.Fatalf("Update = %v, want nil: the download worked", err)
	}
	if store.Len() != 2 || !store.IsBlocked("ads.example.com") {
		t.Errorf("store has %d domains, want the 2 downloaded ones", store.Len())
	}
	warns := warnRecords(records(), "blocklist cache could not be written")
	if len(warns) != 1 {
		t.Fatalf("got %d cache WARN lines, want 1: %v", len(warns), records())
	}
	if hint, _ := warns[0]["hint"].(string); !strings.Contains(hint, "chown -R 65532:65532") {
		t.Errorf("hint = %q, want it to name chown -R 65532:65532", hint)
	}
	if src := sourceByURL(store)[srv.URL]; src.Stale || src.Count != 2 {
		t.Errorf("source status = %+v, want fresh with 2 domains", src)
	}
}

func TestUpdate_CacheDirCannotBeCreatedStillUsesList(t *testing.T) {
	// B2 and b/089: when the cache directory cannot be created (here, its
	// parent is a regular file), the downloaded list is still used, with the
	// "blocklist cache could not be written" WARN and a hint.
	srv, _ := listServer(t, "0.0.0.0 ads.example.com\n")
	parent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "cache")
	records := captureLogs(t)
	store := NewStore()
	if err := Update(store, []string{srv.URL}, dir, DownloadFirst); err != nil {
		t.Fatalf("Update = %v, want nil", err)
	}
	if !store.IsBlocked("ads.example.com") {
		t.Error("the downloaded list is not in use")
	}
	warns := warnRecords(records(), "blocklist cache could not be written")
	if len(warns) != 1 {
		t.Fatalf("got %d cache WARN lines, want 1", len(warns))
	}
	if hint, _ := warns[0]["hint"].(string); hint == "" {
		t.Error("the WARN has no hint")
	}
}

func TestUpdate_CacheRenameFailureStillUsesList(t *testing.T) {
	// B2: when the cache file cannot be renamed into place, the list is still
	// used, with a WARN, and the .tmp file is removed. A directory with the
	// cache file's name makes the rename fail.
	srv, _ := listServer(t, "0.0.0.0 ads.example.com\n")
	dir := t.TempDir()
	cachePath := filepath.Join(dir, cacheFilename(srv.URL))
	if err := os.MkdirAll(filepath.Join(cachePath, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	records := captureLogs(t)
	store := NewStore()
	if err := Update(store, []string{srv.URL}, dir, DownloadFirst); err != nil {
		t.Fatalf("Update = %v, want nil", err)
	}
	if !store.IsBlocked("ads.example.com") {
		t.Error("the downloaded list is not in use")
	}
	if n := len(warnRecords(records(), "blocklist cache could not be written")); n != 1 {
		t.Errorf("got %d cache WARN lines, want 1", n)
	}
	if _, err := os.Stat(cachePath + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("the .tmp file was left behind: %v", err)
	}
}

func TestFetchList_SendsFixedUserAgent(t *testing.T) {
	// B3: a download sends "User-Agent: s-hole".
	srv, agents := listServer(t, "0.0.0.0 ads.example.com\n")
	if err := Update(NewStore(), []string{srv.URL}, t.TempDir(), DownloadFirst); err != nil {
		t.Fatalf("Update = %v", err)
	}
	if got := agents(); len(got) != 1 || got[0] != "s-hole" {
		t.Errorf("User-Agent = %q, want [s-hole]", got)
	}
}

// withSecrets adds user info and a query string to an http URL.
func withSecrets(u string) string {
	return strings.Replace(u, "http://", "http://listuser:listpass@", 1) + "/hosts.txt?token=listtoken"
}

func assertNoSecrets(t *testing.T, where, text string) {
	t.Helper()
	for _, s := range []string{"listuser", "listpass", "listtoken"} {
		if strings.Contains(text, s) {
			t.Errorf("%s holds %q:\n%s", where, s, text)
		}
	}
}

func logText(t *testing.T, recs []map[string]any) string {
	t.Helper()
	b, err := json.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUpdate_LogsAndErrorsHideURLSecrets(t *testing.T) {
	// B3: the URLs in log lines and in returned errors are redacted (R1),
	// including the URL inside an HTTP client error.
	ok, _ := listServer(t, "0.0.0.0 ads.example.com\n")
	notFound := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(notFound.Close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + ln.Addr().String()
	ln.Close()

	cases := map[string]struct {
		url     string
		wantErr bool
	}{
		"download":          {withSecrets(ok.URL), false},
		"HTTP status":       {withSecrets(notFound.URL), true},
		"connection failed": {withSecrets(closed), true},
	}
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		tc := cases[name]
		t.Run(name, func(t *testing.T) {
			records := captureLogs(t)
			err := Update(NewStore(), []string{tc.url}, t.TempDir(), DownloadFirst)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Update = %v, want error %v", err, tc.wantErr)
			}
			if err != nil {
				assertNoSecrets(t, "the returned error", err.Error())
			}
			recs := records()
			if len(recs) == 0 {
				t.Fatal("no log lines")
			}
			assertNoSecrets(t, "the log", logText(t, recs))
			if !strings.Contains(logText(t, recs), "redacted") {
				t.Errorf("the log does not show the redacted URL:\n%s", logText(t, recs))
			}
		})
	}
}

func TestFetchList_StaleCacheWarningHidesURLSecrets(t *testing.T) {
	// B3: the stale-cache WARN after a failed download names the URL and the
	// error with their secrets hidden.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := withSecrets("http://" + ln.Addr().String())
	ln.Close()
	dir := t.TempDir()
	seedCache(t, dir, url, "0.0.0.0 cached.example.com\n", 0)
	records := captureLogs(t)
	store := NewStore()
	if err := Update(store, []string{url}, dir, DownloadFirst); err != nil {
		t.Fatalf("Update = %v, want the stale cache to serve", err)
	}
	if !store.IsBlocked("cached.example.com") {
		t.Error("the stale cache was not used")
	}
	recs := records()
	if len(warnRecords(recs, "download failed, using stale cache")) != 1 {
		t.Fatalf("no stale-cache WARN: %v", recs)
	}
	assertNoSecrets(t, "the log", logText(t, recs))
}

func TestFetchList_BadURLHidesUserInfo(t *testing.T) {
	// B3: a list URL that cannot be parsed still has its user info hidden in
	// the returned error and the log (R1 redacts everything before the last
	// "@" in the authority).
	//
	// POSSIBLE BUG: this test fails against the CL 93 code. fetchList
	// redacts the URL it quotes, but it wraps the http.NewRequest error, and
	// that url.Parse error repeats the raw URL with the user name and
	// password. Reported to the maintainer; do not weaken this test.
	url := "http://listuser:listpass@[::1/hosts.txt"
	records := captureLogs(t)
	err := Update(NewStore(), []string{url}, t.TempDir(), DownloadFirst)
	if err == nil {
		t.Fatal("Update with a malformed URL = nil error")
	}
	for _, s := range []string{"listuser", "listpass"} {
		if strings.Contains(err.Error(), s) {
			t.Errorf("POSSIBLE BUG (B3): the returned error holds %q: %v", s, err)
		}
		if strings.Contains(logText(t, records()), s) {
			t.Errorf("POSSIBLE BUG (B3): the log holds %q:\n%s", s, logText(t, records()))
		}
	}
}
