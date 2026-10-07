package blocklist

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The two WARN messages of the CL 95 unread-list check (W2).
const (
	msgNoDomains    = "blocklist has no domains"
	msgLinesSkipped = "blocklist lines skipped"
)

// adblockBody is the CL 95 example of a list in a format s-hole does not
// read. "##.banner" starts with "#", so it is a comment line; the other three
// lines are skipped. It gives read=0, skipped=3.
const adblockBody = "[Adblock Plus 2.0]\n! comment\n||ads.com^\n##.banner\n"

// goodBody is a normal hosts list: it reads two domains and skips nothing.
const goodBody = "# hosts\n0.0.0.0 good-a.example.com\n0.0.0.0 good-b.example.com\n"

// unreadWarns returns the CL 95 unread-list WARN records for url, in log
// order.
func unreadWarns(recs []map[string]any, url string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["level"] == "WARN" && (r["msg"] == msgNoDomains || r["msg"] == msgLinesSkipped) && r["url"] == url {
			out = append(out, r)
		}
	}
	return out
}

// allUnreadWarns returns every CL 95 unread-list WARN record, for any url.
func allUnreadWarns(recs []map[string]any) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["level"] == "WARN" && (r["msg"] == msgNoDomains || r["msg"] == msgLinesSkipped) {
			out = append(out, r)
		}
	}
	return out
}

// recordIndex returns the position of the first record with msg for url, or
// -1.
func recordIndex(recs []map[string]any, msg, url string) int {
	for i, r := range recs {
		if r["msg"] == msg && r["url"] == url {
			return i
		}
	}
	return -1
}

// wantUnreadWarn checks that recs hold exactly one unread-list WARN for url,
// with message msg, logged after the url's "loaded" line. For the skipped
// message it also checks the read and skipped counts. It returns the record.
func wantUnreadWarn(t *testing.T, recs []map[string]any, url, msg string, read, skipped int) map[string]any {
	t.Helper()
	warns := unreadWarns(recs, url)
	if len(warns) != 1 {
		t.Fatalf("got %d unread-list WARN lines for %s, want 1 (%q); logs: %v", len(warns), url, msg, recs)
	}
	w := warns[0]
	if w["msg"] != msg {
		t.Errorf("WARN msg = %q, want %q", w["msg"], msg)
	}
	if hint, _ := w["hint"].(string); hint == "" {
		t.Errorf("WARN has no hint: %v", w)
	}
	if msg == msgLinesSkipped {
		if w["read"] != float64(read) || w["skipped"] != float64(skipped) {
			t.Errorf("WARN read=%v skipped=%v, want read=%d skipped=%d", w["read"], w["skipped"], read, skipped)
		}
	}
	loaded := recordIndex(recs, "loaded", url)
	warn := recordIndex(recs, msg, url)
	if loaded < 0 {
		t.Errorf("no loaded line for %s", url)
	} else if warn < loaded {
		t.Errorf("WARN %q (record %d) comes before the loaded line (record %d)", msg, warn, loaded)
	}
	return w
}

func TestUpdate_EmptyListWarnsNoDomains(t *testing.T) {
	// CL 95 (W2): a list that loads but gives no domain and skips no line
	// gets "blocklist has no domains". Blank and comment lines do not count.
	for name, body := range map[string]string{
		"zero bytes":           "",
		"blank lines":          "\n\n   \n\t\n",
		"comments only":        "# Title: empty\n# Entries: 0\n",
		"comments and blanks":  "# a\n\n  # b\n\n##.banner\n",
		"CRLF comments blanks": "# a\r\n\r\n# b\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			srv, _ := listServer(t, body)
			records := captureLogs(t)
			store := NewStore()
			if err := Update(store, []string{srv.URL}, t.TempDir(), DownloadFirst); err != nil {
				t.Fatalf("Update: %v", err)
			}
			recs := records()
			w := wantUnreadWarn(t, recs, srv.URL, msgNoDomains, 0, 0)
			for _, k := range []string{"read", "skipped"} {
				if _, ok := w[k]; ok {
					t.Errorf("%q WARN has a %q field: %v", msgNoDomains, k, w)
				}
			}
		})
	}
}

func TestUpdate_AdblockListWarnsLinesSkipped(t *testing.T) {
	// CL 95 (W2): an Adblock list loads, but s-hole reads (almost) none of
	// it. More lines skipped than read gives "blocklist lines skipped" with
	// the two counts. "!" lines are not comments to s-hole; "#" lines are.
	cases := []struct {
		name          string
		body          string
		read, skipped int
	}{
		{"CL 95 example", adblockBody, 0, 3},
		{
			name: "EasyList shape with one stray match",
			body: "[Adblock Plus 2.0]\n" +
				"! Title: EasyList\n" +
				"! Expires: 4 days\n" +
				"! Homepage: https://easylist.to/\n" +
				"||ads.example.com^\n" +
				"||tracker.example.net^$third-party\n" +
				"-728.90.\n" + // dropped by the stricter domain check (W3)
				"/banner/ads.\n" +
				"##.ad-banner\n" +
				"example.com##.sidebar-ad\n" +
				"stray.example.org\n",
			read:    1,
			skipped: 9,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := listServer(t, tc.body)
			records := captureLogs(t)
			store := NewStore()
			if err := Update(store, []string{srv.URL}, t.TempDir(), DownloadFirst); err != nil {
				t.Fatalf("Update: %v", err)
			}
			wantUnreadWarn(t, records(), srv.URL, msgLinesSkipped, tc.read, tc.skipped)
		})
	}
}

func TestUpdate_UnreadListThreshold(t *testing.T) {
	// CL 95 (W2): the skipped WARN fires only when skipped > read. Equal
	// counts do not warn. read=0 with skipped>0 is the skipped WARN, not the
	// empty one.
	line := func(prefix string, n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, prefix, i)
		}
		return b.String()
	}
	cases := []struct {
		read, skipped int
		want          string // "" for no WARN
	}{
		{0, 0, msgNoDomains},
		{0, 1, msgLinesSkipped},
		{1, 0, ""},
		{1, 1, ""},
		{2, 2, ""},
		{2, 3, msgLinesSkipped},
		{3, 2, ""},
		{5, 6, msgLinesSkipped},
		{6, 5, ""},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("read=%d,skipped=%d", tc.read, tc.skipped), func(t *testing.T) {
			// Comments and blank lines between the entries must not move
			// the counts.
			body := "# header\n\n" +
				line("0.0.0.0 d%d.example.com\n# c\n\n", tc.read) +
				line("||junk%d.example.com^\n", tc.skipped)
			srv, _ := listServer(t, body)
			records := captureLogs(t)
			if err := Update(NewStore(), []string{srv.URL}, t.TempDir(), DownloadFirst); err != nil {
				t.Fatalf("Update: %v", err)
			}
			recs := records()
			if tc.want == "" {
				if w := unreadWarns(recs, srv.URL); len(w) != 0 {
					t.Errorf("unexpected unread-list WARN: %v", w)
				}
				return
			}
			wantUnreadWarn(t, recs, srv.URL, tc.want, tc.read, tc.skipped)
		})
	}
}

// stevenBlackHeader is the start of a common hosts list: loopback, broadcast,
// and IPv6 lines that s-hole skips, then the blocked domains.
const stevenBlackHeader = `# Title: StevenBlack/hosts
#
# This hosts file is a merged collection of hosts from reputable sources,

127.0.0.1 localhost
127.0.0.1 localhost.localdomain
127.0.0.1 local
255.255.255.255 broadcasthost
::1 localhost
::1 ip6-localhost
::1 ip6-loopback
fe80::1%lo0 localhost
ff00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
0.0.0.0 0.0.0.0

# Custom host records are listed here.
`

func TestUpdate_HostsListWithLocalhostLinesDoesNotWarn(t *testing.T) {
	// CL 95 (W2): a hosts list skips a few header lines (localhost,
	// broadcasthost, ::1), far fewer than it reads. It must not warn.
	var b strings.Builder
	b.WriteString(stevenBlackHeader)
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "0.0.0.0 ad%d.example.com\n", i)
	}
	srv, _ := listServer(t, b.String())
	records := captureLogs(t)
	store := NewStore()
	if err := Update(store, []string{srv.URL}, t.TempDir(), DownloadFirst); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if w := allUnreadWarns(records()); len(w) != 0 {
		t.Errorf("a normal hosts list warned: %v", w)
	}
	if !store.IsBlocked("ad39.example.com") {
		t.Error("the hosts list was not loaded")
	}
}

func TestUpdate_UnreadListWarnOnEveryLoadPath(t *testing.T) {
	// CL 95 (W2): the WARN covers each way a list loads without an error: a
	// download, a fresh cache under CacheFirst, and a stale cache after a
	// failed download (each kind of failure). The WARN reflects the data
	// that was served, not the other copy.
	lists := []struct {
		name          string
		body          string
		msg           string // "" for no WARN
		read, skipped int
	}{
		{"empty", "# nothing here\n\n", msgNoDomains, 0, 0},
		{"adblock", adblockBody, msgLinesSkipped, 0, 3},
		{"good", goodBody, "", 2, 0},
	}
	paths := []struct {
		name string
		from string
		mode Mode
		// setup returns the list URL and a hit counter. It serves body on
		// the download path. On the cache paths, the server serves
		// something else (or fails), and body goes into the cache file.
		setup func(t *testing.T, dir, body string) (string, *atomic.Int32)
	}{
		{
			name: "download",
			from: fromDownload,
			mode: CacheFirst,
			setup: func(t *testing.T, _ string, body string) (string, *atomic.Int32) {
				srv, hits := countingServer(t, body)
				return srv.URL, hits
			},
		},
		{
			name: "download over an old cache",
			from: fromDownload,
			mode: DownloadFirst,
			setup: func(t *testing.T, dir, body string) (string, *atomic.Int32) {
				srv, hits := countingServer(t, body)
				// The old cache holds the opposite case, so a WARN from the
				// cache file instead of the download fails the test.
				other := goodBody
				if body == goodBody {
					other = adblockBody
				}
				seedCache(t, dir, srv.URL, other, 48*time.Hour)
				return srv.URL, hits
			},
		},
		{
			name: "fresh cache",
			from: fromCache,
			mode: CacheFirst,
			setup: func(t *testing.T, dir, body string) (string, *atomic.Int32) {
				// The server serves a good list; if it were fetched, there
				// would be no WARN for the empty and adblock cases.
				srv, hits := countingServer(t, goodBody)
				seedCache(t, dir, srv.URL, body, time.Hour)
				return srv.URL, hits
			},
		},
		{
			name: "stale cache after connection error",
			from: fromStaleCache,
			mode: DownloadFirst,
			setup: func(t *testing.T, dir, body string) (string, *atomic.Int32) {
				srv := httptest.NewServer(http.NotFoundHandler())
				u := srv.URL
				srv.Close()
				seedCache(t, dir, u, body, 48*time.Hour)
				return u, nil
			},
		},
		{
			name: "stale cache after non-200",
			from: fromStaleCache,
			mode: CacheFirst,
			setup: func(t *testing.T, dir, body string) (string, *atomic.Int32) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					http.Error(w, "down", http.StatusServiceUnavailable)
				}))
				t.Cleanup(srv.Close)
				seedCache(t, dir, srv.URL, body, 48*time.Hour)
				return srv.URL, nil
			},
		},
		{
			name: "stale cache after a broken body",
			from: fromStaleCache,
			mode: DownloadFirst,
			setup: func(t *testing.T, dir, body string) (string, *atomic.Int32) {
				srv := midBodyResetServer(t)
				seedCache(t, dir, srv.URL, body, time.Minute)
				return srv.URL, nil
			},
		},
		{
			name: "stale cache after a body over the cap",
			from: fromStaleCache,
			mode: DownloadFirst,
			setup: func(t *testing.T, dir, body string) (string, *atomic.Int32) {
				orig := maxBodyBytes
				maxBodyBytes = 32
				t.Cleanup(func() { maxBodyBytes = orig })
				srv, _ := countingServer(t, "0.0.0.0 "+strings.Repeat("a", 100)+".example.com\n")
				seedCache(t, dir, srv.URL, body, time.Minute)
				return srv.URL, nil
			},
		},
	}
	for _, p := range paths {
		for _, l := range lists {
			t.Run(p.name+"/"+l.name, func(t *testing.T) {
				dir := t.TempDir()
				url, hits := p.setup(t, dir, l.body)
				records := captureLogs(t)
				store := NewStore()
				if err := Update(store, []string{url}, dir, p.mode); err != nil {
					t.Fatalf("Update: %v", err)
				}
				recs := records()
				if got := loadedFrom(t, recs)[url]; got != p.from {
					t.Fatalf("from = %q, want %q (test setup is wrong)", got, p.from)
				}
				if p.from == fromCache && hits.Load() != 0 {
					t.Fatalf("fresh cache made %d HTTP requests, want 0", hits.Load())
				}
				if l.msg == "" {
					if w := unreadWarns(recs, url); len(w) != 0 {
						t.Errorf("unexpected unread-list WARN: %v", w)
					}
				} else {
					wantUnreadWarn(t, recs, url, l.msg, l.read, l.skipped)
				}
				if src := sourceByURL(store)[url]; src.Count != l.read || src.LastRefresh.IsZero() {
					t.Errorf("source status = %+v, want Count %d and a refresh time", src, l.read)
				}
			})
		}
	}
}

func TestUpdate_FailedListGetsNoUnreadWarn(t *testing.T) {
	// CL 95 (W2): a list that fails to load gets only "blocklist load
	// failed", not an unread-list WARN, whether other lists load or not.
	notFound := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(notFound.Close)
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close()
	broken := midBodyResetServer(t)
	failed := []string{notFound.URL, goneURL, broken.URL}

	t.Run("with a working list", func(t *testing.T) {
		ok, _ := listServer(t, goodBody)
		records := captureLogs(t)
		store := NewStore()
		if err := Update(store, append([]string{ok.URL}, failed...), t.TempDir(), DownloadFirst); err != nil {
			t.Fatalf("Update: %v", err)
		}
		recs := records()
		for _, u := range failed {
			if !hasWarn(recs, "blocklist load failed", u) {
				t.Errorf("no load-failed WARN for %s", u)
			}
		}
		if w := allUnreadWarns(recs); len(w) != 0 {
			t.Errorf("unread-list WARN for a failed or a good list: %v", w)
		}
	})
	t.Run("all lists fail", func(t *testing.T) {
		records := captureLogs(t)
		if err := Update(NewStore(), failed, t.TempDir(), DownloadFirst); err == nil {
			t.Fatal("Update with only failing lists = nil error")
		}
		recs := records()
		if w := allUnreadWarns(recs); len(w) != 0 {
			t.Errorf("unread-list WARN for a failed list: %v", w)
		}
		if len(warnRecords(recs, "block set is empty")) != 1 {
			t.Errorf("want one block-set-empty WARN; logs: %v", recs)
		}
	})
}

func TestUpdate_WarnedListStillCountsAsLoaded(t *testing.T) {
	// CL 95 (W2): a warned list is still a loaded list. Its source status has
	// its Count and a refresh time, the other lists' domains are used, and
	// Update returns no error. Each list gets its own WARN (or none).
	adblock, _ := listServer(t, "[Adblock Plus 2.0]\n||ads.example.com^\n! x\nstray.example.org\n||t.example.net^\n")
	good, _ := listServer(t, goodBody)
	empty, _ := listServer(t, "# empty\n")
	records := captureLogs(t)
	store := NewStore()
	store.Replace([]string{"old.example.com"})
	if err := Update(store, []string{adblock.URL, good.URL, empty.URL}, t.TempDir(), DownloadFirst); err != nil {
		t.Fatalf("Update: %v", err)
	}
	recs := records()
	wantUnreadWarn(t, recs, adblock.URL, msgLinesSkipped, 1, 4)
	wantUnreadWarn(t, recs, empty.URL, msgNoDomains, 0, 0)
	if w := unreadWarns(recs, good.URL); len(w) != 0 {
		t.Errorf("the good list warned: %v", w)
	}
	srcs := sourceByURL(store)
	for u, want := range map[string]int{adblock.URL: 1, good.URL: 2, empty.URL: 0} {
		s, ok := srcs[u]
		if !ok {
			t.Errorf("no source status for %s", u)
			continue
		}
		if s.Count != want || s.Stale || s.LastRefresh.IsZero() {
			t.Errorf("source %s = %+v, want Count %d, fresh, with a refresh time", u, s, want)
		}
	}
	for _, d := range []string{"stray.example.org", "good-a.example.com", "good-b.example.com"} {
		if !store.IsBlocked(d) {
			t.Errorf("%s not blocked", d)
		}
	}
	if store.IsBlocked("old.example.com") {
		t.Error("the old block set was kept, so the warned lists were not treated as loaded")
	}
	if n := len(warnRecords(recs, "block set is empty")); n != 0 {
		t.Errorf("block-set-empty WARN on a non-empty set (%d lines)", n)
	}
}

func TestUpdate_UnreadListsAndEmptyBlockSet(t *testing.T) {
	// CL 95 (W2): when every list is unread, each list gets its own WARN, and
	// the existing "block set is empty" WARN still fires once, with its hint.
	for name, body := range map[string]string{"empty": "# none\n", "adblock": adblockBody} {
		t.Run(name, func(t *testing.T) {
			srv, _ := listServer(t, body)
			records := captureLogs(t)
			store := NewStore()
			if err := Update(store, []string{srv.URL}, t.TempDir(), DownloadFirst); err != nil {
				t.Fatalf("Update: %v", err)
			}
			recs := records()
			if len(unreadWarns(recs, srv.URL)) != 1 {
				t.Errorf("want one unread-list WARN; logs: %v", recs)
			}
			empty := warnRecords(recs, "block set is empty")
			if len(empty) != 1 {
				t.Fatalf("got %d block-set-empty WARN lines, want 1; logs: %v", len(empty), recs)
			}
			if hint, _ := empty[0]["hint"].(string); !strings.Contains(hint, "blocks no domains") {
				t.Errorf("block-set-empty hint = %q, want the existing hint", hint)
			}
		})
	}
}

func TestUpdate_UnreadListWarnHint(t *testing.T) {
	// CL 95 (W2): the hint names the formats s-hole reads (hosts lines, one
	// domain per line, *.example.com lines) and says to use the list's hosts
	// or domains version. Both WARNs carry it.
	empty, _ := listServer(t, "")
	adblock, _ := listServer(t, adblockBody)
	records := captureLogs(t)
	if err := Update(NewStore(), []string{empty.URL, adblock.URL}, t.TempDir(), DownloadFirst); err != nil {
		t.Fatalf("Update: %v", err)
	}
	warns := allUnreadWarns(records())
	if len(warns) != 2 {
		t.Fatalf("got %d unread-list WARN lines, want 2", len(warns))
	}
	for _, w := range warns {
		hint, _ := w["hint"].(string)
		lower := strings.ToLower(hint)
		for _, want := range []string{"hosts", "one domain per line", "*.example.com", "domains version"} {
			if !strings.Contains(lower, want) {
				t.Errorf("%q hint = %q, want it to name %q", w["msg"], hint, want)
			}
		}
	}
}

func TestUpdate_UnreadListWarnHidesURLSecrets(t *testing.T) {
	// CL 95 (W2) and B3: the url field of both WARNs is redacted: no user
	// name, password, or query string.
	empty, _ := listServer(t, "")
	adblock, _ := listServer(t, adblockBody)
	urls := []string{withSecrets(empty.URL), withSecrets(adblock.URL)}
	records := captureLogs(t)
	if err := Update(NewStore(), urls, t.TempDir(), DownloadFirst); err != nil {
		t.Fatalf("Update: %v", err)
	}
	recs := records()
	warns := allUnreadWarns(recs)
	if len(warns) != 2 {
		t.Fatalf("got %d unread-list WARN lines, want 2; logs: %v", len(warns), recs)
	}
	want := map[string]string{
		strings.Replace(empty.URL, "http://", "http://redacted@", 1) + "/hosts.txt?redacted":   msgNoDomains,
		strings.Replace(adblock.URL, "http://", "http://redacted@", 1) + "/hosts.txt?redacted": msgLinesSkipped,
	}
	for _, w := range warns {
		u, _ := w["url"].(string)
		if want[u] != w["msg"] {
			t.Errorf("WARN %q url = %q, want the redacted URL; want one of %v", w["msg"], u, want)
		}
	}
	assertNoSecrets(t, "the log", logText(t, recs))
}

func TestUpdate_UnreadListWarnCarriesNoListOrQueryData(t *testing.T) {
	// CL 95 (W2), privacy: the WARNs carry only the list URL, the two counts,
	// and the fixed hint. No field names a domain (from the list or a
	// query) or a client.
	body := "[Adblock Plus 2.0]\n! secret-comment\n||hidden-ad.example.com^\nleaked-domain.example.org\n||x.example^\n"
	srv, _ := listServer(t, body)
	empty, _ := listServer(t, "# secret-header\n")
	records := captureLogs(t)
	if err := Update(NewStore(), []string{srv.URL, empty.URL}, t.TempDir(), DownloadFirst); err != nil {
		t.Fatalf("Update: %v", err)
	}
	warns := allUnreadWarns(records())
	if len(warns) != 2 {
		t.Fatalf("got %d unread-list WARN lines, want 2", len(warns))
	}
	wantKeys := map[string][]string{
		msgNoDomains:    {"hint", "level", "msg", "time", "url"},
		msgLinesSkipped: {"hint", "level", "msg", "read", "skipped", "time", "url"},
	}
	for _, w := range warns {
		keys := make([]string, 0, len(w))
		for k := range w {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		msg, _ := w["msg"].(string)
		if !equalSlices(keys, wantKeys[msg]) {
			t.Errorf("%q fields = %v, want %v", msg, keys, wantKeys[msg])
		}
		text := logText(t, []map[string]any{w})
		for _, s := range []string{"hidden-ad", "leaked-domain", "secret-comment", "secret-header", "x.example^"} {
			if strings.Contains(text, s) {
				t.Errorf("%q WARN holds list content %q: %s", msg, s, text)
			}
		}
	}
}
