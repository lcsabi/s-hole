package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
)

func getRaw(t *testing.T, url string) (int, http.Header, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp.StatusCode, resp.Header, body
}

// hasKey reports whether key appears as an object key anywhere in v.
func hasKey(v any, key string) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, inner := range x {
			if k == key || hasKey(inner, key) {
				return true
			}
		}
	case []any:
		for _, inner := range x {
			if hasKey(inner, key) {
				return true
			}
		}
	}
	return false
}

func TestStats_PrivacyDefaults(t *testing.T) {
	// A6: without SetPrivacy and SetWarnings, /api/stats reports the defaults
	// and an empty warnings array (not null). It has no query_privacy field.
	_, srv := newTestServer(t, nil)
	_, _, body := getRaw(t, srv.URL+"/api/stats")
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"mode": "none", "clients": "drop", "database": false, "file": "off", "retention_days": float64(0)}
	got, _ := raw["privacy"].(map[string]any)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("privacy.%s = %v, want %v", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("privacy = %v, want exactly the keys %v", got, want)
	}
	if w, ok := raw["warnings"].([]any); !ok || len(w) != 0 {
		t.Errorf("warnings = %#v, want an empty array", raw["warnings"])
	}
	if hasKey(raw, "query_privacy") {
		t.Error("/api/stats has a query_privacy field")
	}
}

func TestStats_PrivacyAndWarningsEchoed(t *testing.T) {
	// A6: the settings from SetPrivacy and the list from SetWarnings reach
	// /api/stats; a nil list is still an empty array.
	s, srv := newTestServer(t, nil)
	s.SetPrivacy(PrivacyInfo{Mode: "all", Clients: "subnet", Database: true, File: "stdout", RetentionDays: 3})
	calls := 0
	s.SetWarnings(func() []string {
		calls++
		return []string{"query_log.mode: every query is recorded", "admin.pprof: on"}
	})
	_, _, body := getRaw(t, srv.URL+"/api/stats")
	var got struct {
		Privacy  PrivacyInfo `json:"privacy"`
		Warnings []string    `json:"warnings"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Privacy != (PrivacyInfo{Mode: "all", Clients: "subnet", Database: true, File: "stdout", RetentionDays: 3}) {
		t.Errorf("privacy = %+v", got.Privacy)
	}
	if len(got.Warnings) != 2 || got.Warnings[1] != "admin.pprof: on" {
		t.Errorf("warnings = %q, want the two from SetWarnings", got.Warnings)
	}
	// The list is read on each request, so a new warning shows at once.
	getRaw(t, srv.URL+"/api/stats")
	if calls != 2 {
		t.Errorf("warnings func called %d times for 2 requests, want 2", calls)
	}

	s.SetWarnings(func() []string { return nil })
	_, _, body = getRaw(t, srv.URL+"/api/stats")
	if !strings.Contains(string(body), `"warnings":[]`) {
		t.Errorf("body with nil warnings = %s, want \"warnings\":[]", body)
	}
}

// secretListSource loads one blocklist through a URL with user info and a
// query string, so the store's source status holds the secrets.
func secretListSource(t *testing.T) (*blocklist.Store, string) {
	t.Helper()
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0.0.0.0 ads.example.com\n"))
	}))
	t.Cleanup(list.Close)
	url := strings.Replace(list.URL, "http://", "http://apiuser:apipass@", 1) + "/hosts.txt?key=apikey"
	store := blocklist.NewStore()
	if err := blocklist.Update(store, []string{url}, t.TempDir(), blocklist.DownloadFirst); err != nil {
		t.Fatalf("Update: %v", err)
	}
	return store, url
}

func assertNoAPISecrets(t *testing.T, where string, body []byte) {
	t.Helper()
	for _, s := range []string{"apiuser", "apipass", "apikey"} {
		if strings.Contains(string(body), s) {
			t.Errorf("%s holds %q:\n%s", where, s, body)
		}
	}
}

func TestStatsAndMetrics_RedactSourceURLs(t *testing.T) {
	// A6 and A9: the source URLs in /api/stats and the url labels on
	// /metrics are redacted (R1).
	store, _ := secretListSource(t)
	s := New(stats.New(), nil, store, nil, func() bool { return true })
	s.SetUpstreamTransportFailures(func() map[string]uint64 {
		return map[string]uint64{"https://apiuser:apipass@9.9.9.9/dns-query?key=apikey": 4}
	})
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)

	_, _, body := getRaw(t, srv.URL+"/api/stats")
	assertNoAPISecrets(t, "/api/stats", body)
	if !strings.Contains(string(body), "redacted@") || !strings.Contains(string(body), "/hosts.txt?redacted") {
		t.Errorf("/api/stats does not show the redacted source URL:\n%s", body)
	}
	_, _, body = getRaw(t, srv.URL+"/metrics")
	assertNoAPISecrets(t, "/metrics", body)
	if !strings.Contains(string(body), `shole_upstream_transport_failures_total{upstream="https://redacted@9.9.9.9/dns-query?redacted"} 4`) {
		t.Errorf("/metrics lacks the redacted upstream label:\n%s", body)
	}
	if !strings.Contains(string(body), "shole_blocklist_source_size{url=\"http://redacted@") {
		t.Errorf("/metrics lacks the redacted source label:\n%s", body)
	}
}

type historyBody struct {
	Window  int64             `json:"window"`
	Bucket  int64             `json:"bucket"`
	Source  string            `json:"source"`
	Logging string            `json:"logging"`
	Series  []json.RawMessage `json:"series"`
}

func getHistory(t *testing.T, base, query string) historyBody {
	t.Helper()
	code, _, body := getRaw(t, base+"/api/history"+query)
	if code != http.StatusOK {
		t.Fatalf("GET /api/history%s = %d: %s", query, code, body)
	}
	var h historyBody
	if err := json.Unmarshal(body, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func historyServer(t *testing.T, mode string) (*Server, string) {
	t.Helper()
	var db *querylog.DBLogger
	if mode != "" {
		var err error
		db, err = querylog.NewDBLogger(filepath.Join(t.TempDir(), "q.db"), mode, 50*time.Millisecond, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
	}
	s := New(stats.New(), db, blocklist.NewStore(), nil, func() bool { return true })
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return s, srv.URL
}

func TestHistory_SourceAndLogging(t *testing.T) {
	// A7: up to 24h comes from the in-memory timeline (source memory, logging
	// all). A longer window comes from the database only when there is one
	// and its mode is not "none"; otherwise it is cut to 24h from memory.
	cases := []struct {
		name, db, query string
		source, logging string
		window, bucket  int64
	}{
		{"1h, no database", "", "?window=1h&bucket=1m", "memory", "all", 3600, 60},
		{"24h, no database", "", "?window=24h&bucket=1h", "memory", "all", 86400, 3600},
		{"24h, database all", "all", "?window=24h&bucket=1h", "memory", "all", 86400, 3600},
		{"default, database all", "all", "", "memory", "all", 86400, 3600},
		{"7d, no database", "", "?window=7d&bucket=1h", "memory", "all", 86400, 3600},
		{"48h, database none", "none", "?window=48h&bucket=1h", "memory", "all", 86400, 3600},
		{"48h bucket, no database", "", "?window=48h&bucket=48h", "memory", "all", 86400, 86400},
		{"48h, database all", "all", "?window=48h&bucket=1h", "database", "all", 172800, 3600},
		{"7d, database blocked", "blocked", "?window=7d&bucket=1h", "database", "blocked", 604800, 3600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, base := historyServer(t, tc.db)
			h := getHistory(t, base, tc.query)
			if h.Source != tc.source || h.Logging != tc.logging || h.Window != tc.window || h.Bucket != tc.bucket {
				t.Errorf("history = {source %q, logging %q, window %d, bucket %d}, want {%q, %q, %d, %d}",
					h.Source, h.Logging, h.Window, h.Bucket, tc.source, tc.logging, tc.window, tc.bucket)
			}
			if want := int(tc.window / tc.bucket); len(h.Series) != want {
				t.Errorf("series has %d buckets, want %d", len(h.Series), want)
			}
		})
	}
}

func TestHistory_MemorySeriesCountsEveryQuery(t *testing.T) {
	// A7: the memory series is the counter's timeline, so it shows queries
	// under every query_log setting, with no database at all.
	s, base := historyServer(t, "")
	for i := 0; i < 3; i++ {
		s.counter.RecordQuery("", "", i == 0)
	}
	s.counter.RecordCacheHit()
	code, _, body := getRaw(t, base+"/api/history?window=1h&bucket=1m")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	var h struct {
		Series []stats.TimelineBucket `json:"series"`
	}
	if err := json.Unmarshal(body, &h); err != nil {
		t.Fatal(err)
	}
	var total, blocked, cached int64
	for _, b := range h.Series {
		total, blocked, cached = total+b.Total, blocked+b.Blocked, cached+b.Cached
	}
	if total != 3 || blocked != 1 || cached != 1 {
		t.Errorf("series sums = {total %d, blocked %d, cached %d}, want {3, 1, 1}", total, blocked, cached)
	}
}

func TestExport_ReportsTheQueryLogSettings(t *testing.T) {
	// A8: the export carries X-Shole-Query-Log-Clients and
	// X-Shole-Query-Log-Mode, the JSON envelope has "clients" and "mode", and
	// the file name includes the clients setting.
	s, base := historyServer(t, "blocked")
	s.SetPrivacy(PrivacyInfo{Mode: "blocked", Clients: "full"})
	for _, format := range []string{"csv", "json"} {
		t.Run(format, func(t *testing.T) {
			code, hdr, body := getRaw(t, base+"/api/queries/export?format="+format)
			if code != http.StatusOK {
				t.Fatalf("status %d", code)
			}
			if hdr.Get("X-Shole-Query-Log-Clients") != "full" || hdr.Get("X-Shole-Query-Log-Mode") != "blocked" {
				t.Errorf("headers clients=%q mode=%q, want full and blocked",
					hdr.Get("X-Shole-Query-Log-Clients"), hdr.Get("X-Shole-Query-Log-Mode"))
			}
			cd := hdr.Get("Content-Disposition")
			if !strings.Contains(cd, "-full-") || !strings.HasSuffix(strings.TrimSuffix(cd, `"`), "."+format) {
				t.Errorf("Content-Disposition = %q, want the clients setting in the file name", cd)
			}
			if format == "json" {
				var env map[string]any
				if err := json.Unmarshal(body, &env); err != nil {
					t.Fatalf("envelope: %v", err)
				}
				if env["clients"] != "full" || env["mode"] != "blocked" {
					t.Errorf("envelope clients=%v mode=%v, want full and blocked", env["clients"], env["mode"])
				}
				if hasKey(env, "query_privacy") || hasKey(env, "log_queries") {
					t.Errorf("envelope has an old 1.x field: %v", env)
				}
			}
		})
	}
	// Without SetPrivacy the clients setting reads as "drop".
	_, base = historyServer(t, "all")
	_, hdr, _ := getRaw(t, base+"/api/queries/export")
	if hdr.Get("X-Shole-Query-Log-Clients") != "drop" || !strings.Contains(hdr.Get("Content-Disposition"), "-drop-") {
		t.Errorf("default export: clients header %q, disposition %q; want drop", hdr.Get("X-Shole-Query-Log-Clients"), hdr.Get("Content-Disposition"))
	}
}

func TestMetrics_NewCounters(t *testing.T) {
	// A9: shole_allowlist_size is always there. shole_refused_total,
	// shole_upstream_plaintext_fallback_total, and
	// shole_query_log_file_dropped_total are there only when their accessors
	// are wired, with the accessor's value.
	s, srv := newTestServer(t, nil)
	s.store.AddToAllowlist("a.example.com")
	s.store.AddToAllowlist("b.example.com")
	_, _, body := getRaw(t, srv.URL+"/metrics")
	if got := parseMetricValue(t, string(body), "shole_allowlist_size"); got != 2 {
		t.Errorf("shole_allowlist_size = %d, want 2", got)
	}
	for _, name := range []string{"shole_refused_total", "shole_upstream_plaintext_fallback_total", "shole_query_log_file_dropped_total"} {
		if strings.Contains(string(body), name) {
			t.Errorf("%s is on /metrics without its accessor", name)
		}
	}

	s.SetRefusedQueries(func() uint64 { return 11 })
	s.SetPlaintextFallbacks(func() uint64 { return 22 })
	s.SetFileLogDropped(func() uint64 { return 33 })
	srv2 := httptest.NewServer(s.handler())
	t.Cleanup(srv2.Close)
	_, _, body = getRaw(t, srv2.URL+"/metrics")
	for name, want := range map[string]int64{
		"shole_refused_total":                     11,
		"shole_upstream_plaintext_fallback_total": 22,
		"shole_query_log_file_dropped_total":      33,
	} {
		if got := parseMetricValue(t, string(body), name); got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
		if !strings.Contains(string(body), "# TYPE "+name+" counter") {
			t.Errorf("%s has no counter TYPE line", name)
		}
	}
}
