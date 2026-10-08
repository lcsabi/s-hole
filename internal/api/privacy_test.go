package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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

// requestFrom sends one request to h from remote and returns the status.
func requestFrom(h http.Handler, method, target, remote, contentType, body string) int {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.RemoteAddr = remote
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// jsonRecords is a race-safe JSON log sink for the package logger, so a test
// can check every attribute of a record.
type jsonRecords struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *jsonRecords) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.Write(p)
}

func (j *jsonRecords) records(t *testing.T) []map[string]any {
	t.Helper()
	j.mu.Lock()
	text := j.buf.String()
	j.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if line == "" {
			continue
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

func (j *jsonRecords) withMsg(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range j.records(t) {
		if r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

// captureJSONLogs swaps the package logger for a JSON handler and restores
// it when the test ends. Tests here do not run in parallel, so the swap of
// the package global is safe.
func captureJSONLogs(t *testing.T) *jsonRecords {
	t.Helper()
	j := &jsonRecords{}
	old := logger
	logger = slog.New(slog.NewJSONHandler(j, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { logger = old })
	return j
}

// ipInText matches an IPv4 address or an IPv6 address with at least two
// colons in a log value.
var ipInText = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b|[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F:]*`)

// assertNoAddressIn fails when an attribute of r other than time holds an IP
// address or one of the extra parts.
func assertNoAddressIn(t *testing.T, r map[string]any, extra ...string) {
	t.Helper()
	for k, v := range r {
		if k == "time" {
			continue
		}
		s := fmt.Sprint(v)
		if ipInText.MatchString(s) {
			t.Errorf("attribute %s = %q holds an IP address (record %v)", k, s, r)
		}
		for _, e := range extra {
			if strings.Contains(s, e) {
				t.Errorf("attribute %s = %q holds %q (record %v)", k, s, e, r)
			}
		}
	}
}

// goneClientWriter is an http.ResponseWriter whose client disconnects after
// ok successful writes: every later write fails with the *net.OpError a
// reset connection gives, whose text holds both socket addresses.
type goneClientWriter struct {
	header http.Header
	ok     int
	writes int
}

func (w *goneClientWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *goneClientWriter) WriteHeader(int) {}

func (w *goneClientWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > w.ok {
		return 0, &net.OpError{
			Op:     "write",
			Net:    "tcp",
			Source: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 35987},
			Addr:   &net.TCPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 57082},
			Err:    errors.New("write: connection reset by peer"),
		}
	}
	return len(p), nil
}

func TestExport_ClientGoneLogsNoAddress(t *testing.T) {
	// PRIV-04 (b/099): an export that the client interrupts logs a WARN that
	// holds no IP address and no port in any attribute: not the socket
	// addresses of the write error, and not a client address from the rows.
	// The JSON export writes the envelope head (write 1), the rows with commas
	// (writes 2 to 8), and the closing "]}" (write 9); the CSV export buffers
	// the rows and fails when it flushes.
	cases := []struct {
		format string
		ok     int
	}{
		{"csv", 0},
		{"json", 0}, // the envelope head
		{"json", 3}, // a row
		{"json", 8}, // the closing "]}"
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/fails after %d writes", tc.format, tc.ok), func(t *testing.T) {
			s, _, _ := exportTestDB(t)
			s.SetPrivacy(PrivacyInfo{Mode: "all", Clients: "full"})
			logs := captureJSONLogs(t)
			req := httptest.NewRequest(http.MethodGet, "/api/queries/export?format="+tc.format, nil)
			req.Host = "127.0.0.1:8080"
			req.RemoteAddr = "192.168.1.20:57082"
			w := &goneClientWriter{ok: tc.ok}
			s.handler().ServeHTTP(w, req)
			if w.writes <= tc.ok {
				t.Fatalf("the export made %d writes, want more than %d", w.writes, tc.ok)
			}

			var warns []map[string]any
			for _, r := range logs.records(t) {
				if r["level"] == "WARN" && strings.HasPrefix(fmt.Sprint(r["msg"]), "query export") {
					warns = append(warns, r)
				}
				assertNoAddressIn(t, r, "35987", "57082")
			}
			if len(warns) == 0 {
				t.Fatalf("no query export WARN; log: %v", logs.records(t))
			}
			if e := fmt.Sprint(warns[0]["err"]); !strings.Contains(e, "connection reset by peer") {
				t.Errorf("err = %q, want the underlying error", e)
			}
		})
	}
}

func TestWriteJSON_ClientGoneLogsNoAddress(t *testing.T) {
	// PRIV-04 (b/099): a JSON response that cannot be written logs a WARN
	// with the underlying error and no IP address or port.
	s, _ := newTestServer(t, nil)
	logs := captureJSONLogs(t)
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req.Host = "127.0.0.1:8080"
	req.RemoteAddr = "192.168.1.20:57082"
	s.handler().ServeHTTP(&goneClientWriter{}, req)
	warns := logs.withMsg(t, "JSON response write failed")
	if len(warns) != 1 || warns[0]["level"] != "WARN" {
		t.Fatalf("records = %v, want one WARN \"JSON response write failed\"", logs.records(t))
	}
	if e := fmt.Sprint(warns[0]["err"]); !strings.Contains(e, "connection reset by peer") {
		t.Errorf("err = %q, want the underlying error", e)
	}
	for _, r := range logs.records(t) {
		assertNoAddressIn(t, r, "35987", "57082")
	}
}

func TestHistory_MemoryFollowsQueryLogMode(t *testing.T) {
	// PRIV-09: a window up to 24 hours comes from memory. Its logging field
	// is the mode the counter follows, and the series follows it: all zeros
	// under "none" (also when the mode is never set or unknown), blocked
	// queries only under "blocked", every query under "all".
	cases := []struct {
		name, mode string
		set        bool
		logging    string
		want       stats.TimelineBucket
	}{
		{"unset", "", false, "none", stats.TimelineBucket{}},
		{"none", "none", true, "none", stats.TimelineBucket{}},
		{"unknown", "verbose", true, "none", stats.TimelineBucket{}},
		{"blocked", "blocked", true, "blocked", stats.TimelineBucket{Total: 2, Blocked: 2}},
		{"all", "all", true, "all", stats.TimelineBucket{Total: 5, Blocked: 2, Cached: 1, Unresolved: 1, UpstreamError: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, base := historyServer(t, "")
			if tc.set {
				s.counter.SetQueryLogMode(tc.mode)
			}
			s.counter.RecordQuery("", "", true)
			s.counter.RecordQuery("", "", true)
			s.counter.RecordQuery("", "", false)
			s.counter.RecordCacheHit()
			s.counter.RecordQuery("", "", false)
			s.counter.RecordForwardFailure()
			s.counter.RecordQuery("", "", false)
			s.counter.RecordUpstreamError()

			code, _, body := getRaw(t, base+"/api/history?window=1h&bucket=1m")
			if code != http.StatusOK {
				t.Fatalf("status %d", code)
			}
			var h struct {
				Source  string                 `json:"source"`
				Logging string                 `json:"logging"`
				Series  []stats.TimelineBucket `json:"series"`
			}
			if err := json.Unmarshal(body, &h); err != nil {
				t.Fatal(err)
			}
			if h.Source != "memory" || h.Logging != tc.logging {
				t.Errorf("source %q, logging %q; want memory, %q", h.Source, h.Logging, tc.logging)
			}
			if len(h.Series) != 60 {
				t.Errorf("series has %d buckets, want 60", len(h.Series))
			}
			var got stats.TimelineBucket
			for _, b := range h.Series {
				got.Total += b.Total
				got.Blocked += b.Blocked
				got.Cached += b.Cached
				got.Unresolved += b.Unresolved
				got.UpstreamError += b.UpstreamError
			}
			if got != tc.want {
				t.Errorf("series sums = %+v, want %+v", got, tc.want)
			}
			if total := s.counter.Snapshot(0).TotalQueries; total != 5 {
				t.Errorf("since-start total = %d, want 5 in every mode", total)
			}
		})
	}
}

func TestHistory_SourceLoggingAndWindow(t *testing.T) {
	// PRIV-09 and A7: up to 24h comes from memory, with logging set to the
	// mode the counter follows. A longer window comes from the database when
	// there is one and its mode is not "none", with the database's mode;
	// otherwise it is cut to 24h from memory.
	cases := []struct {
		name, db, counter, query string
		source, logging          string
		window, bucket           int64
	}{
		{"1h, no database", "", "", "?window=1h&bucket=1m", "memory", "none", 3600, 60},
		{"24h, no database", "", "none", "?window=24h&bucket=1h", "memory", "none", 86400, 3600},
		{"24h, database all", "all", "all", "?window=24h&bucket=1h", "memory", "all", 86400, 3600},
		{"default, database blocked", "blocked", "blocked", "", "memory", "blocked", 86400, 3600},
		{"7d, no database", "", "all", "?window=7d&bucket=1h", "memory", "all", 86400, 3600},
		{"48h, database none", "none", "none", "?window=48h&bucket=1h", "memory", "none", 86400, 3600},
		{"48h bucket, no database", "", "none", "?window=48h&bucket=48h", "memory", "none", 86400, 86400},
		{"48h, database all", "all", "all", "?window=48h&bucket=1h", "database", "all", 172800, 3600},
		{"7d, database blocked", "blocked", "blocked", "?window=7d&bucket=1h", "database", "blocked", 604800, 3600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, base := historyServer(t, tc.db)
			if tc.counter != "" {
				s.counter.SetQueryLogMode(tc.counter)
			}
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

func TestAllowlistAudit_ClientFollowsQueryLog(t *testing.T) {
	// PRIV-10: the allowlist add and remove audit lines always keep the
	// domain. They have a client attribute only when query_log.mode records
	// queries ("blocked" or "all"), masked with query_log.clients like a
	// query-log row: none under "drop" or an unknown value, the subnet under
	// "subnet", the address under "full". Under mode "none", an unset mode,
	// or an unknown mode, no line holds the address in any clients setting,
	// because the query log would not hold it either. No line has the source
	// port, and no line holds the address unless the client attribute does.
	remotes := []struct {
		remote, ip, subnet string
	}{
		{"192.168.1.77:5555", "192.168.1.77", "192.168.1.0"},
		{"[2001:db8:1:2:aaaa::77]:5555", "2001:db8:1:2:aaaa::77", "2001:db8:1:2::"},
	}
	for _, mode := range []string{"", "none", "everything", "blocked", "all"} {
		for _, clients := range []string{"", "drop", "bogus", "subnet", "full"} {
			for _, rm := range remotes {
				t.Run("mode="+mode+"/clients="+clients+"/"+rm.ip, func(t *testing.T) {
					s, _ := newTestServer(t, nil)
					if mode != "" || clients != "" {
						s.SetPrivacy(PrivacyInfo{Mode: mode, Clients: clients})
					}
					logs := captureJSONLogs(t)
					h := s.handler()
					if code := requestFrom(h, http.MethodPost, "/api/allowlist", rm.remote, "application/json", `{"domain":"audit.example.com"}`); code != http.StatusOK {
						t.Fatalf("POST /api/allowlist = %d", code)
					}
					if code := requestFrom(h, http.MethodDelete, "/api/allowlist?domain=audit.example.com", rm.remote, "", ""); code != http.StatusOK {
						t.Fatalf("DELETE /api/allowlist = %d", code)
					}
					want := ""
					if mode == "blocked" || mode == "all" {
						switch clients {
						case "subnet":
							want = rm.subnet
						case "full":
							want = rm.ip
						}
					}
					for _, msg := range []string{"allowlist entry added", "allowlist entry removed"} {
						lines := logs.withMsg(t, msg)
						if len(lines) != 1 {
							t.Fatalf("got %d %q lines, want 1", len(lines), msg)
						}
						r := lines[0]
						if r["domain"] != "audit.example.com" {
							t.Errorf("%q domain = %v, want audit.example.com", msg, r["domain"])
						}
						client, has := r["client"]
						if want == "" && has {
							t.Errorf("%q has client = %v under mode %q, clients %q; want no client attribute", msg, client, mode, clients)
						}
						if want != "" && client != want {
							t.Errorf("%q client = %v, want %q", msg, client, want)
						}
					}
					for _, r := range logs.records(t) {
						for k, v := range r {
							s := fmt.Sprint(v)
							if strings.Contains(s, "5555") {
								t.Errorf("attribute %s = %q holds the source port", k, s)
							}
							if want != rm.ip && strings.Contains(s, rm.ip) {
								t.Errorf("attribute %s = %q holds the address under mode %q, clients %q", k, s, mode, clients)
							}
						}
					}
				})
			}
		}
	}
}

func TestReload_LogLineHasNoClientAddress(t *testing.T) {
	// PRIV-10: the "reload requested via API" line has no client attribute
	// and no requester address under every query_log.clients value, over IPv4
	// and IPv6.
	for _, clients := range []string{"", "drop", "subnet", "full"} {
		for _, remote := range []string{"192.168.1.77:5555", "[2001:db8::77]:5555"} {
			t.Run("clients="+clients+"/"+remote, func(t *testing.T) {
				s, _ := newTestServer(t, nil)
				if clients != "" {
					s.SetPrivacy(PrivacyInfo{Clients: clients})
				}
				logs := captureJSONLogs(t)
				if code := requestFrom(s.handler(), http.MethodPost, "/api/reload", remote, "", ""); code != http.StatusOK {
					t.Fatalf("POST /api/reload = %d", code)
				}
				lines := logs.withMsg(t, "reload requested via API")
				if len(lines) != 1 {
					t.Fatalf("got %d reload lines, want 1: %v", len(lines), logs.records(t))
				}
				if _, has := lines[0]["client"]; has {
					t.Errorf("reload line has a client attribute: %v", lines[0])
				}
				for _, r := range logs.records(t) {
					assertNoAddressIn(t, r, "5555")
				}
			})
		}
	}
}
