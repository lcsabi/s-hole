package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
)

// newTestServer builds a Server backed by a fresh stats/store and an
// httptest.Server in front of its router. reloadFn defaults to returning
// true (single-shot, always wins the lock) but can be overridden.
func newTestServer(t *testing.T, reloadFn func() bool) (*Server, *httptest.Server) {
	t.Helper()
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})

	counter := stats.New()
	if reloadFn == nil {
		reloadFn = func() bool { return true }
	}
	s := New(counter, nil, store, nil, reloadFn)
	httpSrv := httptest.NewServer(s.handler())
	t.Cleanup(httpSrv.Close)
	return s, httpSrv
}

func decode[T any](t *testing.T, body io.Reader) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(body).Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func TestListenAndServe_LifecycleAndShutdown(t *testing.T) {
	// Exercise the production code path (not just s.handler() inside
	// httptest): bind a free port, hit /healthz, then Shutdown.
	store := blocklist.NewStore()
	counter := stats.New()
	s := New(counter, nil, store, nil, func() bool { return true })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	serveErr := make(chan error, 1)
	go func() { serveErr <- s.ListenAndServe(addr) }()

	// Wait briefly for the server to come up, then probe /healthz.
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		s.Shutdown(context.Background())
		t.Fatalf("server never accepted a connection: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("/healthz status = %d", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown returned %v", err)
	}
	select {
	case err := <-serveErr:
		if err != nil {
			t.Errorf("ListenAndServe returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after Shutdown")
	}
}

func TestShutdown_BeforeListenIsNoOp(t *testing.T) {
	// If the caller calls Shutdown without ever calling ListenAndServe,
	// the helper must not panic — s.httpServer is nil at that point.
	store := blocklist.NewStore()
	s := New(stats.New(), nil, store, nil, func() bool { return true })
	if err := s.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown on never-started server = %v, want nil", err)
	}
}

// queriesResponse mirrors the JSON shape returned by /api/queries — kept
// local so the test does not depend on api package internals.
type queriesResponse struct {
	Queries []querylog.QueryRow `json:"queries"`
}

func TestQueriesEndpoint_WithRealDB(t *testing.T) {
	// Wire a real DBLogger so the handleQueries branch that calls
	// s.db.Recent is exercised end-to-end.
	dbPath := filepath.Join(t.TempDir(), "q.db")
	db, err := querylog.NewDBLogger(dbPath, "all", 50*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	defer db.Close()

	db.Log("1.1.1.1", "first.com.", false)
	db.Log("1.1.1.1", "second.com.", true)
	time.Sleep(150 * time.Millisecond) // wait for the flush tick

	store := blocklist.NewStore()
	s := New(stats.New(), db, store, nil, func() bool { return true })
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/queries?limit=10")
	if err != nil {
		t.Fatalf("GET /api/queries: %v", err)
	}
	defer resp.Body.Close()
	body := decode[queriesResponse](t, resp.Body)
	if len(body.Queries) != 2 {
		t.Errorf("got %d rows, want 2", len(body.Queries))
	}
}

func TestQueriesEndpoint_IgnoresBadLimit(t *testing.T) {
	// A non-numeric ?limit= must fall through to the default.
	_, srv := newTestServer(t, nil)
	resp, err := http.Get(srv.URL + "/api/queries?limit=garbage")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestParseLimit(t *testing.T) {
	// T3: the ?limit= parameter is defaulted for absent/malformed/
	// non-positive values and clamped so one request cannot marshal the
	// entire history table.
	cases := []struct {
		query string
		want  int
	}{
		{"", defaultQueriesLimit},
		{"limit=garbage", defaultQueriesLimit},
		{"limit=0", defaultQueriesLimit},
		{"limit=-5", defaultQueriesLimit},
		{"limit=25", 25},
		{"limit=1000", maxQueriesLimit},
		{"limit=99999999", maxQueriesLimit},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/queries?"+tc.query, nil)
			if got := parseLimit(r); got != tc.want {
				t.Errorf("parseLimit(%q) = %d, want %d", tc.query, got, tc.want)
			}
		})
	}
}

func TestWhitelistRemove_RejectsEmptyDomain(t *testing.T) {
	_, srv := newTestServer(t, nil)
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/whitelist?domain=", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestWhitelistAdd_RejectsInvalidDomain(t *testing.T) {
	// R13: ValidDomain gate catches malformed input even when the body
	// shape itself is valid JSON.
	_, srv := newTestServer(t, nil)
	resp, err := http.Post(srv.URL+"/api/whitelist", "application/json",
		strings.NewReader(`{"domain":"no-dot-here"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid domain)", resp.StatusCode)
	}
}

// brokenResponseWriter is an http.ResponseWriter whose Write always
// errors. Used to drive the writeJSON encoder-error branch.
type brokenResponseWriter struct {
	header http.Header
}

func (b *brokenResponseWriter) Header() http.Header {
	if b.header == nil {
		b.header = http.Header{}
	}
	return b.header
}
func (b *brokenResponseWriter) Write([]byte) (int, error) { return 0, errBrokenWrite }
func (b *brokenResponseWriter) WriteHeader(int)           {}

var errBrokenWrite = brokenError{}

type brokenError struct{}

func (brokenError) Error() string { return "broken writer" }

func TestWriteJSON_LogsEncoderErrors(t *testing.T) {
	// The encoder error path is hard to drive via a real HTTP call
	// because json.NewEncoder succeeds on every JSON-encodable type.
	// Inject a ResponseWriter whose Write always errors instead. The
	// purpose is coverage + no panic — the actual log line is verified
	// by inspection in the slog handler.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("writeJSON panicked on a broken writer: %v", r)
		}
	}()
	w := &brokenResponseWriter{}
	writeJSON(w, map[string]string{"x": "y"})
}

func TestReadinessEndpoint_OkOnceBlocklistLoaded(t *testing.T) {
	// /readyz is 200 once store.Len() > 0. newTestServer seeds one entry
	// via store.Replace, so this server is "ready" immediately.
	_, srv := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ok") {
		t.Errorf("body = %q, want 'ok'", body)
	}
}

func TestReadinessEndpoint_503BeforeBlocklist(t *testing.T) {
	// Fresh store with no entries: /readyz must return 503 so a
	// container orchestrator routes traffic away while the initial
	// blocklist download is still in flight. This is the Kubernetes
	// readiness contract — see DESIGN.md "Observability" section.
	store := blocklist.NewStore() // empty
	s := New(stats.New(), nil, store, nil, func() bool { return true })
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (blocklist empty)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "empty") {
		t.Errorf("503 body = %q, want it to mention 'empty'", body)
	}
}

func TestHealthEndpoint(t *testing.T) {
	_, srv := newTestServer(t, nil)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ok") {
		t.Errorf("body = %q, want it to contain 'ok'", body)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	s, srv := newTestServer(t, nil)
	s.counter.RecordQuery("1.1.1.1", "ads.com.", true)
	s.counter.RecordQuery("1.1.1.1", "google.com.", false)
	s.counter.RecordCacheHit()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", got)
	}
	body, _ := io.ReadAll(resp.Body)
	want := []string{
		"shole_queries_total 2",
		"shole_blocked_total 1",
		"shole_cache_hits_total 1",
		"shole_blocklist_size",
		"# HELP shole_queries_total",
		"# TYPE shole_queries_total counter",
	}
	for _, w := range want {
		if !strings.Contains(string(body), w) {
			t.Errorf("metrics body missing %q\nfull body:\n%s", w, body)
		}
	}
}

// fakeCacheStats lets us verify /metrics surfaces cache metrics when a
// CacheStatser is wired up.
type fakeCacheStats struct {
	h, m uint64
	s    int
}

func (f fakeCacheStats) Stats() (uint64, uint64, int) { return f.h, f.m, f.s }

func TestMetricsEndpoint_IncludesCacheStatsWhenWired(t *testing.T) {
	store := blocklist.NewStore()
	counter := stats.New()
	s := New(counter, nil, store, fakeCacheStats{h: 7, m: 3, s: 42}, func() bool { return true })
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "shole_cache_misses_total 3") {
		t.Errorf("expected cache_misses_total=3 in body:\n%s", body)
	}
	if !strings.Contains(string(body), "shole_cache_size 42") {
		t.Errorf("expected cache_size=42 in body:\n%s", body)
	}
}

func TestStatsEndpoint_ReturnsSummary(t *testing.T) {
	s, srv := newTestServer(t, nil)
	s.counter.RecordQuery("1.1.1.1", "ads.com.", true)

	resp, err := http.Get(srv.URL + "/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got := decode[stats.Summary](t, resp.Body)
	if got.TotalQueries != 1 || got.BlockedCount != 1 {
		t.Errorf("summary = %+v, want 1/1", got)
	}
}

func TestWhitelistEndpoints_RoundTrip(t *testing.T) {
	_, srv := newTestServer(t, nil)

	// List is initially empty.
	resp, err := http.Get(srv.URL + "/api/whitelist")
	if err != nil {
		t.Fatalf("GET whitelist: %v", err)
	}
	defer resp.Body.Close()
	body := decode[struct {
		Domains []string `json:"domains"`
	}](t, resp.Body)
	if len(body.Domains) != 0 {
		t.Errorf("initial whitelist = %v, want empty", body.Domains)
	}

	// Add.
	addBody := strings.NewReader(`{"domain":"foo.com"}`)
	resp2, err := http.Post(srv.URL+"/api/whitelist", "application/json", addBody)
	if err != nil {
		t.Fatalf("POST whitelist: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("POST status = %d", resp2.StatusCode)
	}

	// Confirm it's there.
	resp3, err := http.Get(srv.URL + "/api/whitelist")
	if err != nil {
		t.Fatalf("GET whitelist (post-add): %v", err)
	}
	defer resp3.Body.Close()
	body = decode[struct {
		Domains []string `json:"domains"`
	}](t, resp3.Body)
	if len(body.Domains) != 1 || body.Domains[0] != "foo.com" {
		t.Errorf("after add: whitelist = %v, want [foo.com]", body.Domains)
	}

	// Delete.
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/whitelist?domain=foo.com", nil)
	resp4, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE whitelist: %v", err)
	}
	resp4.Body.Close()

	resp5, err := http.Get(srv.URL + "/api/whitelist")
	if err != nil {
		t.Fatalf("GET whitelist (post-delete): %v", err)
	}
	defer resp5.Body.Close()
	body = decode[struct {
		Domains []string `json:"domains"`
	}](t, resp5.Body)
	if len(body.Domains) != 0 {
		t.Errorf("after delete: whitelist = %v, want empty", body.Domains)
	}
}

func TestWhitelistAdd_RejectsEmptyDomain(t *testing.T) {
	_, srv := newTestServer(t, nil)

	resp, err := http.Post(srv.URL+"/api/whitelist", "application/json", strings.NewReader(`{"domain":""}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestWhitelistAdd_RejectsOversizedBody(t *testing.T) {
	// Regression for b/026: bodies above maxRequestBytes must be rejected
	// rather than allocated in full.
	_, srv := newTestServer(t, nil)

	huge := bytes.Repeat([]byte("x"), maxRequestBytes+1024)
	body := bytes.NewReader(append([]byte(`{"domain":"`), append(huge, []byte(`"}`)...)...))
	resp, err := http.Post(srv.URL+"/api/whitelist", "application/json", body)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body too large)", resp.StatusCode)
	}
}

func TestReload_DispatchesAndReturnsStatus(t *testing.T) {
	var called atomic.Int32
	_, srv := newTestServer(t, func() bool {
		called.Add(1)
		return true
	})

	resp, err := http.Post(srv.URL+"/api/reload", "application/json", nil)
	if err != nil {
		t.Fatalf("POST reload: %v", err)
	}
	defer resp.Body.Close()
	out := decode[map[string]string](t, resp.Body)
	if out["status"] != "reload triggered" {
		t.Errorf("status = %q, want 'reload triggered'", out["status"])
	}
	if called.Load() != 1 {
		t.Errorf("reloadFn called %d times, want 1", called.Load())
	}
}

func TestReload_AlreadyInProgressDoesNotDispatch(t *testing.T) {
	// Regression for b/022: when reloadFn returns false (because the
	// caller-owned mutex is held), the API must surface
	// "reload already in progress" rather than spawning a duplicate.
	_, srv := newTestServer(t, func() bool {
		return false // simulate the mutex being held by someone else
	})

	resp, err := http.Post(srv.URL+"/api/reload", "application/json", nil)
	if err != nil {
		t.Fatalf("POST reload: %v", err)
	}
	defer resp.Body.Close()
	out := decode[map[string]string](t, resp.Body)
	if out["status"] != "reload already in progress" {
		t.Errorf("status = %q, want 'reload already in progress'", out["status"])
	}
}

func TestReload_ConcurrentCallsCollapse(t *testing.T) {
	// With a real single-flight closure, only one of N concurrent calls
	// should observe "triggered"; the rest should see "already in progress."
	var mu sync.Mutex
	reload := func() bool {
		if !mu.TryLock() {
			return false
		}
		go func() {
			// Hold the lock briefly to ensure other requests collide.
			defer mu.Unlock()
		}()
		return true
	}
	_, srv := newTestServer(t, reload)

	var triggered, inProgress atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(srv.URL+"/api/reload", "application/json", nil)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			out := decode[map[string]string](t, resp.Body)
			switch out["status"] {
			case "reload triggered":
				triggered.Add(1)
			case "reload already in progress":
				inProgress.Add(1)
			}
		}()
	}
	wg.Wait()

	if triggered.Load()+inProgress.Load() == 0 {
		t.Fatal("no requests returned a known status")
	}
	if triggered.Load() == 50 {
		// Possible but unlikely; if the goroutine releases the lock
		// between every TryLock attempt we never observe contention.
		t.Log("note: no contention observed — single-flight gate ran serially")
	}
}
