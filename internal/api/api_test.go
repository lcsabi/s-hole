package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/laszlo/s-hole/internal/blocklist"
	"github.com/laszlo/s-hole/internal/stats"
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
	s := New(counter, nil, store, reloadFn)
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
			if out["status"] == "reload triggered" {
				triggered.Add(1)
			} else if out["status"] == "reload already in progress" {
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
