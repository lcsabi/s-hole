package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/stats"
)

// TestPprof_OffByDefault is the security-critical assertion: the pprof
// surface — which exposes goroutine stacks, heap layouts, and binary
// symbols — must not be reachable unless the operator explicitly opted
// in. SECURITY.md promises this; this test enforces it.
func TestPprof_OffByDefault(t *testing.T) {
	_, srv := newTestServer(t, nil)

	for _, path := range []string{
		"/debug/pprof/",
		"/debug/pprof/heap",
		"/debug/pprof/goroutine",
		"/debug/pprof/cmdline",
		"/debug/pprof/profile",
		"/debug/pprof/symbol",
		"/debug/pprof/trace",
	} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s status = %d, want 404 (pprof must be off by default)",
					path, resp.StatusCode)
			}
		})
	}
}

// TestPprof_OnWhenEnabled verifies that EnablePprof(true) actually wires
// the handlers. Catches a regression where the registration logic
// disconnects from the flag (e.g. someone refactoring handler() and
// dropping the conditional).
func TestPprof_OnWhenEnabled(t *testing.T) {
	store := blocklist.NewStore()
	store.Replace([]string{"x.com"})
	s := New(stats.New(), nil, store, nil, func() bool { return true })
	s.EnablePprof(true)
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/debug/pprof/")
	if err != nil {
		t.Fatalf("GET /debug/pprof/: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (pprof index should serve when enabled)",
			resp.StatusCode)
	}

	// The pprof index page lists every named profile; if it does not
	// the registration is broken even though the index URL returned 200.
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "heap") {
		t.Errorf("pprof index does not mention 'heap' profile; registration may be broken")
	}
}

// TestPprof_CmdlineWhenEnabled drives one of the named handlers (cmdline
// is the cheapest) to confirm subroute registration works, not just the
// index.
func TestPprof_CmdlineWhenEnabled(t *testing.T) {
	store := blocklist.NewStore()
	store.Replace([]string{"x.com"})
	s := New(stats.New(), nil, store, nil, func() bool { return true })
	s.EnablePprof(true)
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/debug/pprof/cmdline")
	if err != nil {
		t.Fatalf("GET /debug/pprof/cmdline: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/debug/pprof/cmdline status = %d, want 200", resp.StatusCode)
	}
}
