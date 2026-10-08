package api

import (
	"net/http"
	"strings"
	"testing"
)

// SEC-10: the Fetch Metadata resource isolation policy in secure. A request
// that the browser marks as sent from another site (Sec-Fetch-Site
// cross-site or same-site), or that has an unknown Sec-Fetch-Site value, gets
// 403 on every route and every method. The one exception is a top-level
// navigation to the dashboard page: GET "/" with Sec-Fetch-Mode navigate and
// Sec-Fetch-Dest document.

const fetchHost = "127.0.0.1:8080"

// fetchRoutes is every route and method that a page on another site could
// try: the API reads (the XS-Leaks timing probes), the export, the changes,
// the static files, the probes, /metrics, and pprof.
var fetchRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/stats"},
	{http.MethodHead, "/api/stats"},
	{http.MethodGet, "/api/check?domain=ads.example.com"},
	{http.MethodGet, "/api/queries"},
	{http.MethodGet, "/api/queries?domain=example"},
	{http.MethodHead, "/api/queries?domain=example"},
	{http.MethodGet, "/api/queries/export"},
	{http.MethodGet, "/api/queries/export?format=json"},
	{http.MethodGet, "/api/top-blocked"},
	{http.MethodGet, "/api/history"},
	{http.MethodGet, "/api/allowlist"},
	{http.MethodPost, "/api/allowlist"},
	{http.MethodDelete, "/api/allowlist?domain=tracker.example.com"},
	{http.MethodPost, "/api/reload"},
	{http.MethodPost, "/api/purge"},
	{http.MethodGet, "/"},
	{http.MethodHead, "/"},
	{http.MethodGet, "/index.html"},
	{http.MethodGet, "/app.js"},
	{http.MethodGet, "/metrics"},
	{http.MethodGet, "/healthz"},
	{http.MethodGet, "/readyz"},
	{http.MethodGet, "/debug/pprof/"},
	{http.MethodGet, "/no-such-page"},
}

// refusedSites are the Sec-Fetch-Site values that the policy refuses: the
// two values a page on another site sends, and unknown values (fail closed).
var refusedSites = []string{"cross-site", "same-site", "bogus", "CROSS-SITE", "cross-site, same-origin"}

func TestFetchMetadata_OtherSiteRefusedOnEveryRoute(t *testing.T) {
	// SEC-10: a request from another site, or with an unknown Sec-Fetch-Site
	// value, gets 403 on every route and every method, and the handler does
	// not run.
	for _, site := range refusedSites {
		for _, r := range fetchRoutes {
			s, h, reloads := secServer(t)
			hdr := map[string]string{"Sec-Fetch-Site": site, "Content-Type": "application/json"}
			body := ""
			switch r.path {
			case "/api/allowlist":
				body = `{"domain":"tracker.example.com"}`
			case "/api/purge":
				body = `{"confirm": true}`
			}
			if r.method == http.MethodDelete {
				s.store.AddToAllowlist("tracker.example.com")
			}
			rec := serve(h, r.method, r.path, fetchHost, hdr, body)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s with Sec-Fetch-Site %q = %d, want 403", r.method, r.path, site, rec.Code)
			}
			if reloads.Load() != 0 {
				t.Errorf("%s %s with Sec-Fetch-Site %q ran the reload", r.method, r.path, site)
			}
			wantLen := 0
			if r.method == http.MethodDelete {
				wantLen = 1
			}
			if got := s.store.AllowlistLen(); got != wantLen {
				t.Errorf("%s %s with Sec-Fetch-Site %q changed the allowlist size to %d, want %d",
					r.method, r.path, site, got, wantLen)
			}
		}
	}
}

func TestFetchMetadata_CrossSiteQueriesProbeRefused(t *testing.T) {
	// SEC-10 acceptance: a cross-site fetch to /api/queries (the XS-Leaks
	// probe) gets 403, and the reply holds no query data. The 403 still
	// carries the security headers.
	_, h, _ := secServer(t)
	for _, hdr := range []map[string]string{
		{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "empty"},
		{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"},
		{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"},
		{"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "script"},
	} {
		rec := serve(h, http.MethodGet, "/api/queries?domain=example", fetchHost, hdr, "")
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET /api/queries with %v = %d, want 403", hdr, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
			t.Errorf("403 reply has Content-Type %q, want a plain-text refusal", ct)
		}
		assertSecurityHeaders(t, "cross-site 403 on /api/queries", rec.Header())
		assertScriptSrcSelf(t, "cross-site 403 on /api/queries", rec.Header())
	}
}

func TestFetchMetadata_OwnOriginAndTypedURLPass(t *testing.T) {
	// SEC-10: Sec-Fetch-Site same-origin (the dashboard's own fetches) and
	// none (a typed URL or a bookmark) pass on every GET route.
	_, h, _ := secServer(t)
	for _, site := range []string{"same-origin", "none"} {
		for _, r := range fetchRoutes {
			if r.method != http.MethodGet || r.path == "/no-such-page" {
				continue
			}
			rec := serve(h, r.method, r.path, fetchHost, map[string]string{"Sec-Fetch-Site": site}, "")
			if rec.Code == http.StatusForbidden {
				t.Errorf("%s %s with Sec-Fetch-Site %q = 403, want it allowed", r.method, r.path, site)
			}
		}
	}
}

func TestFetchMetadata_SameOriginDashboardFetchWorks(t *testing.T) {
	// SEC-10 acceptance: the dashboard's own fetches (same-origin, cors,
	// empty destination) get their data, and its own changes go through.
	s, h, reloads := secServer(t)
	hdr := map[string]string{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}
	for _, path := range []string{"/api/stats", "/api/queries", "/api/history", "/api/allowlist", "/api/top-blocked"} {
		rec := serve(h, http.MethodGet, path, fetchHost, hdr, "")
		if rec.Code != http.StatusOK {
			t.Errorf("same-origin GET %s = %d, want 200", path, rec.Code)
		}
	}
	rec := serve(h, http.MethodGet, "/app.js", fetchHost,
		map[string]string{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "script"}, "")
	if rec.Code != http.StatusOK {
		t.Errorf("same-origin GET /app.js = %d, want 200", rec.Code)
	}
	post := map[string]string{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
		"Sec-Fetch-Dest": "empty", "Content-Type": "application/json", "Origin": "http://" + fetchHost}
	if rec := serve(h, http.MethodPost, "/api/allowlist", fetchHost, post, `{"domain":"tracker.example.com"}`); rec.Code != http.StatusOK {
		t.Errorf("same-origin POST /api/allowlist = %d, want 200", rec.Code)
	}
	if s.store.AllowlistLen() != 1 {
		t.Errorf("allowlist size = %d after a same-origin add, want 1", s.store.AllowlistLen())
	}
	if rec := serve(h, http.MethodPost, "/api/reload", fetchHost, post, ""); rec.Code != http.StatusOK || reloads.Load() != 1 {
		t.Errorf("same-origin POST /api/reload = %d with %d reloads, want 200 and 1", rec.Code, reloads.Load())
	}
}

func TestFetchMetadata_NoHeaderPasses(t *testing.T) {
	// SEC-10 acceptance: a request without Sec-Fetch-Site (curl, Prometheus
	// /metrics, the /healthz healthcheck) passes.
	_, h, reloads := secServer(t)
	for _, path := range []string{"/api/stats", "/api/queries", "/api/queries?domain=example", "/metrics", "/healthz", "/", "/app.js"} {
		rec := serve(h, http.MethodGet, path, fetchHost, map[string]string{"User-Agent": "curl/8.5.0"}, "")
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s without Sec-Fetch-Site = %d, want 200", path, rec.Code)
		}
	}
	if rec := serve(h, http.MethodPost, "/api/reload", fetchHost, nil, ""); rec.Code != http.StatusOK || reloads.Load() != 1 {
		t.Errorf("POST /api/reload without Sec-Fetch-Site = %d with %d reloads, want 200 and 1", rec.Code, reloads.Load())
	}
}

func TestFetchMetadata_NavigationToDashboardPasses(t *testing.T) {
	// SEC-10 acceptance: a link on another site that opens the dashboard (a
	// top-level GET navigation to "/") works, also with a query string, and
	// with an unknown Sec-Fetch-Site value.
	_, h, _ := secServer(t)
	for _, site := range refusedSites {
		for _, target := range []string{"/", "/?from=link"} {
			hdr := map[string]string{"Sec-Fetch-Site": site, "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
			rec := serve(h, http.MethodGet, target, fetchHost, hdr, "")
			if rec.Code != http.StatusOK {
				t.Errorf("navigation to %s with Sec-Fetch-Site %q = %d, want 200", target, site, rec.Code)
				continue
			}
			if !strings.Contains(rec.Body.String(), "<html") {
				t.Errorf("navigation to %s with Sec-Fetch-Site %q did not serve the dashboard page", target, site)
			}
			assertSecurityHeaders(t, "navigation to "+target, rec.Header())
		}
	}
}

func TestFetchMetadata_OnlyTheDashboardNavigationIsExempt(t *testing.T) {
	// SEC-10: the exception needs all four parts (GET, path "/", navigate
	// mode, document destination). A navigation to another path, a framed
	// dashboard, a no-cors or cors request for "/", and another method on "/"
	// from another site are refused. HEAD and OPTIONS pass
	// CrossOriginProtection, so only the Fetch Metadata check refuses them.
	_, h, _ := secServer(t)
	cases := []struct {
		name, method, target, mode, dest string
	}{
		{"navigate to /api/queries", http.MethodGet, "/api/queries?domain=example", "navigate", "document"},
		{"navigate to /api/queries/export", http.MethodGet, "/api/queries/export", "navigate", "document"},
		{"navigate to /api/stats", http.MethodGet, "/api/stats", "navigate", "document"},
		{"navigate to /index.html", http.MethodGet, "/index.html", "navigate", "document"},
		{"navigate to /app.js", http.MethodGet, "/app.js", "navigate", "document"},
		{"navigate to /metrics", http.MethodGet, "/metrics", "navigate", "document"},
		{"/ in an iframe", http.MethodGet, "/", "navigate", "iframe"},
		{"/ in a frame", http.MethodGet, "/", "navigate", "frame"},
		{"/ as an image", http.MethodGet, "/", "no-cors", "image"},
		{"/ no-cors document", http.MethodGet, "/", "no-cors", "document"},
		{"/ cors fetch", http.MethodGet, "/", "cors", "empty"},
		{"/ navigate without dest", http.MethodGet, "/", "navigate", ""},
		{"/ document without mode", http.MethodGet, "/", "", "document"},
		{"form POST to /", http.MethodPost, "/", "navigate", "document"},
		{"HEAD / navigate", http.MethodHead, "/", "navigate", "document"},
		{"OPTIONS / navigate", http.MethodOptions, "/", "navigate", "document"},
	}
	for _, site := range []string{"cross-site", "same-site", "bogus"} {
		for _, tc := range cases {
			hdr := map[string]string{"Sec-Fetch-Site": site}
			if tc.mode != "" {
				hdr["Sec-Fetch-Mode"] = tc.mode
			}
			if tc.dest != "" {
				hdr["Sec-Fetch-Dest"] = tc.dest
			}
			rec := serve(h, tc.method, tc.target, fetchHost, hdr, "")
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s with Sec-Fetch-Site %q = %d, want 403", tc.name, site, rec.Code)
			}
		}
	}
}

func TestFetchMetadata_RefusalCarriesSecurityHeaders(t *testing.T) {
	// SEC-10: the 403 from the Fetch Metadata check still carries the
	// security headers, on a GET (which CrossOriginProtection lets through)
	// as well as on a POST.
	_, h, _ := secServer(t)
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/api/stats"},
		{http.MethodGet, "/api/queries/export"},
		{http.MethodGet, "/app.js"},
		{http.MethodHead, "/"},
		{http.MethodPost, "/api/reload"},
	} {
		rec := serve(h, r.method, r.path, fetchHost, map[string]string{"Sec-Fetch-Site": "cross-site"}, "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s cross-site = %d, want 403", r.method, r.path, rec.Code)
		}
		what := "cross-site 403 on " + r.method + " " + r.path
		assertSecurityHeaders(t, what, rec.Header())
		assertScriptSrcSelf(t, what, rec.Header())
	}
}

func TestFetchMetadata_HostCheckStillFirst(t *testing.T) {
	// SEC-10 does not replace the Host check (A1, b/073): a rebinding page
	// that sends a same-origin request with a foreign Host still gets 421.
	_, h, _ := secServer(t)
	rec := serve(h, http.MethodGet, "/api/queries", "evil.example", map[string]string{"Sec-Fetch-Site": "same-origin"}, "")
	if rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("same-origin GET /api/queries with Host evil.example = %d, want 421", rec.Code)
	}
}
