package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/stats"
)

// secServer builds a Server with fixed machine names and pprof on, so every
// route the Host check guards exists. reloads counts reload calls.
func secServer(t *testing.T) (*Server, http.Handler, *atomic.Int64) {
	t.Helper()
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})
	reloads := new(atomic.Int64)
	s := New(stats.New(), nil, store, nil, func() bool { reloads.Add(1); return true })
	s.hostnames = []string{"raspberrypi.home", "raspberrypi", "raspberrypi.local"}
	s.EnablePprof(true)
	return s, s.handler(), reloads
}

// serve runs one request through h and returns the recorded response.
func serve(h http.Handler, method, target, host string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = host
	req.RemoteAddr = "127.0.0.1:40000"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// guardedRoutes is every kind of route: the API, the page, the probes,
// /metrics, and pprof.
var guardedRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/stats"},
	{http.MethodGet, "/api/queries"},
	{http.MethodGet, "/api/history"},
	{http.MethodGet, "/api/allowlist"},
	{http.MethodPost, "/api/reload"},
	{http.MethodGet, "/"},
	{http.MethodGet, "/index.html"},
	{http.MethodGet, "/metrics"},
	{http.MethodGet, "/healthz"},
	{http.MethodGet, "/readyz"},
	{http.MethodGet, "/debug/pprof/"},
	{http.MethodGet, "/no-such-page"},
}

func TestHostCheck_AllowedHosts(t *testing.T) {
	// A1: an empty Host, an IP literal, "localhost", and the machine's own
	// names pass, with any port, in any case, with an optional trailing dot.
	_, h, _ := secServer(t)
	hosts := []string{
		"", "127.0.0.1", "127.0.0.1:8080", "192.168.1.2:8080", "203.0.113.9",
		"[::1]", "[::1]:8080", "[fe80::1]:80", "[2001:db8::1]",
		"localhost", "localhost:8080", "LOCALHOST", "Localhost.:8080",
		"raspberrypi", "RaspberryPi:8080", "raspberrypi.local", "raspberrypi.LOCAL.:8080",
		"raspberrypi.home", "raspberrypi.home.",
	}
	for _, host := range hosts {
		for _, r := range guardedRoutes {
			rec := serve(h, r.method, r.path, host, nil, "")
			if rec.Code == http.StatusMisdirectedRequest {
				t.Errorf("%s %s with Host %q = 421, want it allowed", r.method, r.path, host)
			}
		}
	}
}

func TestHostCheck_RefusedHosts(t *testing.T) {
	// A1 (b/073): any other Host gets 421 on every route, with a body that
	// says how to open the dashboard. A name that only starts with the
	// machine's name is refused.
	_, h, reloads := secServer(t)
	hosts := []string{
		"evil.example", "evil.example:8080", "EVIL.example.",
		"raspberrypi.evil.example", "raspberrypi.local.evil.example", "raspberrypi.home.evil.example:8080",
		"localhost.evil.example", "evil-localhost", "127.0.0.1.nip.io",
		"raspberrypi.locals", "xraspberrypi", "raspberrypi.lan",
	}
	for _, host := range hosts {
		for _, r := range guardedRoutes {
			rec := serve(h, r.method, r.path, host, nil, "")
			if rec.Code != http.StatusMisdirectedRequest {
				t.Errorf("%s %s with Host %q = %d, want 421", r.method, r.path, host, rec.Code)
				continue
			}
			body := rec.Body.String()
			if !strings.Contains(body, "dashboard") || !strings.Contains(body, "IP address") {
				t.Errorf("421 body = %q, want it to say how to open the dashboard", body)
			}
		}
	}
	if reloads.Load() != 0 {
		t.Errorf("a refused POST /api/reload ran the reload %d times", reloads.Load())
	}
}

func TestHostCheck_HintNamesTheMachine(t *testing.T) {
	// A1: the 421 body names the machine's .local name with the port the
	// request used; without machine names it says to use the IP address.
	s, h, _ := secServer(t)
	body := serve(h, http.MethodGet, "/", "evil.example:8080", nil, "").Body.String()
	if !strings.Contains(body, "http://raspberrypi.local:8080") {
		t.Errorf("body = %q, want it to name http://raspberrypi.local:8080", body)
	}
	s.hostnames = nil
	h = s.handler()
	rec := serve(h, http.MethodGet, "/", "evil.example", nil, "")
	if rec.Code != http.StatusMisdirectedRequest || !strings.Contains(rec.Body.String(), "IP address") {
		t.Errorf("without names: %d %q, want 421 that names the IP address", rec.Code, rec.Body.String())
	}
	if rec := serve(h, http.MethodGet, "/", "raspberrypi", nil, ""); rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("without names, Host raspberrypi = %d, want 421", rec.Code)
	}
}

func TestLocalHostnames(t *testing.T) {
	// A1: the machine's names are os.Hostname in lowercase, its first label,
	// and the first label with ".local".
	name, err := os.Hostname()
	if err != nil || name == "" {
		t.Skip("no hostname")
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	short, _, _ := strings.Cut(name, ".")
	got := localHostnames()
	for _, want := range []string{name, short, short + ".local"} {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		if !found {
			t.Errorf("localHostnames() = %q, want it to include %q", got, want)
		}
	}
	for _, g := range got {
		if g != name && g != short && g != short+".local" {
			t.Errorf("localHostnames() includes %q, which is none of the three names", g)
		}
	}
	// New fills the list, so the machine's real name works on a real server.
	s := New(stats.New(), nil, blocklist.NewStore(), nil, func() bool { return true })
	if rec := serve(s.handler(), http.MethodGet, "/healthz", strings.ToUpper(short)+".local:8080", nil, ""); rec.Code != http.StatusOK {
		t.Errorf("GET /healthz with the machine's .local name = %d, want 200", rec.Code)
	}
}

func TestCrossOriginProtection(t *testing.T) {
	// A2 (b/074): a state-changing request that the browser marks as
	// cross-site or same-site, or whose Origin host differs from Host, gets
	// 403 and does nothing, and a request without these headers (curl)
	// passes.
	const host = "127.0.0.1:8080"
	cases := []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"no browser headers", nil, http.StatusOK},
		{"same-origin", map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusOK},
		{"cross-site", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"same-site", map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		{"foreign Origin", map[string]string{"Origin": "http://evil.example"}, http.StatusForbidden},
		{"Origin on another port", map[string]string{"Origin": "http://127.0.0.1:9999"}, http.StatusForbidden},
		{"own Origin", map[string]string{"Origin": "http://" + host}, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, h, reloads := secServer(t)
			rec := serve(h, http.MethodPost, "/api/reload", host, tc.hdr, "")
			if rec.Code != tc.want {
				t.Errorf("POST /api/reload = %d, want %d", rec.Code, tc.want)
			}
			wantReloads := int64(0)
			if tc.want == http.StatusOK {
				wantReloads = 1
			}
			if reloads.Load() != wantReloads {
				t.Errorf("reload ran %d times, want %d", reloads.Load(), wantReloads)
			}

			hdr := map[string]string{"Content-Type": "application/json"}
			for k, v := range tc.hdr {
				hdr[k] = v
			}
			rec = serve(h, http.MethodPost, "/api/allowlist", host, hdr, `{"domain":"tracker.example.com"}`)
			if rec.Code != tc.want {
				t.Errorf("POST /api/allowlist = %d, want %d", rec.Code, tc.want)
			}
			if allowed := s.store.AllowlistLen() == 1; allowed != (tc.want == http.StatusOK) {
				t.Errorf("allowlist size = %d after a %d reply", s.store.AllowlistLen(), rec.Code)
			}
			rec = serve(h, http.MethodDelete, "/api/allowlist?domain=tracker.example.com", host, tc.hdr, "")
			if rec.Code != tc.want {
				t.Errorf("DELETE /api/allowlist = %d, want %d", rec.Code, tc.want)
			}
			rec = serve(h, http.MethodPost, "/api/purge", host, hdr, `{"confirm": true}`)
			if tc.want == http.StatusForbidden && rec.Code != http.StatusForbidden {
				t.Errorf("POST /api/purge = %d, want 403", rec.Code)
			}
		})
	}
}

func TestAllowlistAdd_RequiresJSON(t *testing.T) {
	// A3: POST /api/allowlist needs Content-Type application/json, with or
	// without parameters; anything else is 415 and changes nothing.
	cases := map[string]int{
		"":                                  http.StatusUnsupportedMediaType,
		"text/plain":                        http.StatusUnsupportedMediaType,
		"text/plain;charset=UTF-8":          http.StatusUnsupportedMediaType,
		"application/x-www-form-urlencoded": http.StatusUnsupportedMediaType,
		"multipart/form-data; boundary=x":   http.StatusUnsupportedMediaType,
		"application/json-patch+json":       http.StatusUnsupportedMediaType,
		"application/json":                  http.StatusOK,
		"application/json; charset=utf-8":   http.StatusOK,
		"Application/JSON":                  http.StatusOK,
	}
	for ct, want := range cases {
		t.Run(ct, func(t *testing.T) {
			s, h, _ := secServer(t)
			hdr := map[string]string{}
			if ct != "" {
				hdr["Content-Type"] = ct
			}
			rec := serve(h, http.MethodPost, "/api/allowlist", "127.0.0.1:8080", hdr, `{"domain":"ads.example.com"}`)
			if rec.Code != want {
				t.Errorf("Content-Type %q = %d, want %d", ct, rec.Code, want)
			}
			if got := s.store.AllowlistLen(); (got == 1) != (want == http.StatusOK) {
				t.Errorf("allowlist size = %d after %d", got, rec.Code)
			}
		})
	}
}

// assertSecurityHeaders checks A4 on one response.
func assertSecurityHeaders(t *testing.T, what string, h http.Header) {
	t.Helper()
	want := map[string]string{
		"Cache-Control":                "no-store",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"X-Frame-Options":              "DENY",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s: %s = %q, want %q", what, k, got, v)
		}
	}
	csp := h.Get("Content-Security-Policy")
	for _, d := range []string{"frame-ancestors 'none'", "connect-src 'self'", "base-uri 'none'", "object-src 'none'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("%s: Content-Security-Policy %q lacks %s", what, csp, d)
		}
	}
}

func TestSecurityHeaders_EveryResponse(t *testing.T) {
	// A4: every response carries the security headers: success, error, the
	// static page, /metrics, the probes, pprof, a 404, a 403 from the
	// cross-origin check, 415, 400, and 503.
	_, h, _ := secServer(t)
	const host = "127.0.0.1:8080"
	cases := []struct {
		name, method, path string
		hdr                map[string]string
		body               string
	}{
		{"stats", http.MethodGet, "/api/stats", nil, ""},
		{"page", http.MethodGet, "/", nil, ""},
		{"page file", http.MethodGet, "/index.html", nil, ""},
		{"metrics", http.MethodGet, "/metrics", nil, ""},
		{"healthz", http.MethodGet, "/healthz", nil, ""},
		{"readyz", http.MethodGet, "/readyz", nil, ""},
		{"pprof", http.MethodGet, "/debug/pprof/", nil, ""},
		{"history", http.MethodGet, "/api/history", nil, ""},
		{"export", http.MethodGet, "/api/queries/export", nil, ""},
		{"cross-site 403", http.MethodPost, "/api/reload", map[string]string{"Sec-Fetch-Site": "cross-site"}, ""},
		{"415", http.MethodPost, "/api/allowlist", map[string]string{"Content-Type": "text/plain"}, "x"},
		{"400", http.MethodGet, "/api/check?domain=", nil, ""},
		{"purge 503", http.MethodPost, "/api/purge", map[string]string{"Content-Type": "application/json"}, `{"confirm": true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(h, tc.method, tc.path, host, tc.hdr, tc.body)
			assertSecurityHeaders(t, tc.method+" "+tc.path+" ("+http.StatusText(rec.Code)+")", rec.Header())
		})
	}
}

func TestSecurityHeaders_MisdirectedRequest(t *testing.T) {
	// A4 says every response carries the headers; the 421 from the Host
	// check is a response too.
	//
	// POSSIBLE BUG: this test fails against the CL 93 code. secure() writes
	// the 421 before it sets the headers. The 421 body holds no query data,
	// so the effect is small. Reported to the maintainer; do not weaken this
	// test without agreement.
	_, h, _ := secServer(t)
	rec := serve(h, http.MethodGet, "/api/stats", "evil.example", nil, "")
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", rec.Code)
	}
	assertSecurityHeaders(t, "421 reply", rec.Header())
}

func TestSecurityHeaders_StaticNotFound(t *testing.T) {
	// A4 says every response carries the headers; a 404 from the static
	// file server is a response too.
	//
	// POSSIBLE BUG: this test fails against the CL 93 code. http.FileServer
	// deletes Cache-Control from its error replies, so the 404 for an unknown
	// path has no "Cache-Control: no-store". The other headers stay. Reported
	// to the maintainer; do not weaken this test without agreement.
	_, h, _ := secServer(t)
	rec := serve(h, http.MethodGet, "/no-such-page", "127.0.0.1:8080", nil, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	assertSecurityHeaders(t, "static 404", rec.Header())
}

func TestSecurityHeaders_RealServer(t *testing.T) {
	// A1 and A4 over a real connection: a browser on the same machine reaches
	// the dashboard by IP address, and the reply has the headers.
	_, srv := newTestServer(t, nil)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", resp.StatusCode)
	}
	assertSecurityHeaders(t, "GET /", resp.Header)
}
