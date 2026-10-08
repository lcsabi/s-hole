package api

import (
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// SEC-19: the dashboard script is a separate embedded file (static/app.js),
// the page has no inline script and no inline event handler, and the
// Content-Security-Policy allows script only from the page's own origin.

// cspDirectives splits a Content-Security-Policy value into its directives,
// keyed by name.
func cspDirectives(csp string) map[string][]string {
	out := map[string][]string{}
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(d)
		if len(f) == 0 {
			continue
		}
		out[strings.ToLower(f[0])] = f[1:]
	}
	return out
}

// assertScriptSrcSelf fails unless the response's script-src directive is
// exactly 'self': no 'unsafe-inline', no 'unsafe-eval', no nonce, no hash,
// no host, and no wildcard.
func assertScriptSrcSelf(t *testing.T, what string, h http.Header) {
	t.Helper()
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		t.Errorf("%s: no Content-Security-Policy header", what)
		return
	}
	dirs := cspDirectives(csp)
	src, ok := dirs["script-src"]
	if !ok {
		t.Errorf("%s: Content-Security-Policy %q has no script-src directive", what, csp)
		return
	}
	if len(src) != 1 || src[0] != "'self'" {
		t.Errorf("%s: script-src = %q, want exactly 'self'", what, src)
	}
	// script-src-elem and script-src-attr override script-src for elements
	// and inline handlers; neither may open the policy again.
	for _, name := range []string{"script-src-elem", "script-src-attr"} {
		if v, ok := dirs[name]; ok {
			t.Errorf("%s: Content-Security-Policy sets %s %q, which overrides script-src", what, name, v)
		}
	}
	if strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("%s: Content-Security-Policy %q allows 'unsafe-eval'", what, csp)
	}
}

func TestCSP_ScriptSrcIsSelfOnEveryResponse(t *testing.T) {
	// SEC-19: every response, the page, the script, the API, the probes, a
	// 404, and the refusals, carries a CSP whose script-src is exactly 'self'.
	_, h, _ := secServer(t)
	cases := []struct {
		name, method, path, host string
		hdr                      map[string]string
		body                     string
	}{
		{"page", http.MethodGet, "/", fetchHost, nil, ""},
		{"page file", http.MethodGet, "/index.html", fetchHost, nil, ""},
		{"script", http.MethodGet, "/app.js", fetchHost, nil, ""},
		{"stats", http.MethodGet, "/api/stats", fetchHost, nil, ""},
		{"queries", http.MethodGet, "/api/queries", fetchHost, nil, ""},
		{"metrics", http.MethodGet, "/metrics", fetchHost, nil, ""},
		{"healthz", http.MethodGet, "/healthz", fetchHost, nil, ""},
		{"pprof", http.MethodGet, "/debug/pprof/", fetchHost, nil, ""},
		{"static 404", http.MethodGet, "/no-such-page", fetchHost, nil, ""},
		{"415", http.MethodPost, "/api/allowlist", fetchHost, map[string]string{"Content-Type": "text/plain"}, "x"},
		{"cross-site POST 403", http.MethodPost, "/api/reload", fetchHost, map[string]string{"Sec-Fetch-Site": "cross-site"}, ""},
		{"421", http.MethodGet, "/", "evil.example", nil, ""},
	}
	for _, tc := range cases {
		rec := serve(h, tc.method, tc.path, tc.host, tc.hdr, tc.body)
		assertScriptSrcSelf(t, tc.name+" ("+http.StatusText(rec.Code)+")", rec.Header())
	}
}

func TestCSP_StylesAndOtherDirectivesStay(t *testing.T) {
	// SEC-19 keeps style-src 'unsafe-inline' (the page still has inline
	// styles) and the rest of the policy limited to the page's own origin.
	_, h, _ := secServer(t)
	dirs := cspDirectives(serve(h, http.MethodGet, "/", fetchHost, nil, "").Header().Get("Content-Security-Policy"))
	want := map[string]string{
		"default-src":     "'self'",
		"connect-src":     "'self'",
		"object-src":      "'none'",
		"base-uri":        "'none'",
		"frame-ancestors": "'none'",
	}
	for k, v := range want {
		if got := strings.Join(dirs[k], " "); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	style := strings.Join(dirs["style-src"], " ")
	if !strings.Contains(style, "'self'") || !strings.Contains(style, "'unsafe-inline'") {
		t.Errorf("style-src = %q, want 'self' and 'unsafe-inline'", style)
	}
}

// getStatic returns the body of a static file served by the dashboard.
func getStatic(t *testing.T, path string) (int, http.Header, string) {
	t.Helper()
	_, h, _ := secServer(t)
	rec := serve(h, http.MethodGet, path, fetchHost, nil, "")
	return rec.Code, rec.Header(), rec.Body.String()
}

var (
	scriptTag   = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script\s*>`)
	srcAttr     = regexp.MustCompile(`(?i)\bsrc\s*=\s*["']?([^"'\s>]+)`)
	openTag     = regexp.MustCompile(`(?s)<[a-zA-Z][^>]*>`)
	handlerAttr = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	idAttr      = regexp.MustCompile(`\bid\s*=\s*["']([^"']+)["']`)
)

func TestDashboard_NoInlineScript(t *testing.T) {
	// SEC-19: the served page holds no inline <script> body and no inline
	// event-handler attribute, and loads its script from app.js on its own
	// origin. With script-src 'self', inline script would not run and the
	// page would break.
	code, _, page := getStatic(t, "/")
	if code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", code)
	}
	tags := scriptTag.FindAllStringSubmatch(page, -1)
	if len(tags) == 0 {
		t.Fatal("index.html has no <script> element, want one that loads app.js")
	}
	loadsApp := false
	for _, m := range tags {
		if strings.TrimSpace(m[2]) != "" {
			t.Errorf("index.html has an inline script body: %.80q", m[2])
		}
		src := srcAttr.FindStringSubmatch(m[1])
		if src == nil {
			t.Errorf("index.html has a <script%s> without src", m[1])
			continue
		}
		if strings.Contains(src[1], "://") || strings.HasPrefix(src[1], "//") {
			t.Errorf("index.html loads script %q from another origin", src[1])
		}
		if strings.TrimPrefix(src[1], "/") == "app.js" {
			loadsApp = true
		}
	}
	if !loadsApp {
		t.Error("index.html does not load app.js")
	}
	for _, tag := range openTag.FindAllString(page, -1) {
		if handlerAttr.MatchString(tag) {
			t.Errorf("index.html has an inline event handler: %.120q", tag)
		}
	}
	if strings.Contains(strings.ToLower(page), "javascript:") {
		t.Error("index.html has a javascript: URL, which script-src 'self' blocks")
	}
}

func TestDashboard_ScriptNeedsNoUnsafeDirective(t *testing.T) {
	// SEC-19: app.js must not depend on what script-src 'self' blocks: an
	// inline handler in the HTML it builds, a javascript: URL, eval, or a
	// string passed to setTimeout or setInterval. Each would fail silently
	// in the browser (a CSP violation in the console).
	code, _, js := getStatic(t, "/app.js")
	if code != http.StatusOK {
		t.Fatalf("GET /app.js = %d, want 200", code)
	}
	checks := map[string]*regexp.Regexp{
		"inline handler in built HTML": regexp.MustCompile(`(?i)\son[a-z]+=["'\\$]`),
		"javascript: URL":              regexp.MustCompile(`(?i)javascript:`),
		"eval":                         regexp.MustCompile(`\beval\s*\(`),
		"new Function":                 regexp.MustCompile(`\bnew\s+Function\s*\(`),
		"string timer":                 regexp.MustCompile(`\bset(Timeout|Interval)\s*\(\s*["'` + "`" + `]`),
	}
	for what, re := range checks {
		if loc := re.FindStringIndex(js); loc != nil {
			t.Errorf("app.js uses %s: %.80q", what, js[loc[0]:])
		}
	}
}

func TestDashboard_AppJSServed(t *testing.T) {
	// SEC-19: GET /app.js serves the script with a JavaScript Content-Type
	// (nosniff makes the browser refuse any other type) and the security
	// headers.
	code, hdr, js := getStatic(t, "/app.js")
	if code != http.StatusOK {
		t.Fatalf("GET /app.js = %d, want 200", code)
	}
	mt, _, err := mime.ParseMediaType(hdr.Get("Content-Type"))
	if err != nil || (mt != "text/javascript" && mt != "application/javascript") {
		t.Errorf("GET /app.js Content-Type = %q, want a JavaScript type", hdr.Get("Content-Type"))
	}
	if strings.TrimSpace(js) == "" || strings.HasPrefix(strings.TrimSpace(js), "<") {
		t.Errorf("GET /app.js body does not look like a script: %.80q", js)
	}
	assertSecurityHeaders(t, "GET /app.js", hdr)
	assertScriptSrcSelf(t, "GET /app.js", hdr)
}

func TestDashboard_ScriptElementIDsExist(t *testing.T) {
	// SEC-19: every element id that app.js looks up exists in index.html. A
	// renamed id breaks the page without an error in the Go tests.
	_, _, page := getStatic(t, "/")
	_, _, js := getStatic(t, "/app.js")
	ids := map[string]bool{}
	for _, m := range idAttr.FindAllStringSubmatch(page, -1) {
		ids[m[1]] = true
	}
	lookups := []*regexp.Regexp{
		regexp.MustCompile(`\$\(\s*['"]([^'"]+)['"]\s*\)`),
		regexp.MustCompile(`getElementById\(\s*['"]([^'"]+)['"]\s*\)`),
		regexp.MustCompile(`setTbody\(\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`querySelector(?:All)?\(\s*['"]#([A-Za-z][\w-]*)['"]\s*\)`),
	}
	used := map[string]bool{}
	for _, re := range lookups {
		for _, m := range re.FindAllStringSubmatch(js, -1) {
			used[m[1]] = true
		}
	}
	// The collapse buttons name the panel body they toggle.
	for _, m := range regexp.MustCompile(`data-collapse\s*=\s*["']([^"']+)["']`).FindAllStringSubmatch(page, -1) {
		used[m[1]] = true
	}
	if len(used) < 10 {
		t.Fatalf("found only %d element lookups in app.js; the test patterns no longer match the script", len(used))
	}
	var missing []string
	for id := range used {
		if !ids[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("app.js looks up ids that index.html does not have: %q", missing)
	}
}
