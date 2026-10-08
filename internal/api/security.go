package api

import (
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

// The admin server has no login yet (device pairing is planned, ROADMAP
// #42). The checks in this file are not authentication. They stop a web
// page in the operator's own browser from using that browser to reach the
// server, which binding to localhost alone does not stop:
//
//   - DNS rebinding: a page on attacker.example points its own name at the
//     admin server's address. The browser then treats the server as the
//     page's own origin and lets the page read the query history. The browser
//     still sends "Host: attacker.example", so the Host check refuses it.
//   - Cross-site requests: a page sends a "simple" POST (text/plain, no
//     preflight) to /api/allowlist and unblocks a tracker for the whole LAN.
//     http.CrossOriginProtection refuses a state-changing request that the
//     browser marks as cross-site.
//   - Cross-site reads: a page cannot read a GET reply from another origin,
//     but it can send the GET and time the reply (does the history hold a
//     domain?) or start exports. The Fetch Metadata check (fetchAllowed)
//     refuses a request that the browser marks as sent from another site,
//     except a link from another site that opens the dashboard page. A
//     browser marks requests only to a trustworthy origin, such as the
//     default 127.0.0.1 bind.
//
// The response headers keep query data out of the browser's disk cache, stop
// another page from framing the dashboard, and limit what the page may load
// or send if a script injection ever slips through.

// securityHeaders are set on every response.
var securityHeaders = map[string]string{
	// The dashboard and the API serve query history: keep every response out
	// of the browser and proxy caches.
	"Cache-Control":                "no-store",
	"X-Content-Type-Options":       "nosniff",
	"Referrer-Policy":              "no-referrer",
	"X-Frame-Options":              "DENY",
	"Cross-Origin-Resource-Policy": "same-origin",
	// The page script is a separate file (static/app.js), so script-src
	// allows no inline script and no inline event handler: an injected
	// <script> or onerror attribute does not run. The page still uses inline
	// styles, so style-src allows them. Everything else is limited to the
	// page's own origin: it can fetch only from the admin server, cannot be
	// framed, and cannot change its base URL.
	"Content-Security-Policy": "default-src 'self'; script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; " +
		"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
}

// secure wraps the routes with the security headers, the Host check, the
// Fetch Metadata check, and the cross-origin check, in that order. Every route
// goes through it, /metrics and the probes included: Prometheus, Docker, and
// Kubernetes reach s-hole by IP address, which the Host check accepts, and
// send no Sec-Fetch-Site header, which the Fetch Metadata check accepts.
func (s *Server) secure(next http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "s-hole refused a cross-site request: the dashboard accepts changes only from its own page", http.StatusForbidden)
	}))
	protected := cop.Handler(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The headers come first, so the 421 and 403 replies below carry them too.
		h := w.Header()
		for k, v := range securityHeaders {
			h.Set(k, v)
		}
		if !s.hostAllowed(r.Host) {
			http.Error(w, s.hostHint(r), http.StatusMisdirectedRequest)
			return
		}
		if !fetchAllowed(r) {
			http.Error(w, "s-hole refused a request from another site. Open the dashboard directly: type its address or use a bookmark", http.StatusForbidden)
			return
		}
		protected.ServeHTTP(w, r)
	})
}

// fetchAllowed is a Fetch Metadata resource isolation policy (SEC-10). A
// browser sends Sec-Fetch-Site on a request to a trustworthy origin (HTTPS,
// localhost, or a loopback address): "same-origin" from the dashboard itself,
// "none" when the operator types the URL or opens a bookmark. "same-site" and
// "cross-site" come from another page, and "same-site" includes another port
// on the same address (a second web app on the same host). Such a request is
// refused, with one exception: a link from another page may open the
// dashboard page itself (a top-level GET navigation to "/"), which shows no
// data until the page fetches it from its own origin. An unknown value is
// refused. A request without the header passes: curl, Prometheus, the
// healthcheck, an old browser, and a browser that opens the dashboard over
// plain HTTP by a LAN address, which gets no header. So this check protects
// the default 127.0.0.1 bind; for a LAN-exposed dashboard over plain HTTP the
// Host check and CrossOriginProtection stay the only defenses.
func fetchAllowed(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	}
	return r.Method == http.MethodGet && r.URL.Path == "/" &&
		r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
		r.Header.Get("Sec-Fetch-Dest") == "document"
}

// localHostnames returns the names that address this machine and that an
// attacker's page cannot send: the hostname the OS reports, its first label,
// and that label with ".local" (the mDNS name, as in raspberrypi.local). A
// rebinding page always sends its own name, so allowing the machine's own
// names gives the attacker nothing. A prefix match such as "raspberrypi.*"
// would not be safe, because anyone can register raspberrypi.example.
func localHostnames() []string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return nil
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	short, _, _ := strings.Cut(name, ".")
	out := []string{name}
	if short != name {
		out = append(out, short)
	}
	return append(out, short+".local")
}

// hostAllowed reports whether a request's Host header names this server: an
// IP address (with any port), "localhost", or one of the machine's own names
// (see localHostnames). An empty Host is allowed: every browser sends one, so
// a request without it cannot come from the browser attacks above.
func (s *Server) hostAllowed(hostHeader string) bool {
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if host == "" {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	host = strings.ToLower(host)
	if host == "localhost" {
		return true
	}
	for _, n := range s.hostnames {
		if host == n {
			return true
		}
	}
	return false
}

// hostHint is the body of the 421 reply: it says how to open the dashboard.
func (s *Server) hostHint(r *http.Request) string {
	port := ""
	if _, p, err := net.SplitHostPort(r.Host); err == nil {
		port = ":" + p
	}
	msg := "s-hole answers only requests addressed to its IP address or to localhost"
	if len(s.hostnames) > 0 {
		local := s.hostnames[len(s.hostnames)-1]
		msg += ", or to this machine's name. Open the dashboard as http://" + local + port + " or by IP address"
	} else {
		msg += ". Open the dashboard by IP address"
	}
	return msg
}

// isJSON reports whether the request body is declared as JSON. A browser
// can send a cross-site POST without a preflight only as text/plain, a form
// encoding, or multipart, so requiring application/json on a JSON endpoint
// also blocks the requests that CrossOriginProtection cannot see (an old
// browser that sends neither Sec-Fetch-Site nor Origin).
func isJSON(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// keepNoStore wraps the static file server. http.FileServer deletes
// Cache-Control from its error replies (a 404 for an unknown path, for
// example), so noStoreWriter sets it again before the status line.
func keepNoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(noStoreWriter{w}, r)
	})
}

type noStoreWriter struct{ http.ResponseWriter }

func (w noStoreWriter) WriteHeader(code int) {
	w.Header().Set("Cache-Control", securityHeaders["Cache-Control"])
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w noStoreWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
