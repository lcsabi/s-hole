package api

import (
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

// The admin server has no login (a settled scope decision, see the ROADMAP
// non-goals). The checks in this file are not authentication. They stop a web
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
	// The embedded page uses inline scripts, inline event handlers, and
	// inline styles, so script-src and style-src allow inline code. Everything
	// else is limited to the page's own origin: it can fetch only from the
	// admin server, cannot be framed, and cannot change its base URL.
	"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
		"style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; " +
		"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
}

// secure wraps the routes with the Host check, the security headers, and the
// cross-origin check, in that order. Every route goes through it, /metrics
// and the probes included: Prometheus, Docker, and Kubernetes reach s-hole by
// IP address, which the Host check accepts.
func (s *Server) secure(next http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "s-hole refused a cross-site request: the dashboard accepts changes only from its own page", http.StatusForbidden)
	}))
	protected := cop.Handler(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The headers come first, so the 421 below carries them too.
		h := w.Header()
		for k, v := range securityHeaders {
			h.Set(k, v)
		}
		if !s.hostAllowed(r.Host) {
			http.Error(w, s.hostHint(r), http.StatusMisdirectedRequest)
			return
		}
		protected.ServeHTTP(w, r)
	})
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
