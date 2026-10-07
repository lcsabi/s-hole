// Package redact hides secrets in values that s-hole shows: logs, /metrics,
// and the admin API.
package redact

import (
	"net/url"
	"strings"
)

// URL hides the parts of a URL that can hold a secret: the user info
// becomes "redacted" and the query string is replaced by "redacted". A URL
// that url.Parse rejects (a bad port, an open IPv6 bracket) can still hold
// user info, so that case is redacted by hand: everything before the last
// "@" in the authority is replaced. A string with neither part is returned
// unchanged. Logs, /metrics, and /api/stats show URLs through it, so a token
// in the user info or the query string of a blocklist or DoH URL never
// reaches them. A token in the path is not hidden.
func URL(u string) string {
	parsed, err := url.Parse(u)
	if err == nil {
		changed := false
		if parsed.User != nil {
			parsed.User = url.User("redacted")
			changed = true
		}
		if parsed.RawQuery != "" {
			parsed.RawQuery = "redacted"
			changed = true
		}
		if !changed {
			return u
		}
		return parsed.String()
	}
	scheme, rest, ok := strings.Cut(u, "://")
	if !ok {
		return u
	}
	authority, path, hasPath := strings.Cut(rest, "/")
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return u
	}
	out := scheme + "://redacted" + authority[at:]
	if hasPath {
		out += "/" + path
	}
	return out
}
