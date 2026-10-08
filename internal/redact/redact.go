// Package redact hides secrets and personal data in values that s-hole
// shows: logs, /metrics, and the admin API.
package redact

import (
	"errors"
	"net"
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

// NetError returns the text of err without the socket addresses in it. A
// read or write on a network connection fails with a *net.OpError, whose text
// holds the local and the remote address, for example "write tcp
// 127.0.0.1:8080->192.168.1.20:51234: write: broken pipe". The remote address
// is the client's, which must not reach the application log (b/078, b/099).
// NetError keeps the operation and the underlying error ("write: broken
// pipe") in place of the *net.OpError's text, and keeps any text that wraps
// it, so a wrapper must not add an address of its own. Every log of an error
// from a client connection goes through it.
func NetError(err error) string {
	var op *net.OpError
	if !errors.As(err, &op) {
		return err.Error()
	}
	if op.Err == nil {
		// (*net.OpError).Error dereferences Err, also through a wrapper's
		// Error, so neither can be called. The operation is all that is safe.
		return op.Op
	}
	safe := op.Op + ": " + op.Err.Error()
	full := err.Error()
	if inner := op.Error(); strings.Contains(full, inner) {
		return strings.ReplaceAll(full, inner, safe)
	}
	// The wrapping text does not quote the *net.OpError, so it can hold the
	// addresses in another form. Keep only the safe part.
	return safe
}
