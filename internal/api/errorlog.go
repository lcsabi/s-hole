package api

import (
	"log"
	"net/netip"
	"regexp"
	"strings"
)

// net/http writes some lines of its own: "http: panic serving <addr>: <value>"
// with a stack trace when a handler panics, "http: TLS handshake error from
// <addr>: ..." once the server uses TLS, and accept errors. Without an
// ErrorLog these lines go through the log package to slog's default handler
// at INFO, with no pkg attribute and with the client's ip:port (b/103). The
// application log never names a client (redact.NetError does the same for
// the errors that s-hole logs itself), so newErrorLog sends each line through
// the api logger at ERROR and replaces every address in it with "client".
// The stack trace stays: it holds function names and pointers, no request
// data. http.ErrAbortHandler writes no line, so it stays silent.

// addrPattern finds the addresses that net/http prints: an IPv4 address and
// a bracketed IPv6 address, each with an optional port (the net.JoinHostPort
// form), and a bare IPv6 address, which a panic value can hold. redactAddrs
// replaces a match only when netip parses it, so a time of day or a
// three-part version stays as it is (a four-part version such as 1.2.3.4 is
// an IPv4 address and is replaced).
var addrPattern = regexp.MustCompile(
	`\[[0-9A-Fa-f:.]+(?:%[^\]\s]+)?\](?::\d+)?` + // [2001:db8::1]:5678, [fe80::1%eth0]
		`|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b` + // 192.0.2.1:5678, 192.0.2.1
		`|[0-9A-Fa-f]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f.]*(?:%[0-9A-Za-z_.-]+)?`, // 2001:db8::1, ::1, ::ffff:192.0.2.1
)

// redactAddrs replaces every IP address in s, with or without a port, with
// "client".
func redactAddrs(s string) string {
	return addrPattern.ReplaceAllStringFunc(s, func(m string) string {
		switch {
		case strings.HasPrefix(m, "["):
			if isAddr(m[1:strings.IndexByte(m, ']')]) {
				return "client"
			}
		case strings.Count(m, ":") <= 1: // IPv4, with or without a port
			if host, _, _ := strings.Cut(m, ":"); isAddr(host) {
				return "client"
			}
		default:
			// A bare IPv6 match can take in the colon of the text around it:
			// "dial 2001:db8::1: refused" or "from:2001:db8::1". Try the
			// match with one colon at either end left outside the address.
			for _, pre := range []string{"", ":"} {
				for _, post := range []string{"", ":"} {
					addr, ok := strings.CutPrefix(m, pre)
					if ok {
						addr, ok = strings.CutSuffix(addr, post)
					}
					if ok && isAddr(addr) {
						return pre + "client" + post
					}
				}
			}
		}
		return m
	})
}

// isAddr reports whether s is an IP address (IPv4, IPv6, or IPv6 with a
// zone).
func isAddr(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// errorLogWriter is the writer of the admin server's ErrorLog. The log
// package calls Write once for each message that net/http logs; a panic
// message holds the stack trace on the lines after the first.
type errorLogWriter struct{}

func (errorLogWriter) Write(p []byte) (int, error) {
	text := redactAddrs(strings.TrimRight(string(p), "\n"))
	msg, stack, _ := strings.Cut(text, "\n")
	attrs := []any{"detail", msg}
	if stack != "" {
		attrs = append(attrs, "stack", stack)
	}
	logger.Error("admin HTTP server error", attrs...)
	return len(p), nil
}

// newErrorLog returns the ErrorLog for the admin http.Server.
func newErrorLog() *log.Logger {
	return log.New(errorLogWriter{}, "", 0)
}
