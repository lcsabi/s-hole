//go:build !windows

package main

import (
	"os"
	"syscall"
)

// reloadSignals is the set of signals that should trigger a blocklist
// refresh rather than shutdown. On Unix this is SIGHUP, matching the
// long-standing convention for "reload config" — operators expect
// `kill -HUP $(pidof s-hole)` to work without needing the admin API.
func reloadSignals() []os.Signal {
	return []os.Signal{syscall.SIGHUP}
}

// isReloadSignal reports whether sig is one of reloadSignals. Kept as a
// helper so the dispatch in main.go has no platform-specific code.
func isReloadSignal(sig os.Signal) bool {
	return sig == syscall.SIGHUP
}
