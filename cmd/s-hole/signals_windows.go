//go:build windows

package main

import "os"

// reloadSignals is empty on Windows. SIGHUP is not a meaningful signal
// in the Windows process model; operators use POST /api/reload (or the
// dashboard reload button) to reload the DoT certificate and blocklists, or
// restart the service.
func reloadSignals() []os.Signal { return nil }

// isReloadSignal always returns false on Windows; see reloadSignals.
func isReloadSignal(_ os.Signal) bool { return false }
