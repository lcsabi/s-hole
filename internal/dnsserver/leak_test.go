package dnsserver

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs the dnsserver test suite under goleak, which fails the
// package if any goroutine outlives the tests. The UDP and TCP listeners
// started by Server.Start must be reclaimed by Server.Shutdown; this guard
// catches a regression where a test leaves a listener (or an in-flight
// forward) running after it returns.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
