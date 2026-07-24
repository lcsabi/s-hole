package querylog

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs the querylog test suite under goleak, which fails the
// package if any goroutine outlives the tests. DBLogger runs a batch-writer
// goroutine and (when retention is enabled) an hourly prune goroutine, both
// of which must be reclaimed by DBLogger.Close(); this guard catches a
// regression where a test forgets to Close or Close fails to join them.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
