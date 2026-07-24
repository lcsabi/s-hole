package cache

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs the cache test suite under goleak, which fails the package
// if any goroutine outlives the tests. The cache spawns a background
// cleanup goroutine that must be reclaimed by Cache.Close(); this guard
// catches a regression where a test (or Close itself) forgets to stop it.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
