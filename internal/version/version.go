// Package version holds the build-time identity of the binary.
//
// The three vars below are written at link time via -ldflags="-X ...". The
// Makefile populates them from `git describe`, `git rev-parse`, and the
// current UTC timestamp; release pipelines should do the same. Source
// builds without those flags fall back to the placeholder values, which
// is fine for `go install`-style installs.
package version

import "runtime"

// Version is the human-readable version (e.g. "v1.0.0", "v1.0.0-dirty",
// or "dev"). Injected via -ldflags="-X 'github.com/lcsabi/s-hole/internal/version.Version=...'".
var Version = "dev"

// Commit is the short git commit hash. Injected the same way as Version.
var Commit = "unknown"

// BuildDate is the build timestamp in RFC3339 UTC. Injected the same way.
var BuildDate = "unknown"

// String returns a multi-line build identity suitable for `-version`
// output and for the startup log line.
func String() string {
	return "s-hole " + Version +
		"\n  commit:  " + Commit +
		"\n  built:   " + BuildDate +
		"\n  go:      " + runtime.Version() +
		"\n  os/arch: " + runtime.GOOS + "/" + runtime.GOARCH
}

// Info is the structured view of the three build-time vars. Returned by
// Short for callers that want to embed the build identity in a single
// log/event/header without memorising the field order.
type Info struct {
	Version   string
	Commit    string
	BuildDate string
}

// Short returns the build identity as a struct. Used by cmd/s-hole/main.go
// to attach version metadata to the startup log line in one shot and to
// hand the metadata to any subsystem that wants to surface it (e.g. an
// HTTP response header). Direct package-level reads (`version.Version`)
// remain available for callers that only want one field.
func Short() Info {
	return Info{Version: Version, Commit: Commit, BuildDate: BuildDate}
}
