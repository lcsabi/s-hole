//go:build !windows

package service

import "log/slog"

// NewEventLogHandler is unsupported off Windows. cmd/s-hole/main.go only calls
// it when IsWindowsService() is true (always false here), but the symbol must
// exist so main compiles with no platform conditionals of its own. This
// mirrors the no-op stub pattern in svc_other.go.
func NewEventLogHandler() (slog.Handler, error) { return nil, errNotSupported }
