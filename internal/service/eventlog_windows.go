//go:build windows

package service

import (
	"log/slog"

	"golang.org/x/sys/windows/svc/eventlog"
)

// NewEventLogHandler opens the s-hole event-log source and returns a slog
// handler that writes to it. main installs this handler in place of the stdout
// handler when the process runs under the SCM, where stdout is discarded. The
// caller falls back to stdout if this returns an error, so a failure to open
// the source never leaves the process with no logger.
func NewEventLogHandler() (slog.Handler, error) {
	el, err := eventlog.Open(svcName)
	if err != nil {
		return nil, err
	}
	return newEventLogHandler(el), nil
}
