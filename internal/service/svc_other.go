//go:build !windows

// Non-Windows stubs for the service package. They allow cmd/s-hole/main.go to call
// into service unconditionally; the install/start/stop subcommands return
// a not-supported error pointing operators at systemd instead.

package service

import "errors"

var errNotSupported = errors.New("service management is only supported on Windows; use systemd on Linux")

// IsWindowsService always returns false off Windows.
func IsWindowsService() bool { return false }

// Run on non-Windows simply invokes fn synchronously; the stop callback
// is unused because no SCM exists to send a stop control.
func Run(fn, _ func()) error { fn(); return nil }

// Install is unsupported off Windows.
func Install(_ string) error { return errNotSupported }

// Uninstall is unsupported off Windows.
func Uninstall() error { return errNotSupported }

// Start is unsupported off Windows.
func Start() error { return errNotSupported }

// Stop is unsupported off Windows.
func Stop() error { return errNotSupported }
