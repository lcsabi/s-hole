//go:build windows

package main

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// This test runs only on Windows. CI runs Linux, so it is only compiled
// there (GOOS=windows go vet ./cmd/s-hole/).

func TestConnRefused_WindowsErrno(t *testing.T) {
	// b/094: Windows reports a refused connection as WSAECONNREFUSED
	// (10061), not as syscall.ECONNREFUSED. It counts as refused, bare and
	// wrapped the way the net package returns it (*net.OpError around
	// *os.SyscallError "connectex"). Other socket errors do not.
	wrap := func(errno windows.Errno) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", errno)}
	}
	if windows.WSAECONNREFUSED != 10061 {
		t.Fatalf("WSAECONNREFUSED = %d, want 10061", windows.WSAECONNREFUSED)
	}
	for _, err := range []error{
		windows.WSAECONNREFUSED,
		os.NewSyscallError("connectex", windows.WSAECONNREFUSED),
		wrap(windows.WSAECONNREFUSED),
	} {
		if !connRefused(err) {
			t.Errorf("connRefused(%v) = false, want true", err)
		}
	}
	for _, errno := range []windows.Errno{windows.WSAECONNRESET, windows.WSAETIMEDOUT, windows.WSAEHOSTUNREACH, windows.WSAENETUNREACH, windows.WSAEACCES} {
		if connRefused(errno) || connRefused(wrap(errno)) {
			t.Errorf("connRefused(%v) = true, want false", errno)
		}
	}
}
