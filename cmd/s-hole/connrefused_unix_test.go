//go:build !windows

package main

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestConnRefused_UnixErrno(t *testing.T) {
	// b/094: ECONNREFUSED counts as refused, bare and wrapped the way the
	// net package returns it (*net.OpError around *os.SyscallError). Other
	// socket errors, such as a reset or a timeout, do not.
	wrap := func(errno syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
	}
	for _, err := range []error{
		syscall.ECONNREFUSED,
		os.NewSyscallError("connect", syscall.ECONNREFUSED),
		wrap(syscall.ECONNREFUSED),
	} {
		if !connRefused(err) {
			t.Errorf("connRefused(%v) = false, want true", err)
		}
	}
	for _, errno := range []syscall.Errno{syscall.ECONNRESET, syscall.ETIMEDOUT, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EACCES} {
		if connRefused(errno) || connRefused(wrap(errno)) {
			t.Errorf("connRefused(%v) = true, want false", errno)
		}
	}
}
