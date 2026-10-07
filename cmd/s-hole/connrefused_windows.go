//go:build windows

package main

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// connRefused reports whether err is a refused TCP connection: nothing
// listens on the address. Windows reports it as WSAECONNREFUSED (10061), not
// as syscall.ECONNREFUSED, so the Unix check alone never matched there and
// an offline purge failed instead of deleting the files (b/094).
func connRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED) || errors.Is(err, syscall.ECONNREFUSED)
}
