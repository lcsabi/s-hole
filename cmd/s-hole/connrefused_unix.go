//go:build !windows

package main

import (
	"errors"
	"syscall"
)

// connRefused reports whether err is a refused TCP connection: nothing
// listens on the address.
func connRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
