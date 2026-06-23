//go:build !windows

package service

import "errors"

var errNotSupported = errors.New("service management is only supported on Windows; use systemd on Linux")

func IsWindowsService() bool        { return false }
func Run(fn, _ func()) error        { fn(); return nil }
func Install(_ string) error        { return errNotSupported }
func Uninstall() error              { return errNotSupported }
func Start() error                  { return errNotSupported }
func Stop() error                   { return errNotSupported }
