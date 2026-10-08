//go:build windows

package main

// restrictUmask does nothing on Windows, which has no umask. A file there
// takes the access list of its folder; `-service install` gives the config
// folder an access list for SYSTEM, the Administrators group, and the
// service (see internal/service).
func restrictUmask() {}
