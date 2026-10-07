//go:build !windows

package main

import "syscall"

// restrictUmask makes every file s-hole creates readable by its own user
// only: the query database and its -wal and -shm files, the query log file,
// and the blocklist cache. Without it, the usual umask of 022 left the query
// history readable by every account on the host (b/076). The systemd unit
// sets UMask=0077 as well; this covers a run from a terminal or in Docker.
func restrictUmask() {
	syscall.Umask(0o077)
}
