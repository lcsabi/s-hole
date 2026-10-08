//go:build !windows

package querylog

import (
	"os"
	"syscall"
)

// openFlags makes ZeroFile fail on a symbolic link that replaced the file
// after the Lstat, and not wait on a named pipe.
const openFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// linkCount returns the number of hard links to the file.
func linkCount(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}
