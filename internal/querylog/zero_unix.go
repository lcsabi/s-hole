//go:build !windows

package querylog

import (
	"os"
	"syscall"
)

// openFlags makes ZeroFile fail on a symbolic link that replaced the file
// after the Lstat, and not wait on a named pipe.
const openFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// linkCount returns the number of hard links to the file, from its FileInfo.
func linkCount(_ *os.File, fi os.FileInfo) (uint64, error) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink), nil
	}
	return 1, nil
}
