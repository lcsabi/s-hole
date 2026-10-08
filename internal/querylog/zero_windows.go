//go:build windows

package querylog

import (
	"os"
	"syscall"
)

// openFlags adds nothing on Windows: ZeroFile relies on the Lstat check and
// os.SameFile there.
const openFlags = 0

// linkCount returns the number of hard links to the open file f. FileInfo on
// Windows does not carry it, so linkCount asks the file system through the
// handle. The offline purge runs as an administrator in the config folder,
// where the service account can create files, and a hard link there could
// point to a file that only an administrator can write (b/104).
func linkCount(f *os.File, _ os.FileInfo) (uint64, error) {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &info); err != nil {
		return 0, err
	}
	return uint64(info.NumberOfLinks), nil
}
