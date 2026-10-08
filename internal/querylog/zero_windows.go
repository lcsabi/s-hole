//go:build windows

package querylog

import "os"

// openFlags adds nothing on Windows: ZeroFile relies on the Lstat check and
// os.SameFile there.
const openFlags = 0

// linkCount returns 1: os.FileInfo on Windows does not carry the link count.
func linkCount(os.FileInfo) uint64 { return 1 }
