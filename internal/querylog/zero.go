package querylog

import (
	"errors"
	"fmt"
	"os"
)

// ErrRefused matches the error of ZeroFile for a path that it refuses: a
// symbolic link, a file that is not a regular file, a file with more than
// one hard link, or a file that is not the one it should overwrite.
var ErrRefused = errors.New("refused")

// refusedError is a refusal; its text names the path and the reason.
type refusedError string

func (e refusedError) Error() string        { return string(e) }
func (e refusedError) Is(target error) bool { return target == ErrRefused }

// refused returns a refusedError for path with reason.
func refused(path, reason string) error {
	return refusedError(path + ": " + reason)
}

// zeroChunk is the size of each zero write in ZeroFile.
const zeroChunk = 64 << 10

// zeroHead is the size of the SQLite WAL header, which ZeroFile writes and
// syncs before the rest of the file.
const zeroHead = 32

// ZeroFile overwrites the file at path with zeros up to its current size and
// syncs it to the disk. It does not truncate or remove the file: the caller
// does that next, so the blocks the file frees hold zeros, not query data.
// On flash storage and on a copy-on-write file system the overwrite can go to
// new blocks, so it is best effort (see PRIVACY.md).
//
// ZeroFile writes and syncs the first 32 bytes before the rest. For a WAL
// file, these bytes are the header: SQLite recovery ignores a WAL whose
// header is not valid. After a power loss during the overwrite, a valid
// header with only part of the frames zeroed would make recovery replay the
// older frames over newer pages in the database, and rows would silently
// lose their last changes.
//
// The offline purge can run as root in the data directory, which the s-hole
// user owns, or on Windows as an administrator in the config folder, where
// the service account can create files. So ZeroFile refuses a symbolic link,
// a file that is not a regular file, and a file with more than one hard
// link: the overwrite would otherwise reach a file that another name points
// to. A missing file returns an error that matches fs.ErrNotExist.
func ZeroFile(path string) error {
	return zeroFile(path, nil)
}

// zeroFile is ZeroFile. When want is not nil, it also refuses a file that is
// not want: the online purge holds the query log open and must not overwrite
// another file that took its name.
func zeroFile(path string, want os.FileInfo) error {
	lfi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !lfi.Mode().IsRegular() {
		return refused(path, "not a regular file; not overwritten")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|openFlags, 0)
	if err != nil {
		return err
	}
	err = writeZeros(f, path, lfi, want)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func writeZeros(f *os.File, path string, lfi, want os.FileInfo) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	switch {
	case !fi.Mode().IsRegular() || !os.SameFile(fi, lfi):
		return refused(path, "changed while it was opened; not overwritten")
	case want != nil && !os.SameFile(fi, want):
		return refused(path, "is not the open query log file; not overwritten")
	}
	links, err := linkCount(f, fi)
	if err != nil {
		return err
	}
	if links > 1 {
		return refused(path, fmt.Sprintf("has %d hard links; not overwritten", links))
	}
	zeros := make([]byte, zeroChunk)
	head := min(fi.Size(), zeroHead)
	if _, err := f.WriteAt(zeros[:head], 0); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	for off := head; off < fi.Size(); off += zeroChunk {
		n := min(fi.Size()-off, zeroChunk)
		if _, err := f.WriteAt(zeros[:n], off); err != nil {
			return err
		}
	}
	return f.Sync()
}

// truncateFile empties the file at path through a new handle, but only when
// it is still the file want: the query log path can name another file after
// a log rotation.
func truncateFile(path string, want os.FileInfo) error {
	f, err := os.OpenFile(path, os.O_WRONLY|openFlags, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(fi, want) {
		return refused(path, "is not the open query log file; not emptied")
	}
	return f.Truncate(0)
}
