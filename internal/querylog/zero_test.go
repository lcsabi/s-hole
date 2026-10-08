package querylog

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// zeroMarker is the test domain that a ZeroFile test writes into a file. It
// must not remain in the file after the overwrite (PRIV-08).
const zeroMarker = "zerofile-4b7d.example."

// markerContent returns n bytes that repeat zeroMarker, so the marker is in
// every chunk of the file, also in the last part chunk.
func markerContent(n int) []byte {
	return bytes.Repeat([]byte(zeroMarker), n/len(zeroMarker)+1)[:n]
}

// allZero reports whether every byte of b is zero.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// symlinkOrSkip makes link point to target, or skips the test where the
// platform does not allow it (Windows without the privilege).
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot make a symbolic link here: %v", err)
	}
}

func TestZeroFile_OverwritesWholeFileKeepsSize(t *testing.T) {
	// PRIV-08: ZeroFile writes zeros over every byte of the file, up to its
	// current size, and does not truncate it. The sizes cover an empty
	// file, less than one 64 KiB chunk, an exact chunk, an exact multiple,
	// and sizes that end in a part chunk.
	for _, size := range []int{0, 1, 100, zeroChunk - 1, zeroChunk, zeroChunk + 1, 2 * zeroChunk, 3*zeroChunk + 12345} {
		path := filepath.Join(t.TempDir(), "q.log")
		if err := os.WriteFile(path, markerContent(size), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ZeroFile(path); err != nil {
			t.Errorf("size %d: ZeroFile = %v, want nil", size, err)
			continue
		}
		got := fileBytes(t, path)
		if got == nil {
			t.Errorf("size %d: the file was removed", size)
			continue
		}
		if len(got) != size {
			t.Errorf("size %d: size after ZeroFile = %d, want it unchanged", size, len(got))
		}
		if !allZero(got) {
			t.Errorf("size %d: the file holds bytes other than zero after ZeroFile", size)
		}
		if bytes.Contains(got, []byte(zeroMarker)) {
			t.Errorf("size %d: the test domain is still in the file", size)
		}
	}
}

func TestZeroFile_MissingFileIsNotExistAndNotCreated(t *testing.T) {
	// PRIV-08: a missing file gives an error that matches fs.ErrNotExist,
	// and ZeroFile does not create the file.
	path := filepath.Join(t.TempDir(), "missing.log")
	err := ZeroFile(path)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ZeroFile(missing) = %v, want an error that matches fs.ErrNotExist", err)
	}
	if errors.Is(err, ErrRefused) {
		t.Errorf("ZeroFile(missing) = %v matches ErrRefused; a missing file is not a refusal", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ZeroFile created %s (Lstat = %v)", path, err)
	}
}

func TestZeroFile_RefusesSymlinkToRegularFile(t *testing.T) {
	// PRIV-08: the offline purge can run as root in a directory that the
	// s-hole user owns. A symbolic link at the path is refused, and the
	// file that it points to keeps its content.
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "other.txt")
	content := markerContent(3*zeroChunk + 7)
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "q.log")
	symlinkOrSkip(t, target, link)

	if err := ZeroFile(link); !errors.Is(err, ErrRefused) {
		t.Errorf("ZeroFile(symbolic link) = %v, want an error that matches ErrRefused", err)
	}
	if got := fileBytes(t, target); !bytes.Equal(got, content) {
		t.Errorf("the link target changed: %d bytes, zero-filled %v", len(got), allZero(got))
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link changed: Lstat = %v, %v", fi, err)
	}
}

func TestZeroFile_RefusesSymlinkToMissingFile(t *testing.T) {
	// PRIV-08: a dangling symbolic link is refused, and ZeroFile does not
	// create the file that it points to.
	dir := t.TempDir()
	target := filepath.Join(dir, "absent.txt")
	link := filepath.Join(dir, "q.log")
	symlinkOrSkip(t, target, link)
	if err := ZeroFile(link); !errors.Is(err, ErrRefused) {
		t.Errorf("ZeroFile(dangling symbolic link) = %v, want an error that matches ErrRefused", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ZeroFile created the link target (Lstat = %v)", err)
	}
}

func TestZeroFile_RefusesDirectory(t *testing.T) {
	// PRIV-08: a path that is not a regular file is refused.
	dir := t.TempDir()
	keep := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(keep, []byte(zeroMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ZeroFile(dir); !errors.Is(err, ErrRefused) {
		t.Errorf("ZeroFile(directory) = %v, want an error that matches ErrRefused", err)
	}
	if got := fileBytes(t, keep); string(got) != zeroMarker {
		t.Errorf("a file in the directory changed: %q", got)
	}
}
