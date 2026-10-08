//go:build !windows

package querylog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestZeroFile_RefusesHardLinkedFile(t *testing.T) {
	// PRIV-08: a file with a second hard link is refused, because the
	// overwrite would also reach the other name. No name of the file
	// changes.
	dir := t.TempDir()
	path := filepath.Join(dir, "q.log")
	content := markerContent(zeroChunk + 99)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.txt")
	if err := os.Link(path, other); err != nil {
		t.Skipf("cannot make a hard link here: %v", err)
	}
	if err := ZeroFile(path); !errors.Is(err, ErrRefused) {
		t.Errorf("ZeroFile(hard-linked file) = %v, want an error that matches ErrRefused", err)
	}
	for _, p := range []string{path, other} {
		if got := fileBytes(t, p); !bytes.Equal(got, content) {
			t.Errorf("%s changed: %d bytes, zero-filled %v", filepath.Base(p), len(got), allZero(got))
		}
	}
}

func TestZeroFile_RefusesNamedPipeWithoutBlocking(t *testing.T) {
	// PRIV-08: a named pipe is not a regular file. ZeroFile refuses it and
	// does not wait for a reader or a writer on the pipe.
	path := filepath.Join(t.TempDir(), "q.log")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot make a named pipe here: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- ZeroFile(path) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRefused) {
			t.Errorf("ZeroFile(named pipe) = %v, want an error that matches ErrRefused", err)
		}
	case <-time.After(5 * time.Second):
		// Open the pipe for reading and writing so the blocked call
		// returns and the goroutine does not outlive the test.
		if f, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
			<-done
			f.Close()
		}
		t.Fatal("ZeroFile blocked on a named pipe")
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("the named pipe changed: Lstat = %v, %v", fi, err)
	}
}

func TestZeroFile_OtherErrorIsNotRefused(t *testing.T) {
	// PRIV-08: ErrRefused marks a path that ZeroFile does not overwrite on
	// purpose. An error from the system, such as a file that cannot be
	// opened for writing, does not match it.
	if os.Geteuid() == 0 {
		t.Skip("root can open a read-only file for writing")
	}
	path := filepath.Join(t.TempDir(), "q.log")
	if err := os.WriteFile(path, []byte(zeroMarker), 0o400); err != nil {
		t.Fatal(err)
	}
	err := ZeroFile(path)
	if err == nil {
		t.Fatal("ZeroFile(read-only file) = nil, want an error")
	}
	if errors.Is(err, ErrRefused) {
		t.Errorf("ZeroFile(read-only file) = %v matches ErrRefused, want a plain error", err)
	}
}
