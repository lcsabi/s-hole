//go:build windows

package querylog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestZeroFile_RefusesHardLinkedFileOnWindows(t *testing.T) {
	// b/104: the offline purge runs as an administrator in the config
	// folder, where the service account can create files. A file with a
	// second hard link is refused, and no name of the file changes.
	dir := t.TempDir()
	path := filepath.Join(dir, "q.log")
	content := markerContent(zeroChunk + 99)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.txt")
	if err := os.Link(path, other); err != nil {
		t.Skipf("cannot make a hard link here: %v", err)
	}
	if err := ZeroFile(path); !errors.Is(err, ErrRefused) {
		t.Errorf("ZeroFile(hard-linked file) = %v, want an error that matches ErrRefused", err)
	}
	if err := ZeroFile(other); !errors.Is(err, ErrRefused) {
		t.Errorf("ZeroFile(second name) = %v, want an error that matches ErrRefused", err)
	}
	for _, p := range []string{path, other} {
		if got := fileBytes(t, p); !bytes.Equal(got, content) {
			t.Errorf("%s changed: %d bytes, zero-filled %v", filepath.Base(p), len(got), allZero(got))
		}
	}

	// With the second name removed, the file has one link again and
	// ZeroFile overwrites it: the link count is read, not a fixed value.
	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}
	if err := ZeroFile(path); err != nil {
		t.Fatalf("ZeroFile(one link) = %v, want nil", err)
	}
	if got := fileBytes(t, path); len(got) != len(content) || !allZero(got) {
		t.Errorf("after ZeroFile: %d bytes, zero-filled %v, want %d zero bytes", len(got), allZero(got), len(content))
	}
}
