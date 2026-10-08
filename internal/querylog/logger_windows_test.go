//go:build windows

package querylog

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileLogger_PurgeEmptiesAppendFileOnWindows(t *testing.T) {
	// b/105: on Windows the log file is open for append, and that handle
	// has no right to write data, so Truncate on it fails with "Access is
	// denied". Purge must still empty the file: it returns nil, the file
	// has size 0 and no old line, and the next line starts at offset 0.
	path := filepath.Join(t.TempDir(), "q.log")
	old := strings.Repeat("old "+purgeMarker+"\n", 5000)
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	l := newTestFileLogger(t, path, "all")
	l.Log(Record{ClientIP: "10.0.0.1", Domain: purgeMarker})
	if err := l.Purge(context.Background()); err != nil {
		t.Fatalf("Purge = %v, want nil (b/105)", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Errorf("size after Purge = %d, want 0 (b/105)", fi.Size())
	}
	l.Log(Record{ClientIP: "10.0.0.1", Domain: "after.example."})
	closeFileLogger(t, l)
	got := fileBytes(t, path)
	if bytes.IndexByte(got, 0) >= 0 {
		t.Error("the file holds zero bytes after Purge and a new line")
	}
	if bytes.Contains(got, []byte(purgeMarker)) {
		t.Error("the file holds a line from before the purge")
	}
	if strings.Count(string(got), "\n") != 1 || !strings.Contains(string(got), "after.example.") {
		t.Errorf("file = %q, want only the line logged after the purge", got)
	}
}

func TestFileLogger_PurgeTwiceOnWindows(t *testing.T) {
	// b/105: a second purge on the same open file also empties it.
	path := filepath.Join(t.TempDir(), "q.log")
	l := newTestFileLogger(t, path, "all")
	for i := range 2 {
		l.Log(Record{ClientIP: "10.0.0.1", Domain: purgeMarker})
		if err := l.Purge(context.Background()); err != nil {
			t.Fatalf("Purge %d = %v, want nil (b/105)", i+1, err)
		}
		if got := fileBytes(t, path); len(got) != 0 {
			t.Errorf("Purge %d: the file holds %d bytes, want 0", i+1, len(got))
		}
	}
	closeFileLogger(t, l)
}
