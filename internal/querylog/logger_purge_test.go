package querylog

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// purgeMarker is the test domain that the PRIV-08 purge tests log.
const purgeMarker = "purgefile-8e21.example."

func TestFileLogger_PurgeOverwriteKeepsLaterLines(t *testing.T) {
	// PRIV-08: Purge overwrites the log file with zeros, then empties it.
	// After it the file holds no zeros and no old line: a line logged after
	// the purge is the only content, at the start of the file.
	path := filepath.Join(t.TempDir(), "q.log")
	old := strings.Repeat("old "+purgeMarker+"\n", 5000) // more than one 64 KiB chunk
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	l := newTestFileLogger(t, path, "all")
	l.Log(Record{ClientIP: "10.0.0.1", Domain: purgeMarker})
	if err := l.Purge(context.Background()); err != nil {
		t.Fatalf("Purge = %v", err)
	}
	if got := fileBytes(t, path); len(got) != 0 {
		t.Errorf("the file holds %d bytes right after Purge, want 0", len(got))
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

func TestFileLogger_PurgeDoesNotOverwriteAnotherFileAtThePath(t *testing.T) {
	// PRIV-08: when the log file was renamed away and another file now has
	// its name, Purge does not overwrite the new file. It still empties the
	// file that the logger has open, and it returns an error.
	dir := t.TempDir()
	path := filepath.Join(dir, "q.log")
	if err := os.WriteFile(path, []byte("old "+purgeMarker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := newTestFileLogger(t, path, "all")
	defer closeFileLogger(t, l)
	moved := filepath.Join(dir, "q.log.1")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	other := []byte("another file " + purgeMarker + "\n")
	if err := os.WriteFile(path, other, 0o600); err != nil {
		t.Fatal(err)
	}

	err := l.Purge(context.Background())
	if !errors.Is(err, ErrNotOverwritten) || !errors.Is(err, ErrRefused) {
		t.Errorf("Purge with another file at the path = %v, want an error that matches ErrNotOverwritten and ErrRefused", err)
	}
	if err != nil && !strings.HasPrefix(err.Error(), "emptied, but not overwritten with zeros") {
		t.Errorf("Purge error = %q, want it to start with \"emptied, but not overwritten with zeros\"", err)
	}
	if got := fileBytes(t, path); !bytes.Equal(got, other) {
		t.Errorf("the new file at the path changed: %q", got)
	}
	if got := fileBytes(t, moved); len(got) != 0 {
		t.Errorf("the open log file holds %d bytes after Purge, want 0", len(got))
	}
}

func TestFileLogger_PurgeStdoutUnchanged(t *testing.T) {
	// PRIV-08: standard output still gives ErrStdoutNotPurgeable.
	redirectStdout(t)
	l, err := NewFileLogger("stdout", "all")
	if err != nil {
		t.Fatalf("NewFileLogger = %v", err)
	}
	defer l.Close()
	if err := l.Purge(context.Background()); !errors.Is(err, ErrStdoutNotPurgeable) {
		t.Errorf("Purge(stdout) = %v, want ErrStdoutNotPurgeable", err)
	}
}
