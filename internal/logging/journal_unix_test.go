//go:build !windows

package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// devIno returns the "<dev>:<ino>" string that systemd would put in
// JOURNAL_STREAM for f, and the two numbers.
func devIno(t *testing.T, f *os.File) (string, uint64, uint64) {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		t.Skipf("fstat %s: %v", f.Name(), err)
	}
	dev, ino := uint64(st.Dev), uint64(st.Ino) //nolint:unconvert // Dev is not uint64 on every unix
	return fmt.Sprintf("%d:%d", dev, ino), dev, ino
}

func TestStreamMatches(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "stream"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	other, err := os.Create(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	match, dev, ino := devIno(t, f)
	otherEnv, _, _ := devIno(t, other)

	tests := []struct {
		name string
		env  string
		want bool
	}{
		{"matching dev and ino", match, true},
		{"empty env", "", false},
		{"wrong dev", fmt.Sprintf("%d:%d", dev+1, ino), false},
		{"wrong ino", fmt.Sprintf("%d:%d", dev, ino+1), false},
		{"dev and ino swapped", fmt.Sprintf("%d:%d", ino, dev), dev == ino},
		{"another file", otherEnv, false},
		{"garbage", "not-a-stream", false},
		{"trailing text", match + "x", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := streamMatches(tc.env, f); got != tc.want {
				t.Errorf("streamMatches(%q) = %v, want %v", tc.env, got, tc.want)
			}
		})
	}
}

// TestStreamMatches_ClosedFile checks that a file that cannot be stat'ed
// never matches.
func TestStreamMatches_ClosedFile(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "stream"))
	if err != nil {
		t.Fatal(err)
	}
	match, _, _ := devIno(t, f)
	f.Close()
	if streamMatches(match, f) {
		t.Error("streamMatches on a closed file = true, want false")
	}
}

// TestStdoutIsJournal checks the exported function against os.Stdout.
// t.Setenv restores JOURNAL_STREAM when the test ends.
func TestStdoutIsJournal(t *testing.T) {
	match, _, _ := devIno(t, os.Stdout)

	t.Setenv("JOURNAL_STREAM", match)
	if !StdoutIsJournal() {
		t.Errorf("StdoutIsJournal() = false with JOURNAL_STREAM=%q (stdout's dev:ino), want true", match)
	}

	t.Setenv("JOURNAL_STREAM", "")
	if StdoutIsJournal() {
		t.Error("StdoutIsJournal() = true with an empty JOURNAL_STREAM, want false")
	}

	t.Setenv("JOURNAL_STREAM", "1:1")
	if StdoutIsJournal() && match != "1:1" {
		t.Error("StdoutIsJournal() = true with a JOURNAL_STREAM for another file, want false")
	}
}
