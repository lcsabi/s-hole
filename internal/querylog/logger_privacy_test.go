package querylog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMaskClientIP_Modes(t *testing.T) {
	// Q1: "full" keeps the address, "subnet" keeps IPv4 /24 and IPv6 /64 and
	// passes a value that is not an IP through, and every other mode ("drop",
	// "", or an unknown value) gives "" so a bad value fails closed.
	cases := []struct {
		ip, mode, want string
	}{
		{"192.168.1.77", "full", "192.168.1.77"},
		{"2001:db8:1:2:3:4:5:6", "full", "2001:db8:1:2:3:4:5:6"},
		{"192.168.1.77", "subnet", "192.168.1.0"},
		{"10.20.30.40", "subnet", "10.20.30.0"},
		{"::ffff:192.168.1.77", "subnet", "192.168.1.0"},
		{"2001:db8:1:2:3:4:5:6", "subnet", "2001:db8:1:2::"},
		{"fe80::1234", "subnet", "fe80::"},
		{"unknown", "subnet", "unknown"},
		{"not an ip", "subnet", "not an ip"},
		{"192.168.1.77", "drop", ""},
		{"192.168.1.77", "", ""},
		{"192.168.1.77", "Full", ""},
		{"192.168.1.77", "SUBNET", ""},
		{"192.168.1.77", "none", ""},
		{"2001:db8::1", "bogus", ""},
	}
	for _, tc := range cases {
		if got := MaskClientIP(tc.ip, tc.mode); got != tc.want {
			t.Errorf("MaskClientIP(%q, %q) = %q, want %q", tc.ip, tc.mode, got, tc.want)
		}
	}
}

// redirectStdout points os.Stdout at a pipe until the test ends. A FileLogger
// for "stdout" must be created after the call, because it keeps the os.Stdout
// it finds. The returned reader yields what the logger wrote.
func redirectStdout(t *testing.T) (r, w *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = orig
		w.Close()
		r.Close()
	})
	return r, w
}

func TestFileLogger_StdoutDestination(t *testing.T) {
	// Q2: dest "stdout" writes to standard output, Close does not close it,
	// and Purge returns ErrStdoutNotPurgeable.
	r, w := redirectStdout(t)
	l, err := NewFileLogger("stdout", "all")
	if err != nil {
		t.Fatalf("NewFileLogger(stdout) = %v", err)
	}
	l.Log(Record{ClientIP: "192.168.1.5", Domain: "example.com.", Blocked: true})
	if err := l.Purge(context.Background()); !errors.Is(err, ErrStdoutNotPurgeable) {
		t.Errorf("Purge on stdout = %v, want ErrStdoutNotPurgeable", err)
	}
	l.Log(Record{ClientIP: "192.168.1.5", Domain: "after.example."})
	if err := l.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	// Standard output must still be open after Close.
	if _, err := io.WriteString(w, "still open\n"); err != nil {
		t.Errorf("standard output is closed after FileLogger.Close: %v", err)
	}
	w.Close()
	out, _ := io.ReadAll(r)
	// The line logged before Purge may be discarded with the queue, so only
	// the line logged after it is checked.
	if !strings.Contains(string(out), "ALLOW 192.168.1.5 after.example.") {
		t.Errorf("standard output = %q, want the line logged after the purge attempt", out)
	}
}

func TestFileLogger_CreatesOwnerOnlyFile(t *testing.T) {
	// Q2 (b/076): a new file is created with mode 0600.
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "q.log")
	l := newTestFileLogger(t, path, "all")
	closeFileLogger(t, l)
	assertMode(t, path, 0o600)
}

func TestFileLogger_TightensExistingFileAndAppends(t *testing.T) {
	// Q2 (b/076): an existing file is set to 0600 and opened for append, so
	// its earlier lines stay.
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "q.log")
	if err := os.WriteFile(path, []byte("earlier line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	l := newTestFileLogger(t, path, "all")
	assertMode(t, path, 0o600)
	l.Log(Record{ClientIP: "10.0.0.1", Domain: "new.example."})
	closeFileLogger(t, l)
	out := readAll(t, path)
	if !strings.HasPrefix(out, "earlier line\n") || !strings.Contains(out, "new.example.") {
		t.Errorf("file = %q, want the earlier line followed by the new one", out)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", filepath.Base(path), got, want)
	}
}

func TestFileLogger_OpenFailureIsAnError(t *testing.T) {
	// Q2 (b/079): an open failure is returned. There is no fallback to
	// standard output, which would send the history to the system journal.
	r, w := redirectStdout(t)
	l, err := NewFileLogger(filepath.Join(t.TempDir(), "missing-dir", "q.log"), "all")
	if err == nil {
		l.Log(Record{ClientIP: "10.0.0.1", Domain: "leak.example."})
		l.Close()
		t.Fatal("NewFileLogger in a missing directory = nil error, want an error")
	}
	if l != nil {
		t.Errorf("NewFileLogger returned a logger with the error: %+v", l)
	}
	w.Close()
	if out, _ := io.ReadAll(r); len(out) != 0 {
		t.Errorf("standard output got %q, want nothing", out)
	}
}

func TestFileLogger_LineFormatIsUTC(t *testing.T) {
	// Q2: "<RFC3339 UTC with Z> <ALLOW|BLOCK> <client> <domain>[ CACHED|
	// FAILED]". The local zone is set to +05:00 so a line in local time
	// cannot pass on a host whose zone is UTC.
	orig := time.Local
	time.Local = time.FixedZone("TEST", 5*60*60)
	t.Cleanup(func() { time.Local = orig })

	path := filepath.Join(t.TempDir(), "q.log")
	l := newTestFileLogger(t, path, "all")
	before := time.Now().UTC().Truncate(time.Second)
	l.Log(Record{ClientIP: "192.168.1.0", Domain: "ads.example.", Blocked: true})
	l.Log(Record{ClientIP: "", Domain: "plain.example."})
	l.Log(Record{ClientIP: "10.0.0.1", Domain: "cached.example.", CacheHit: true})
	l.Log(Record{ClientIP: "10.0.0.1", Domain: "dead.example.", Rcode: rcodeServerFailure, Synthesized: true})
	closeFileLogger(t, l)
	after := time.Now().UTC()

	lineRE := regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ) (ALLOW|BLOCK) (\S*) (\S+)( CACHED| FAILED)?$`)
	lines := strings.Split(strings.TrimSuffix(readAll(t, path), "\n"), "\n")
	want := []struct{ action, client, domain, marker string }{
		{"BLOCK", "192.168.1.0", "ads.example.", ""},
		{"ALLOW", "", "plain.example.", ""},
		{"ALLOW", "10.0.0.1", "cached.example.", " CACHED"},
		{"ALLOW", "10.0.0.1", "dead.example.", " FAILED"},
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(want), strings.Join(lines, "\n"))
	}
	for i, line := range lines {
		m := lineRE.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("line %q does not match the format", line)
			continue
		}
		ts, err := time.Parse(time.RFC3339, m[1])
		if err != nil || ts.Before(before) || ts.After(after) {
			t.Errorf("line %q: time %s is not the UTC time of the query", line, m[1])
		}
		if m[2] != want[i].action || m[3] != want[i].client || m[4] != want[i].domain || m[5] != want[i].marker {
			t.Errorf("line %q, want %+v", line, want[i])
		}
	}
}

func TestFileLogger_LogNeverBlocksAndCountsDrops(t *testing.T) {
	// Q2 (b/075): when the reader falls behind, Log does not block. A line
	// that does not fit in the queue is dropped and counted. Standard output
	// is a pipe that nobody reads, so the writer goroutine blocks on it.
	r, _ := redirectStdout(t)
	l, err := NewFileLogger("stdout", "all")
	if err != nil {
		t.Fatalf("NewFileLogger = %v", err)
	}
	const pushed = 20000
	done := make(chan struct{})
	go func() {
		for i := 0; i < pushed; i++ {
			l.Log(Record{ClientIP: "192.168.1.5", Domain: "d" + strconv.Itoa(i) + ".example."})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Log blocked while the reader was not reading")
	}
	dropped := l.Dropped()
	if dropped == 0 {
		t.Errorf("Dropped() = 0 after %d lines into a full pipe, want > 0", pushed)
	}

	// Read the pipe so Close can write the queued lines. Every line is
	// either written or counted as dropped.
	read := make(chan int)
	go func() {
		b, _ := io.ReadAll(r)
		read <- bytes.Count(b, []byte("\n"))
	}()
	if err := l.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if l.Dropped() != dropped {
		t.Errorf("Dropped() changed after the flood: %d, then %d", dropped, l.Dropped())
	}
	os.Stdout.Close()
	written := <-read
	if uint64(written)+dropped != pushed {
		t.Errorf("written %d + dropped %d = %d, want %d", written, dropped, uint64(written)+dropped, pushed)
	}
}

func TestFileLogger_CloseWritesQueuedLines(t *testing.T) {
	// Q2: Close writes every queued line before it closes the file.
	path := filepath.Join(t.TempDir(), "q.log")
	l := newTestFileLogger(t, path, "all")
	const n = fileQueueSize - 1
	for i := 0; i < n; i++ {
		l.Log(Record{ClientIP: "10.0.0.1", Domain: "d" + strconv.Itoa(i) + ".example."})
	}
	closeFileLogger(t, l)
	if got := strings.Count(readAll(t, path), "\n"); got != n {
		t.Errorf("file has %d lines after Close, want %d", got, n)
	}
	if l.Dropped() != 0 {
		t.Errorf("Dropped() = %d, want 0", l.Dropped())
	}
}

func TestFileLogger_PurgeEmptiesFileAndQueue(t *testing.T) {
	// Q2: Purge discards the queued lines and truncates the file. No line
	// logged before Purge may appear after it; a line logged after it is kept.
	path := filepath.Join(t.TempDir(), "q.log")
	if err := os.WriteFile(path, []byte("old line from an earlier run\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := newTestFileLogger(t, path, "all")
	for i := 0; i < fileQueueSize; i++ {
		l.Log(Record{ClientIP: "10.0.0.1", Domain: "before" + strconv.Itoa(i) + ".example."})
	}
	if err := l.Purge(context.Background()); err != nil {
		t.Fatalf("Purge = %v", err)
	}
	l.Log(Record{ClientIP: "10.0.0.1", Domain: "after.example."})
	closeFileLogger(t, l)
	out := readAll(t, path)
	if strings.Contains(out, "before") || strings.Contains(out, "old line") {
		t.Errorf("file holds lines from before the purge:\n%.300s", out)
	}
	if !strings.Contains(out, "after.example.") || strings.Count(out, "\n") != 1 {
		t.Errorf("file = %q, want only the line logged after the purge", out)
	}
}

func TestFileLogger_PurgeAfterCloseFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.log")
	l := newTestFileLogger(t, path, "all")
	closeFileLogger(t, l)
	if err := l.Purge(context.Background()); err == nil {
		t.Error("Purge after Close = nil, want an error")
	}
}

func TestFileLogger_PurgeHonorsContext(t *testing.T) {
	// A purge that cannot reach the writer returns the context error. The
	// writer is blocked on a full pipe, so the purge request cannot be taken.
	r, _ := redirectStdout(t)
	l, err := NewFileLogger("stdout", "all")
	if err != nil {
		t.Fatalf("NewFileLogger = %v", err)
	}
	for i := 0; i < 5000; i++ {
		l.Log(Record{ClientIP: "192.168.1.5", Domain: "d" + strconv.Itoa(i) + ".example."})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.Purge(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Purge with a blocked writer = %v, want context.DeadlineExceeded", err)
	}
	go io.Copy(io.Discard, r)
	if err := l.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
}
