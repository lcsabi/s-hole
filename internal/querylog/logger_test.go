package querylog

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func readAll(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestFileLogger_LogAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queries.log")
	l := NewFileLogger(path, "all")
	defer l.Close()

	l.Log(Record{ClientIP: "1.2.3.4", Domain: "ads.example.com.", Blocked: true})
	l.Log(Record{ClientIP: "1.2.3.4", Domain: "google.com."})
	l.Log(Record{ClientIP: "1.2.3.4", Domain: "cdn.example.com.", CacheHit: true})

	out := readAll(t, path)
	if !strings.Contains(out, "BLOCK 1.2.3.4 ads.example.com.") {
		t.Errorf("missing BLOCK line in: %s", out)
	}
	if !strings.Contains(out, "ALLOW 1.2.3.4 google.com.") {
		t.Errorf("missing ALLOW line in: %s", out)
	}
	// A cache hit appends a trailing CACHED marker to the ALLOW line.
	if !strings.Contains(out, "ALLOW 1.2.3.4 cdn.example.com. CACHED") {
		t.Errorf("missing cached ALLOW line in: %s", out)
	}
}

func TestFileLogger_LogBlockedOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queries.log")
	l := NewFileLogger(path, "blocked")
	defer l.Close()

	l.Log(Record{ClientIP: "1.2.3.4", Domain: "ads.example.com.", Blocked: true})
	l.Log(Record{ClientIP: "1.2.3.4", Domain: "google.com."})

	out := readAll(t, path)
	if !strings.Contains(out, "BLOCK") {
		t.Error("missing BLOCK line for blocked-only filter")
	}
	if strings.Contains(out, "ALLOW") {
		t.Error("ALLOW line should be suppressed in blocked-only mode")
	}
}

func TestNewFileLogger_FallsBackToStdoutOnBadPath(t *testing.T) {
	// A path inside a nonexistent directory cannot be opened. NewFileLogger
	// must fall back to os.Stdout rather than returning a useless logger.
	l := NewFileLogger("/does/not/exist/queries.log", "all")
	if l == nil {
		t.Fatal("NewFileLogger returned nil")
	}
	if l.f != os.Stdout {
		t.Errorf("FileLogger.f = %v, want os.Stdout", l.f)
	}
	// Close should be a no-op when writing to stdout; verify it does
	// not panic and returns nil.
	if err := l.Close(); err != nil {
		t.Errorf("Close on stdout-backed FileLogger returned %v", err)
	}
}

func TestNewFileLogger_EmptyPathUsesStdout(t *testing.T) {
	l := NewFileLogger("", "all")
	if l.f != os.Stdout {
		t.Errorf("empty path FileLogger.f = %v, want os.Stdout", l.f)
	}
}

func TestFileLogger_LogNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queries.log")
	l := NewFileLogger(path, "none")
	defer l.Close()

	l.Log(Record{ClientIP: "1.2.3.4", Domain: "ads.example.com.", Blocked: true})
	l.Log(Record{ClientIP: "1.2.3.4", Domain: "google.com."})

	out := readAll(t, path)
	if out != "" {
		t.Errorf("log_queries=none wrote: %q", out)
	}
}

// recorder is a Logger that just appends every call so we can verify
// the Multi fan-out preserves order.
type recorder struct {
	mu      sync.Mutex
	entries []string
}

func (r *recorder) Log(rec Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, rec.ClientIP+"|"+rec.Domain)
}

func TestMulti_FansOut(t *testing.T) {
	a, b := &recorder{}, &recorder{}
	m := NewMulti(a, b)
	m.Log(Record{ClientIP: "1.1.1.1", Domain: "example.com."})
	m.Log(Record{ClientIP: "2.2.2.2", Domain: "ads.com.", Blocked: true})

	if len(a.entries) != 2 {
		t.Errorf("logger a got %d entries, want 2", len(a.entries))
	}
	if len(b.entries) != 2 {
		t.Errorf("logger b got %d entries, want 2", len(b.entries))
	}
	if a.entries[0] != "1.1.1.1|example.com." {
		t.Errorf("logger a[0] = %q", a.entries[0])
	}
}
