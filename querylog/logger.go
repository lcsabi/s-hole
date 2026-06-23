package querylog

import (
	"fmt"
	"log"
	"os"
	"time"
)

// FileLogger writes one line per query to a file (or stdout when path is empty).
type FileLogger struct {
	f          *os.File
	logQueries string
}

func NewFileLogger(path, logQueries string) *FileLogger {
	if path == "" {
		return &FileLogger{f: os.Stdout, logQueries: logQueries}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[querylog] cannot open %s, falling back to stdout: %v", path, err)
		return &FileLogger{f: os.Stdout, logQueries: logQueries}
	}
	return &FileLogger{f: f, logQueries: logQueries}
}

func (l *FileLogger) Log(clientIP, domain string, blocked bool) {
	if l.logQueries == "none" {
		return
	}
	if l.logQueries == "blocked" && !blocked {
		return
	}
	action := "ALLOW"
	if blocked {
		action = "BLOCK"
	}
	fmt.Fprintf(l.f, "%s %s %s %s\n", time.Now().Format(time.RFC3339), action, clientIP, domain)
}

func (l *FileLogger) Close() error {
	if l.f != os.Stdout {
		return l.f.Close()
	}
	return nil
}

// Logger is the interface that all query log backends must implement.
type Logger interface {
	Log(clientIP, domain string, blocked bool)
}

// Compile-time interface checks.
var _ Logger = (*FileLogger)(nil)
var _ Logger = (*DBLogger)(nil)
var _ Logger = (*Multi)(nil)

// Multi fans out Log calls to multiple loggers.
type Multi struct {
	loggers []Logger
}

func NewMulti(loggers ...Logger) *Multi {
	return &Multi{loggers: loggers}
}

func (m *Multi) Log(clientIP, domain string, blocked bool) {
	for _, l := range m.loggers {
		l.Log(clientIP, domain, blocked)
	}
}
