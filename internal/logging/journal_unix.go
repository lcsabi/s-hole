//go:build !windows

package logging

import (
	"fmt"
	"os"
	"syscall"
)

// StdoutIsJournal reports whether stdout is connected to the systemd journal.
// systemd sets JOURNAL_STREAM to "<device>:<inode>" of the stream it gives a
// service. A process whose stdout was redirected elsewhere can still inherit
// the variable (a terminal started from a systemd user session, for example),
// so the check compares it with stdout's own device and inode, as
// systemd.exec(5) advises.
func StdoutIsJournal() bool {
	return streamMatches(os.Getenv("JOURNAL_STREAM"), os.Stdout)
}

func streamMatches(env string, f *os.File) bool {
	if env == "" {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return env == fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}
