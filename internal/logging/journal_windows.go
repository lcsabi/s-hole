//go:build windows

package logging

// StdoutIsJournal is always false on Windows, which has no systemd journal.
func StdoutIsJournal() bool { return false }
