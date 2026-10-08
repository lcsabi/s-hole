//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// openForCheck opens each path that exists for reading and returns the open
// files by path. On Unix an open file keeps the data of a deleted file, so
// a test reads, after the purge, the bytes that each file held at the
// moment that the purge deleted it (PRIV-08).
func openForCheck(t *testing.T, paths ...string) map[string]*os.File {
	t.Helper()
	open := map[string]*os.File{}
	for _, p := range paths {
		f, err := os.Open(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		open[p] = f
	}
	return open
}

// lastContent reads the whole content of the open file f.
func lastContent(t *testing.T, f *os.File) []byte {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, fi.Size())
	if _, err := f.ReadAt(b, 0); err != nil && len(b) > 0 {
		t.Fatalf("read %s: %v", f.Name(), err)
	}
	return b
}

// assertWiped checks that each open file was deleted and that, at that
// moment, it had its size from before the purge (sizes) and held zeros
// only, so no test domain (PRIV-08). The purge overwrites every file before
// it deletes it, and nothing truncates a file first.
func assertWiped(t *testing.T, open map[string]*os.File, sizes map[string]int64) {
	t.Helper()
	for p, f := range open {
		assertGone(t, p)
		b := lastContent(t, f)
		if want, ok := sizes[p]; ok && int64(len(b)) != want {
			t.Errorf("%s had %d bytes when it was deleted, want its original %d (overwritten, not truncated)", filepath.Base(p), len(b), want)
		}
		if bytes.Contains(b, []byte(wipeMarker)) {
			t.Errorf("%s held the test domain when it was deleted", filepath.Base(p))
		}
		for i, c := range b {
			if c != 0 {
				t.Errorf("%s held a byte other than zero at offset %d (of %d) when it was deleted", filepath.Base(p), i, len(b))
				break
			}
		}
	}
}

// sizesOf returns the size of each open file.
func sizesOf(t *testing.T, open map[string]*os.File) map[string]int64 {
	t.Helper()
	sizes := map[string]int64{}
	for p, f := range open {
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		sizes[p] = fi.Size()
	}
	return sizes
}

// crashState writes the files that a crash leaves at db: a valid query
// database with its -wal and -shm files, and rows that are only in the -wal
// file. It copies the files of a DBLogger that is still open.
func crashState(t *testing.T, db string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "q.db")
	live := openQueryDB(t, src)
	waitQueryRows(t, live, wipeMarker, 100)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.WriteFile(db+suffix, readFile(t, src+suffix), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(readFile(t, db+"-wal"), []byte(wipeMarker)) {
		t.Fatal("the copied -wal file does not hold the test domain; the test proves nothing")
	}
	if len(readFile(t, db+"-shm")) == 0 {
		t.Fatal("the copied -shm file is empty; the test proves nothing")
	}
}

func TestPurgeOffline_FilesHoldNoHistoryWhenDeleted(t *testing.T) {
	// PRIV-08 acceptance: after an offline purge, a byte scan of each file
	// at the moment before it was deleted finds no test domain. The
	// database was written by NewDBLogger and the log file by FileLogger.
	wd := offlineWorkDir(t)
	db, log := filepath.Join(wd, "q.db"), filepath.Join(wd, "q.log")
	writeQueryDB(t, db, wipeMarker, 500)
	writeQueryLog(t, log, wipeMarker, 500)
	if !bytes.Contains(readFile(t, db), []byte(wipeMarker)) {
		t.Fatal("the test domain is not in the database file; the test proves nothing")
	}
	open := openForCheck(t, db, db+"-wal", db+"-shm", log)
	sizes := sizesOf(t, open)

	cfg, _ := loadOffline(t, "query_log:\n  database: \"q.db\"\n  file: \"q.log\"\n")
	rep, notFound := purgeOffline(cfg)
	steps := stepByWhat(rep)
	if notFound || rep.Failed() {
		t.Errorf("notFound %v, failed %v; want neither: %+v", notFound, rep.Failed(), rep.Steps)
	}
	if s := steps["query database"]; s.Result != "files deleted" {
		t.Errorf("query database step = %q, want \"files deleted\"", s.Result)
	}
	if s := steps["query log file"]; s.Result != "deleted" {
		t.Errorf("query log file step = %q, want \"deleted\"", s.Result)
	}
	assertGone(t, db, db+"-wal", db+"-shm", log)
	assertWiped(t, open, sizes)
}

func TestPurgeOffline_CrashStateFilesAreZeroedInFull(t *testing.T) {
	// PRIV-08: after a crash, the -wal and -shm files stay next to the
	// database, and rows can be in the -wal file only. Nothing opens the
	// database: each of the three files is overwritten with zeros up to its
	// size and then deleted. A file that SQLite truncated first would leave
	// the old data in free disk blocks.
	wd := offlineWorkDir(t)
	db := filepath.Join(wd, "q.db")
	crashState(t, db)
	open := openForCheck(t, db, db+"-wal", db+"-shm")
	if len(open) != 3 {
		t.Fatalf("opened %d of the 3 database files", len(open))
	}
	sizes := sizesOf(t, open)

	cfg, _ := loadOffline(t, "query_log:\n  database: \"q.db\"\n")
	rep, notFound := purgeOffline(cfg)
	if s := stepByWhat(rep)["query database"]; notFound || s.Failed || s.Result != "files deleted" {
		t.Errorf("step = %+v, notFound %v; want \"files deleted\", not failed", s, notFound)
	}
	assertSingleLine(t, rep)
	assertWiped(t, open, sizes)
}

func TestPurgeOffline_NotADatabaseIsZeroedBeforeDelete(t *testing.T) {
	// PRIV-08: a file at the database path that is not a SQLite database is
	// overwritten with zeros, then deleted, and the step does not fail.
	wd := offlineWorkDir(t)
	db := filepath.Join(wd, "q.db")
	if err := os.WriteFile(db, bytes.Repeat([]byte(wipeMarker+"\n"), 5000), 0o600); err != nil {
		t.Fatal(err)
	}
	open := openForCheck(t, db)
	sizes := sizesOf(t, open)
	cfg, _ := loadOffline(t, "query_log:\n  database: \"q.db\"\n")
	rep, _ := purgeOffline(cfg)
	if s := stepByWhat(rep)["query database"]; s.Failed || s.Result != "files deleted" {
		t.Errorf("step = %+v, want \"files deleted\", not failed", s)
	}
	assertSingleLine(t, rep)
	assertWiped(t, open, sizes)
}

func TestPurgeOffline_HardLinkedLogFileIsNotTouched(t *testing.T) {
	// PRIV-08: a query log file with a second hard link is not overwritten
	// or deleted, because the overwrite would reach the other name. The
	// step fails, the other name keeps its content, and the database step
	// still runs.
	wd := offlineWorkDir(t)
	log := filepath.Join(wd, "q.log")
	writeQueryLog(t, log, wipeMarker, 50)
	content := readFile(t, log)
	other := filepath.Join(t.TempDir(), "other.txt")
	if err := os.Link(log, other); err != nil {
		t.Skipf("cannot make a hard link here: %v", err)
	}
	writeQueryDB(t, filepath.Join(wd, "q.db"), wipeMarker, 10)

	cfg, _ := loadOffline(t, "query_log:\n  database: \"q.db\"\n  file: \"q.log\"\n")
	rep, _ := purgeOffline(cfg)
	assertDeleteFailed(t, rep, "query log file")
	assertSingleLine(t, rep)
	if s := stepByWhat(rep)["query database"]; s.Failed || s.Result != "files deleted" {
		t.Errorf("query database step = %+v, want \"files deleted\"", s)
	}
	for _, p := range []string{log, other} {
		if got := readFile(t, p); !bytes.Equal(got, content) {
			t.Errorf("%s changed (%d bytes, was %d)", filepath.Base(p), len(got), len(content))
		}
	}
}

func TestPurgeOffline_CorruptDatabaseIsZeroedAndDeleted(t *testing.T) {
	// PRIV-08: nothing opens the database, so a corrupt database file is
	// overwritten with zeros and deleted like any other file, and the step
	// does not fail.
	wd := offlineWorkDir(t)
	db := filepath.Join(wd, "q.db")
	writeQueryDB(t, db, wipeMarker, 500)
	b := readFile(t, db)
	const page = 4096
	if len(b) < 4*page {
		t.Fatalf("the database has %d bytes; too small to corrupt", len(b))
	}
	for i := 2 * page; i < len(b)-page; i++ {
		b[i] = 0xFF
	}
	copy(b[len(b)-page:], bytes.Repeat([]byte(wipeMarker), page/len(wipeMarker)))
	if err := os.WriteFile(db, b, 0o600); err != nil {
		t.Fatal(err)
	}
	open := openForCheck(t, db)
	sizes := sizesOf(t, open)

	cfg, _ := loadOffline(t, "query_log:\n  database: \"q.db\"\n")
	rep, _ := purgeOffline(cfg)
	if s := stepByWhat(rep)["query database"]; s.Failed || s.Result != "files deleted" {
		t.Errorf("step = %+v, want \"files deleted\", not failed", s)
	}
	assertSingleLine(t, rep)
	assertWiped(t, open, sizes)
}

func TestPurgeOffline_HardLinkedDatabaseFilesAreNotTouched(t *testing.T) {
	// PRIV-08: a file at q.db, q.db-wal, or q.db-shm with a second hard
	// link is not overwritten or deleted, and the other name keeps its
	// exact content. Nothing may open the database, because SQLite writes
	// through a hard-linked -wal or -shm file. The step fails with one
	// line that names each refused path once. The database files that are
	// not hard-linked are still overwritten with zeros and deleted.
	for _, set := range linkSets {
		t.Run(setName(set), func(t *testing.T) {
			l := setupLinkedDB(t, set, os.Link)
			open := openForCheck(t, l.plain...)
			sizes := sizesOf(t, open)
			cfg, _ := loadOffline(t, "query_log:\n  database: \""+l.db+"\"\n")
			rep, _ := purgeOffline(cfg)
			l.check(t, rep, "has 2 hard links; not overwritten")
			assertWiped(t, open, sizes)
		})
	}
}

func TestPurgeOffline_HardLinkedCrashSidecarIsNotTouched(t *testing.T) {
	// PRIV-08: in the state that a crash leaves (a valid database whose
	// rows are in the -wal file), a hard-linked -wal or -shm file is not
	// changed through either name. SQLite would write through such a
	// file if the purge opened the database. The two other files are
	// overwritten in full and deleted.
	for _, suffix := range []string{"-wal", "-shm"} {
		t.Run("q.db"+suffix, func(t *testing.T) {
			wd := offlineWorkDir(t)
			db := filepath.Join(wd, "q.db")
			crashState(t, db)
			other := filepath.Join(t.TempDir(), "other"+suffix)
			if err := os.Link(db+suffix, other); err != nil {
				t.Skipf("cannot make a hard link here: %v", err)
			}
			saved := readFile(t, other)
			var plain []string
			for _, s := range []string{"", "-wal", "-shm"} {
				if s != suffix {
					plain = append(plain, db+s)
				}
			}
			open := openForCheck(t, plain...)
			sizes := sizesOf(t, open)

			cfg, _ := loadOffline(t, "query_log:\n  database: \"q.db\"\n")
			rep, _ := purgeOffline(cfg)
			assertSingleLine(t, rep)
			want := "delete failed: q.db" + suffix + ": has 2 hard links; not overwritten"
			if s := stepByWhat(rep)["query database"]; !s.Failed || s.Result != want {
				t.Errorf("step = %+v, want failed with %q", s, want)
			}
			for _, p := range []string{db + suffix, other} {
				if got := readFile(t, p); !bytes.Equal(got, saved) {
					t.Errorf("%s changed (%d bytes, was %d)", filepath.Base(p), len(got), len(saved))
				}
			}
			assertWiped(t, open, sizes)
		})
	}
}

func TestPurgeOffline_NamedPipeLogIsRefusedWithoutBlocking(t *testing.T) {
	// PRIV-08: a named pipe at the query log path is not a regular file.
	// The purge does not wait on it, does not delete it, and fails the step.
	wd := offlineWorkDir(t)
	log := filepath.Join(wd, "q.log")
	if err := syscall.Mkfifo(log, 0o600); err != nil {
		t.Skipf("cannot make a named pipe here: %v", err)
	}
	cfg, _ := loadOffline(t, "query_log:\n  file: \"q.log\"\n")
	done := make(chan struct{})
	go func() {
		defer close(done)
		rep, _ := purgeOffline(cfg)
		assertDeleteFailed(t, rep, "query log file")
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		if f, err := os.OpenFile(log, os.O_RDWR, 0); err == nil {
			<-done
			f.Close()
		}
		t.Fatal("the purge blocked on a named pipe")
	}
	if fi, err := os.Lstat(log); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("the named pipe was changed or deleted: %v, %v", fi, err)
	}
}
