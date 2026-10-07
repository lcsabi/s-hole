package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lcsabi/s-hole/internal/api"
	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/config"
)

// offlineWorkDir makes a fresh directory the current directory for the test
// (t.Chdir restores the old one) and returns its path as os.Getwd reports
// it, the base that relative config paths resolve against.
func offlineWorkDir(t *testing.T) string {
	t.Helper()
	t.Chdir(t.TempDir())
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

// loadOffline loads a config body the way runPurge does, with the admin
// address on a port where nothing listens, so the purge takes the offline
// path.
func loadOffline(t *testing.T, body string) (*config.Config, string) {
	t.Helper()
	clearSholeEnv(t)
	body += "admin:\n  listen: \"" + closedAddr(t) + "\"\n"
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, probs, err := config.Load(cfgPath)
	if err != nil || len(probs) != 0 {
		t.Fatalf("config.Load = (%v, %v)", probs, err)
	}
	return cfg, cfgPath
}

func touch(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("visited.example"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func assertGone(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists (%v)", p, err)
		}
	}
}

const listsYAML = "blocking:\n  lists: [\"https://lists.example/hosts.txt\"]\n  cache_dir: \"cache\"\n"

func TestPurgeOffline_MissingStoresAreNotFound(t *testing.T) {
	// b/091: a configured store whose files do not exist is reported as
	// "not found at <absolute path>", resolved against the current directory,
	// and is not a failure.
	wd := offlineWorkDir(t)
	cfg, _ := loadOffline(t, "query_log:\n  database: \"data/q.db\"\n  file: \"logs/q.log\"\n"+listsYAML)
	rep, notFound := purgeOffline(cfg)
	if !notFound {
		t.Error("notFound = false, want true")
	}
	if rep.Failed() {
		t.Errorf("report failed: %+v", rep)
	}
	want := map[string]string{
		"query database": "not found at " + filepath.Join(wd, "data", "q.db"),
		"query log file": "not found at " + filepath.Join(wd, "logs", "q.log"),
	}
	steps := stepByWhat(rep)
	for what, result := range want {
		s, ok := steps[what]
		if !ok || s.Result != result || s.Failed {
			t.Errorf("step %q = %+v (present %v), want result %q, not failed", what, s, ok, result)
		}
	}
	if len(rep.Steps) != 3 {
		t.Errorf("got %d steps, want 3: %+v", len(rep.Steps), rep.Steps)
	}
}

func TestPurgeOffline_AbsolutePathShownAsConfigured(t *testing.T) {
	// b/091: an absolute configured path is reported as it is.
	offlineWorkDir(t)
	abs := filepath.Join(t.TempDir(), "elsewhere", "q.db")
	cfg, _ := loadOffline(t, "query_log:\n  database: \""+abs+"\"\n")
	rep, notFound := purgeOffline(cfg)
	if s := stepByWhat(rep)["query database"]; !notFound || s.Result != "not found at "+abs || s.Failed {
		t.Errorf("step = %+v, notFound %v; want \"not found at %s\"", s, notFound, abs)
	}
}

func TestPurgeOffline_DatabaseFoundByAnyOfItsFiles(t *testing.T) {
	// b/091: the database is missing only when none of db, db-wal, and db-shm
	// exists. Any one of them is deleted and reported as "files deleted".
	for _, suffix := range []string{"", "-wal", "-shm"} {
		t.Run("only q.db"+suffix, func(t *testing.T) {
			wd := offlineWorkDir(t)
			touch(t, filepath.Join(wd, "q.db"+suffix))
			cfg, _ := loadOffline(t, "query_log:\n  database: \"q.db\"\n")
			rep, notFound := purgeOffline(cfg)
			if s := stepByWhat(rep)["query database"]; notFound || s.Result != "files deleted" || s.Failed {
				t.Errorf("step = %+v, notFound %v; want \"files deleted\"", s, notFound)
			}
			assertGone(t, filepath.Join(wd, "q.db"+suffix))
		})
	}
}

func TestPurgeOffline_ExistingStoresAreDeleted(t *testing.T) {
	// b/091: a store that exists is deleted and reported as before.
	wd := offlineWorkDir(t)
	files := []string{
		filepath.Join(wd, "q.db"), filepath.Join(wd, "q.db-wal"), filepath.Join(wd, "q.db-shm"),
		filepath.Join(wd, "q.log"),
		filepath.Join(wd, "cache", "blocklist_a.txt"), filepath.Join(wd, "cache", "blocklist_b.txt"),
	}
	touch(t, files...)
	touch(t, filepath.Join(wd, "cache", "keep.txt"))
	cfg, _ := loadOffline(t, "query_log:\n  database: \"q.db\"\n  file: \"q.log\"\n"+listsYAML)
	rep, notFound := purgeOffline(cfg)
	if notFound || rep.Failed() {
		t.Errorf("notFound %v, failed %v; want neither: %+v", notFound, rep.Failed(), rep)
	}
	want := map[string]string{
		"query database":        "files deleted",
		"query log file":        "deleted",
		"downloaded blocklists": "2 files deleted",
	}
	for what, result := range want {
		if s := stepByWhat(rep)[what]; s.Result != result {
			t.Errorf("step %q = %q, want %q", what, s.Result, result)
		}
	}
	assertGone(t, files...)
	if _, err := os.Stat(filepath.Join(wd, "cache", "keep.txt")); err != nil {
		t.Errorf("keep.txt was deleted: %v", err)
	}
}

func TestPurgeOffline_Blocklists(t *testing.T) {
	// b/091: with blocking.lists set and no blocklist_*.txt file in
	// cache_dir (the directory is missing, or holds only other files), the
	// step says "none found in <absolute cache_dir>". It is not a failure and
	// does not set notFound: the lists are public data, not personal data.
	// With no lists, the step says "0 files deleted" as before.
	cases := []struct {
		name   string
		lists  string
		setup  func(t *testing.T, wd string)
		result func(wd string) string
	}{
		{"no lists, only other files", "[]", func(t *testing.T, wd string) {
			touch(t, filepath.Join(wd, "cache", "keep.txt"))
		}, func(string) string { return "0 files deleted" }},
		{"no lists, cache_dir missing", "[]", func(*testing.T, string) {},
			func(string) string { return "0 files deleted" }},
		{"lists, one file", "[\"https://a.example/l\"]", func(t *testing.T, wd string) {
			touch(t, filepath.Join(wd, "cache", "blocklist_x.txt"))
		}, func(string) string { return "1 files deleted" }},
		{"lists, cache_dir missing", "[\"https://a.example/l\"]", func(*testing.T, string) {},
			func(wd string) string { return "none found in " + filepath.Join(wd, "cache") }},
		{"lists, only other files", "[\"https://a.example/l\"]", func(t *testing.T, wd string) {
			touch(t, filepath.Join(wd, "cache", "keep.txt"), filepath.Join(wd, "cache", "blocklist_x.txt.bak"))
		}, func(wd string) string { return "none found in " + filepath.Join(wd, "cache") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wd := offlineWorkDir(t)
			tc.setup(t, wd)
			cfg, _ := loadOffline(t, "blocking:\n  lists: "+tc.lists+"\n  cache_dir: \"cache\"\n")
			rep, notFound := purgeOffline(cfg)
			s := stepByWhat(rep)["downloaded blocklists"]
			if want := tc.result(wd); notFound || s.Result != want || s.Failed {
				t.Errorf("step = %+v, notFound %v; want %q, not failed, notFound false", s, notFound, want)
			}
		})
	}
	// The other files in cache_dir stay.
	wd := offlineWorkDir(t)
	keep := []string{filepath.Join(wd, "cache", "keep.txt"), filepath.Join(wd, "cache", "blocklist_x.txt.bak")}
	touch(t, keep...)
	cfg, _ := loadOffline(t, listsYAML)
	purgeOffline(cfg)
	for _, p := range keep {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was deleted: %v", filepath.Base(p), err)
		}
	}
}

func TestPurgeOffline_AbsoluteCacheDirShownAsConfigured(t *testing.T) {
	// b/091: a missing absolute cache_dir is named as it is configured.
	offlineWorkDir(t)
	dir := filepath.Join(t.TempDir(), "elsewhere", "cache")
	cfg, _ := loadOffline(t, "blocking:\n  lists: [\"https://a.example/l\"]\n  cache_dir: \""+dir+"\"\n")
	rep, notFound := purgeOffline(cfg)
	if s := stepByWhat(rep)["downloaded blocklists"]; notFound || s.Result != "none found in "+dir || s.Failed {
		t.Errorf("step = %+v, notFound %v; want \"none found in %s\"", s, notFound, dir)
	}
}

func TestPurgeOffline_EachMissingPersonalStoreSetsNotFound(t *testing.T) {
	// b/091: a missing query database alone, or a missing query log file
	// alone, is "not found at <absolute path>", not a failure, and sets
	// notFound. The other store is off.
	cases := []struct{ name, yaml, what, rel string }{
		{"query database", "query_log:\n  database: \"data/q.db\"\n", "query database", filepath.Join("data", "q.db")},
		{"query log file", "query_log:\n  file: \"logs/q.log\"\n", "query log file", filepath.Join("logs", "q.log")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wd := offlineWorkDir(t)
			cfg, _ := loadOffline(t, tc.yaml)
			rep, notFound := purgeOffline(cfg)
			want := "not found at " + filepath.Join(wd, tc.rel)
			if s := stepByWhat(rep)[tc.what]; !notFound || s.Result != want || s.Failed {
				t.Errorf("step = %+v, notFound %v; want %q, not failed, notFound true", s, notFound, want)
			}
			if rep.Failed() {
				t.Errorf("report failed: %+v", rep)
			}
		})
	}
}

func TestPurgeOffline_OffAndStdoutUnchanged(t *testing.T) {
	// b/091: an "off" store and standard output are reported as before, and
	// they are not "not found".
	offlineWorkDir(t)
	cfg, _ := loadOffline(t, "query_log:\n  database: \"off\"\n  file: \"off\"\n")
	rep, notFound := purgeOffline(cfg)
	steps := stepByWhat(rep)
	if notFound || steps["query database"].Result != "off, nothing stored" || steps["query log file"].Result != "off, nothing stored" {
		t.Errorf("off: notFound %v, steps %+v", notFound, rep.Steps)
	}
	cfg, _ = loadOffline(t, "query_log:\n  file: \"stdout\"\n")
	rep, notFound = purgeOffline(cfg)
	if s, ok := stepByWhat(rep)["query log output"]; notFound || !ok || s.Result != journalNote || s.Failed {
		t.Errorf("stdout: notFound %v, step %+v (present %v), want the journal note", notFound, s, ok)
	}
}

// purgeOutput runs runPurge and returns its exit code and standard output.
func purgeOutput(t *testing.T, cfgPath string) (int, string) {
	t.Helper()
	var j jsonLog
	var code int
	out := captureStdout(t, func() { code = runPurge(j.logger(), cfgPath) })
	return code, out
}

func TestRunPurge_NotFoundNoteAfterTheSteps(t *testing.T) {
	// b/091: when a step is "not found", runPurge prints a note after the
	// steps: relative paths start in the current directory, and the purge
	// should run again from s-hole's directory (/var/lib/s-hole for the Linux
	// installer). "Not found" alone does not make it exit 1.
	offlineWorkDir(t)
	_, cfgPath := loadOffline(t, "query_log:\n  database: \"q.db\"\n")
	code, out := purgeOutput(t, cfgPath)
	if code != 0 {
		t.Errorf("exit = %d, want 0 for \"not found\" only\n%s", code, out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	lastStep, noteAt := -1, -1
	for i, l := range lines {
		if strings.HasPrefix(l, "  ") {
			lastStep = i
		}
		if noteAt < 0 && strings.Contains(l, "Relative paths") {
			noteAt = i
		}
	}
	if noteAt < 0 {
		t.Fatalf("no note about relative paths:\n%s", out)
	}
	if noteAt < lastStep {
		t.Errorf("the note comes before the last step:\n%s", out)
	}
	note := strings.Join(lines[noteAt:], " ")
	for _, want := range []string{"current directory", "run the purge again", "/var/lib/s-hole"} {
		if !strings.Contains(note, want) {
			t.Errorf("note %q lacks %q", note, want)
		}
	}
	if !strings.Contains(out, "not found at ") {
		t.Errorf("output has no \"not found\" step:\n%s", out)
	}
}

func TestRunPurge_NoNoteWithoutNotFound(t *testing.T) {
	// b/091: with no "not found" step there is no note.
	wd := offlineWorkDir(t)
	touch(t, filepath.Join(wd, "q.db"), filepath.Join(wd, "q.log"))
	_, cfgPath := loadOffline(t, "query_log:\n  database: \"q.db\"\n  file: \"q.log\"\n")
	code, out := purgeOutput(t, cfgPath)
	if code != 0 {
		t.Errorf("exit = %d, want 0\n%s", code, out)
	}
	for _, s := range []string{"Relative paths", "/var/lib/s-hole", "not found"} {
		if strings.Contains(out, s) {
			t.Errorf("output holds %q without a \"not found\" step:\n%s", s, out)
		}
	}
	_, cfgPath = loadOffline(t, "query_log:\n  database: \"off\"\n  file: \"stdout\"\n")
	if _, out := purgeOutput(t, cfgPath); strings.Contains(out, "/var/lib/s-hole") {
		t.Errorf("off and stdout gave the note:\n%s", out)
	}
}

func TestRunPurge_RealFailureStillExitsOne(t *testing.T) {
	// b/091: a real delete failure still gives exit 1, also next to a "not
	// found" step, and the note is still printed.
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix directory permissions and a user other than root")
	}
	wd := offlineWorkDir(t)
	touch(t, filepath.Join(wd, "cache", "blocklist_a.txt"))
	if err := os.Chmod(filepath.Join(wd, "cache"), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(wd, "cache"), 0o700) })
	_, cfgPath := loadOffline(t, "query_log:\n  database: \"q.db\"\n"+listsYAML)
	code, out := purgeOutput(t, cfgPath)
	if code != 1 || !strings.Contains(out, "FAILED") {
		t.Errorf("exit = %d, want 1 with a FAILED step\n%s", code, out)
	}
	if !strings.Contains(out, "not found at "+filepath.Join(wd, "q.db")) || !strings.Contains(out, "/var/lib/s-hole") {
		t.Errorf("output lacks the \"not found\" step or the note:\n%s", out)
	}
}

func TestRunPurge_APIPathHasNoNote(t *testing.T) {
	// b/091: through a running s-hole nothing changes: the API report is
	// shown, the local paths are not checked, and there is no note.
	clearSholeEnv(t)
	offlineWorkDir(t)
	addr := adminServer(t, blocklist.NewStore(), func(context.Context) api.PurgeReport {
		return api.PurgeReport{Steps: []api.PurgeStep{{What: "query database", Result: "every row deleted"}}}
	})
	cfgPath := writeConfig(t, "query_log:\n  database: \"q.db\"\n  file: \"q.log\"\n"+listsYAML+
		"admin:\n  listen: \""+addr+"\"\n")
	code, out := purgeOutput(t, cfgPath)
	if code != 0 || !strings.Contains(out, "every row deleted") {
		t.Errorf("exit %d, output %q; want 0 and the API report", code, out)
	}
	for _, s := range []string{"not found", "Relative paths", "/var/lib/s-hole"} {
		if strings.Contains(out, s) {
			t.Errorf("API purge output holds %q:\n%s", s, out)
		}
	}
}

// noteLines returns the lines of runPurge output after the last step line
// (a step line starts with two spaces).
func noteLines(out string) []string {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	last := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "  ") {
			last = i
		}
	}
	return lines[last+1:]
}

func TestRunPurge_NoteNamesTheCurrentDirectory(t *testing.T) {
	// b/091: the first line of the note names the directory that relative
	// paths start in, in parentheses, as the absolute path from os.Getwd.
	wd := offlineWorkDir(t)
	_, cfgPath := loadOffline(t, "query_log:\n  file: \"q.log\"\n")
	code, out := purgeOutput(t, cfgPath)
	if code != 0 {
		t.Errorf("exit = %d, want 0\n%s", code, out)
	}
	note := noteLines(out)
	if len(note) == 0 {
		t.Fatalf("no note after the steps:\n%s", out)
	}
	if !filepath.IsAbs(wd) || !strings.Contains(note[0], "("+wd+")") {
		t.Errorf("first note line = %q, want it to name (%s)", note[0], wd)
	}
	if !strings.Contains(out, "not found at "+filepath.Join(wd, "q.log")) {
		t.Errorf("output has no \"not found\" step for the log file:\n%s", out)
	}
}

func TestRunPurge_MissingBlocklistCacheAloneGivesNoNote(t *testing.T) {
	// b/091: when the only missing store is the blocklist cache, runPurge
	// shows "none found in <dir>" and prints no note: the database and the
	// log file are off, or they were found and deleted.
	cases := []struct {
		name  string
		yaml  string
		setup func(t *testing.T, wd string)
	}{
		{"database and log file off", "query_log:\n  database: \"off\"\n  file: \"off\"\n", func(*testing.T, string) {}},
		{"database and log file found", "query_log:\n  database: \"q.db\"\n  file: \"q.log\"\n", func(t *testing.T, wd string) {
			touch(t, filepath.Join(wd, "q.db"), filepath.Join(wd, "q.log"))
		}},
		{"only other files in cache_dir", "query_log:\n  database: \"off\"\n  file: \"off\"\n", func(t *testing.T, wd string) {
			touch(t, filepath.Join(wd, "cache", "keep.txt"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wd := offlineWorkDir(t)
			tc.setup(t, wd)
			_, cfgPath := loadOffline(t, tc.yaml+listsYAML)
			code, out := purgeOutput(t, cfgPath)
			if code != 0 {
				t.Errorf("exit = %d, want 0\n%s", code, out)
			}
			if !strings.Contains(out, "none found in "+filepath.Join(wd, "cache")) {
				t.Errorf("output has no \"none found\" step for the blocklists:\n%s", out)
			}
			if note := noteLines(out); len(note) != 0 {
				t.Errorf("got a note after the steps, want none: %q", note)
			}
			for _, s := range []string{"not found", "Relative paths", "/var/lib/s-hole", "FAILED"} {
				if strings.Contains(out, s) {
					t.Errorf("output holds %q:\n%s", s, out)
				}
			}
		})
	}
}

func TestRunPurge_MissingDatabaseWithMissingCacheGivesNote(t *testing.T) {
	// b/091: a missing query database still raises the note when the
	// blocklist cache is missing too; the blocklist step stays "none found".
	wd := offlineWorkDir(t)
	_, cfgPath := loadOffline(t, "query_log:\n  database: \"q.db\"\n"+listsYAML)
	code, out := purgeOutput(t, cfgPath)
	if code != 0 {
		t.Errorf("exit = %d, want 0\n%s", code, out)
	}
	for _, want := range []string{
		"not found at " + filepath.Join(wd, "q.db"),
		"none found in " + filepath.Join(wd, "cache"),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if note := noteLines(out); len(note) == 0 || !strings.Contains(note[0], "("+wd+")") {
		t.Errorf("note = %q, want a note that names (%s)", note, wd)
	}
}
