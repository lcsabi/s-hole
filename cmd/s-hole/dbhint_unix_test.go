//go:build !windows

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The query log database hint is written inside main, so these tests run
// main in a child process: the test binary runs again with only
// TestMainHelperProcess selected, and the helper calls main with a test
// config. The child logs JSON to stdout, and the parent reads it.

// mainHelperConfig names the variable that tells TestMainHelperProcess which
// config to run main with. It has no S_HOLE_ prefix, so config.Load does not
// report it as an unknown s-hole variable.
const mainHelperConfig = "SHOLE_TEST_MAIN_CONFIG"

// TestMainHelperProcess is not a test. It runs main when a test starts the
// test binary again with mainHelperConfig set, and does nothing otherwise.
func TestMainHelperProcess(t *testing.T) {
	cfg := os.Getenv(mainHelperConfig)
	if cfg == "" {
		return
	}
	os.Args = []string{"s-hole", "-config", cfg}
	main()
	os.Exit(0)
}

// startupRecord runs main in a child process with a config whose
// query_log.database is dbPath, and returns the first JSON log record with a
// msg in msgs. It stops the child when it has the record.
func startupRecord(t *testing.T, dbPath string, msgs ...string) map[string]any {
	t.Helper()
	work := t.TempDir()
	cfgPath := filepath.Join(work, "config.yaml")
	cfgBody := "dns:\n  listen: \"127.0.0.1:0\"\n" +
		"blocking:\n  cache_dir: \"" + work + "\"\n" +
		"query_log:\n  database: \"" + dbPath + "\"\n" +
		"admin:\n  listen: \"127.0.0.1:0\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestMainHelperProcess$")
	cmd.Dir = work
	env := []string{mainHelperConfig + "=" + cfgPath, "S_HOLE_LOG_FORMAT=json"}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "S_HOLE_") || name == "JOURNAL_STREAM" || name == mainHelperConfig {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	found := make(chan map[string]any, 1)
	var seen []string
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			line := sc.Text()
			seen = append(seen, line)
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue // the banner is not JSON
			}
			for _, m := range msgs {
				if rec["msg"] == m {
					found <- rec
					return
				}
			}
		}
		close(found)
	}()
	select {
	case rec, ok := <-found:
		if !ok {
			cmd.Wait()
			t.Fatalf("s-hole exited without a %q line; stdout:\n%s\nstderr:\n%s", msgs, strings.Join(seen, "\n"), stderr.String())
		}
		return rec
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("no %q line within 20 s; stderr:\n%s", msgs, stderr.String())
	}
	return nil
}

const (
	dbOpenFailed = "query log database open failed"
	dbOpened     = "query log database opened"
)

func TestMain_QueryLogDatabasePermissionHint(t *testing.T) {
	// b/092: when the query database cannot be opened because of a
	// permission error, the startup WARN names the fix after the Linux
	// installer and the fix for Docker. Two permission errors: a directory
	// that s-hole cannot write, and an existing database file that s-hole
	// cannot open (as a root-owned 0600 file after a reinstall).
	if os.Geteuid() == 0 {
		t.Skip("runs as root: root can write any directory and open any file, so no permission error occurs")
	}
	cases := map[string]func(t *testing.T) string{
		"directory not writable": func(t *testing.T) string {
			dir := filepath.Join(t.TempDir(), "data")
			if err := os.Mkdir(dir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(dir, 0o700) })
			return filepath.Join(dir, "queries.db")
		},
		"file not readable": func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "queries.db")
			if err := os.WriteFile(p, nil, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(p, 0o600) })
			return p
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			rec := startupRecord(t, setup(t), dbOpenFailed, dbOpened)
			if rec["msg"] != dbOpenFailed || rec["level"] != "WARN" {
				t.Fatalf("got %v %q, want WARN %q", rec["level"], rec["msg"], dbOpenFailed)
			}
			if e, _ := rec["err"].(string); !strings.Contains(e, "permission denied") {
				t.Errorf("err = %v, want a permission error", rec["err"])
			}
			hint, _ := rec["hint"].(string)
			for _, advice := range []string{
				"sudo chown -R s-hole:s-hole /var/lib/s-hole",
				"sudo chown -R 65532:65532",
			} {
				if !strings.Contains(hint, advice) {
					t.Errorf("hint = %q, want it to contain %q", hint, advice)
				}
			}
		})
	}
}

func TestMain_QueryLogDatabaseOtherErrorHint(t *testing.T) {
	// b/092: a database open error that is not a permission error (here, a
	// directory that does not exist) keeps the old hint, which points at
	// query_log.database, with no ownership advice.
	dbPath := filepath.Join(t.TempDir(), "missing", "queries.db")
	rec := startupRecord(t, dbPath, dbOpenFailed, dbOpened)
	if rec["msg"] != dbOpenFailed || rec["level"] != "WARN" {
		t.Fatalf("got %v %q, want WARN %q", rec["level"], rec["msg"], dbOpenFailed)
	}
	hint, _ := rec["hint"].(string)
	if !strings.Contains(hint, "Check query_log.database") {
		t.Errorf("hint = %q, want it to contain %q", hint, "Check query_log.database")
	}
	if strings.Contains(hint, "chown") {
		t.Errorf("hint = %q, want no ownership advice for an error that is not a permission error", hint)
	}
}
