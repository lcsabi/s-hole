package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Tests for the installer health check (CL 118, b/107). The old check passed
// at the first `systemctl is-active` that said active. The unit is
// Type=simple with Restart=on-failure, so a service that crashed at startup
// looked active, and the installer exited 0 while s-hole restarted every 5 s.
//
// The behavioral tests cut wait_for_stable_service (and the installer lines
// around its call) out of deploy/install-linux.sh and run them with bash. A
// fake systemctl, journalctl, ss, and a no-op sleep come first on PATH. The
// fake systemctl answers each poll from a scripted list of states, so a test
// can count the polls and tell a fast failure from a timeout.

// svcState is one answer of the fake `systemctl show`. restarts is the
// NRestarts value; restartsOmit leaves the NRestarts line out.
type svcState struct {
	active, sub, restarts string
}

const restartsOmit = "<omit>"

// running and state make the common answers with NRestarts=0.
var running = svcState{"active", "running", "0"}

func state(active, sub string) svcState { return svcState{active, sub, "0"} }

// repeat returns n copies of s.
func repeat(s svcState, n int) []svcState {
	out := make([]svcState, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// seq joins lists of states into one.
func seq(parts ...[]svcState) []svcState {
	var out []svcState
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// baseFail makes the fake fail the initial `systemctl show -p NRestarts
// --value` call with no output.
const baseFail = "<fail>"

// healthEnv describes one run of the fake commands.
type healthEnv struct {
	base   string     // output of the initial NRestarts read, or baseFail
	states []svcState // one per poll; the last one repeats
	ss     string     // output of `ss -H -lunt`
}

// healthRun is what a run left behind.
type healthRun struct {
	rc             int
	stdout, stderr string
	log            []string // every fake command call, in order: "<cmd> <args>"
	polls          int      // state polls answered by the fake systemctl
	unsupported    []string // systemctl show calls the fake cannot answer
}

// calls returns the log entries of one fake command, without its name.
func (r healthRun) calls(cmd string) []string {
	var out []string
	for _, l := range r.log {
		if rest, ok := strings.CutPrefix(l, cmd+" "); ok {
			out = append(out, rest)
		} else if l == cmd {
			out = append(out, "")
		}
	}
	return out
}

// index returns the position of the first log entry equal to entry, or -1.
func (r healthRun) index(entry string) int {
	for i, l := range r.log {
		if l == entry {
			return i
		}
	}
	return -1
}

func (r healthRun) String() string {
	return fmt.Sprintf("rc=%d polls=%d\nstdout:\n%s\nstderr:\n%s\nlog:\n  %s",
		r.rc, r.polls, r.stdout, r.stderr, strings.Join(r.log, "\n  "))
}

// fakeSystemctl answers `show -p NRestarts --value UNIT` from the base file,
// answers every other `show` that asks for ActiveState and SubState with the
// next poll file (the last one repeats), and logs every call. It records a
// `show` form it cannot answer in "unsupported", so a test reports it instead
// of reading a wrong state.
const fakeSystemctl = `#!/bin/sh
D=%[1]q
printf 'systemctl %%s\n' "$*" >> "$D/log"
[ "$1" = show ] || exit 0
case " $* " in
  *" --value "*)
    if [ "$*" != "show -p NRestarts --value s-hole" ]; then
      printf '%%s\n' "$*" >> "$D/unsupported"
      exit 2
    fi
    [ -f "$D/base_fail" ] && exit 1
    cat "$D/base"
    exit 0
    ;;
  *ActiveState*SubState*|*SubState*ActiveState*) ;;
  *)
    printf '%%s\n' "$*" >> "$D/unsupported"
    exit 2
    ;;
esac
n=0
[ -f "$D/polls" ] && read -r n < "$D/polls"
n=$((n + 1))
printf '%%s\n' "$n" > "$D/polls"
if [ -f "$D/poll.$n" ]; then cat "$D/poll.$n"; else cat "$D/poll.last"; fi
`

// fakeLogger logs its call; extra is shell text that runs after the log.
const fakeLogger = `#!/bin/sh
D=%[1]q
printf '%[2]s %%s\n' "$*" >> "$D/log"
%[3]s
`

// writeExec writes an executable file.
func writeExec(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}

// requireBash returns the path of bash, or skips the test. The installer is
// for Linux; on Windows a bash on PATH can be WSL's, which cannot run the
// fakes in a Windows temp directory, so the behavioral tests skip there.
func requireBash(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the installer health check is Linux-only; the shell tests do not run on Windows")
	}
	return lookShell(t, "bash")
}

// installerFunc returns the text of a shell function in
// deploy/install-linux.sh, from "NAME() {" to the first line that is "}".
func installerFunc(t *testing.T, name string) string {
	t.Helper()
	lines := strings.Split(string(readDeployFile(t, "install-linux.sh")), "\n")
	for i, l := range lines {
		if l != name+"() {" {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			if lines[j] == "}" {
				return strings.Join(lines[i:j+1], "\n") + "\n"
			}
		}
		t.Fatalf("install-linux.sh: %s has no closing } line", name)
	}
	t.Fatalf("install-linux.sh has no %q line", name+"() {")
	return ""
}

// runHealthScript runs body with bash under the installer's own shell
// options, with the fakes first on PATH, and returns what happened.
func runHealthScript(t *testing.T, env healthEnv, body string, args ...string) healthRun {
	t.Helper()
	bash := requireBash(t)
	if len(env.states) == 0 {
		t.Fatal("healthEnv needs at least one state")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	data := filepath.Join(dir, "data")
	for _, d := range []string{bin, data} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeExec(t, filepath.Join(bin, "systemctl"), fmt.Sprintf(fakeSystemctl, data))
	writeExec(t, filepath.Join(bin, "sleep"), fmt.Sprintf(fakeLogger, data, "sleep", ""))
	writeExec(t, filepath.Join(bin, "journalctl"), fmt.Sprintf(fakeLogger, data, "journalctl", "echo 'fake journal line'"))
	writeExec(t, filepath.Join(bin, "ss"), fmt.Sprintf(fakeLogger, data, "ss", `cat "$D/ss"`))
	writeTestFile(t, filepath.Join(data, "ss"), env.ss)
	writeTestFile(t, filepath.Join(data, "log"), "")
	if env.base == baseFail {
		writeTestFile(t, filepath.Join(data, "base_fail"), "")
		writeTestFile(t, filepath.Join(data, "base"), "")
	} else {
		writeTestFile(t, filepath.Join(data, "base"), env.base+"\n")
	}
	for i, s := range env.states {
		out := "ActiveState=" + s.active + "\nSubState=" + s.sub + "\n"
		if s.restarts != restartsOmit {
			out += "NRestarts=" + s.restarts + "\n"
		}
		writeTestFile(t, filepath.Join(data, fmt.Sprintf("poll.%d", i+1)), out)
		if i == len(env.states)-1 {
			writeTestFile(t, filepath.Join(data, "poll.last"), out)
		}
	}

	script := filepath.Join(dir, "run.sh")
	writeTestFile(t, script, "set -euo pipefail\n"+body)
	cmd := exec.Command(bash, append([]string{"--noprofile", "--norc", script}, args...)...)
	cmd.Dir = dir
	for _, kv := range os.Environ() {
		switch strings.SplitN(kv, "=", 2)[0] {
		case "PATH", "BASH_ENV", "ENV":
		default:
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var o, e strings.Builder
	cmd.Stdout, cmd.Stderr = &o, &e
	var r healthRun
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run bash: %v", err)
		}
		r.rc = ee.ExitCode()
	}
	r.stdout, r.stderr = o.String(), e.String()
	if b, err := os.ReadFile(filepath.Join(data, "log")); err == nil {
		r.log = strings.Split(strings.TrimRight(string(b), "\n"), "\n")
		if len(r.log) == 1 && r.log[0] == "" {
			r.log = nil
		}
	}
	if b, err := os.ReadFile(filepath.Join(data, "polls")); err == nil {
		if _, err := fmt.Sscan(string(b), &r.polls); err != nil {
			t.Fatalf("read poll count: %v", err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(data, "unsupported")); err == nil {
		r.unsupported = strings.Split(strings.TrimSpace(string(b)), "\n")
	}
	if len(r.unsupported) > 0 {
		t.Fatalf("the fake systemctl cannot answer %q; extend the fake\n%v", r.unsupported, r)
	}
	return r
}

// runWait runs the installer's wait_for_stable_service with STABLE and
// TIMEOUT. The call sits in an && || list, so errexit is off inside the
// function, as it is under the installer's `if !`.
func runWait(t *testing.T, env healthEnv, stable, timeout int) healthRun {
	t.Helper()
	body := installerFunc(t, "wait_for_stable_service") +
		"wait_for_stable_service s-hole \"$1\" \"$2\" && rc=0 || rc=$?\nexit \"$rc\"\n"
	return runHealthScript(t, env, body, fmt.Sprint(stable), fmt.Sprint(timeout))
}

// checkSleeps checks that every poll the function waited after slept with
// `sleep 1` (CL 118 req 1), and that it slept at least min times.
func checkSleeps(t *testing.T, r healthRun, min int) {
	t.Helper()
	sleeps := r.calls("sleep")
	for _, a := range sleeps {
		if a != "1" {
			t.Errorf("sleep called with %q, want \"1\"\n%v", a, r)
		}
	}
	if len(sleeps) < min {
		t.Errorf("sleep called %d times, want at least %d\n%v", len(sleeps), min, r)
	}
	if len(sleeps) > r.polls {
		t.Errorf("sleep called %d times for %d polls; it sleeps only between polls\n%v", len(sleeps), r.polls, r)
	}
}

// checkPass checks a successful run: rc 0, nothing on stderr (CL 118 req 6).
func checkPass(t *testing.T, r healthRun) {
	t.Helper()
	if r.rc != 0 {
		t.Errorf("rc = %d, want 0\n%v", r.rc, r)
	}
	if r.stderr != "" {
		t.Errorf("stderr is not empty on success: %q", r.stderr)
	}
}

// checkFail checks a failed run: rc 1 and a stderr reason that names the
// state (CL 118 req 6).
func checkFail(t *testing.T, r healthRun, wantState string) {
	t.Helper()
	if r.rc != 1 {
		t.Errorf("rc = %d, want 1\n%v", r.rc, r)
	}
	if strings.TrimSpace(r.stderr) == "" {
		t.Errorf("stderr is empty; a failure must print a reason\n%v", r)
	}
	if !strings.Contains(r.stderr, wantState) {
		t.Errorf("stderr does not name the state %q: %q", wantState, r.stderr)
	}
}

// TestWaitForStableService_ReadsStateWithShow pins CL 118 req 1: the
// function reads the restart count with `systemctl show -p NRestarts --value
// UNIT` before the first poll, reads the state with `systemctl show`, and
// asks for ActiveState, SubState, and NRestarts.
func TestWaitForStableService_ReadsStateWithShow(t *testing.T) {
	r := runWait(t, healthEnv{base: "0", states: []svcState{running}}, 3, 10)
	checkPass(t, r)
	calls := r.calls("systemctl")
	if len(calls) == 0 || calls[0] != "show -p NRestarts --value s-hole" {
		t.Fatalf("first systemctl call = %q, want the initial NRestarts read\n%v", calls, r)
	}
	for _, c := range calls[1:] {
		if !strings.HasPrefix(c, "show ") {
			t.Errorf("systemctl %s: the function reads state with `systemctl show` only", c)
			continue
		}
		for _, p := range []string{"ActiveState", "SubState", "NRestarts"} {
			if !strings.Contains(c, p) {
				t.Errorf("systemctl %s: does not ask for %s", c, p)
			}
		}
		if !strings.HasSuffix(c, " s-hole") {
			t.Errorf("systemctl %s: does not name the unit", c)
		}
	}
	checkSleeps(t, r, 2)
}

// TestWaitForStableService_SteadyRunPasses pins CL 118 req 2: a unit that is
// active/running from the first poll passes after STABLE polls, not before
// and not much later, and the function waits between polls.
func TestWaitForStableService_SteadyRunPasses(t *testing.T) {
	for _, stable := range []int{1, 3, 5} {
		t.Run(fmt.Sprint("stable=", stable), func(t *testing.T) {
			r := runWait(t, healthEnv{base: "0", states: []svcState{running}}, stable, 30)
			checkPass(t, r)
			if r.polls < stable || r.polls > stable+1 {
				t.Errorf("polls = %d, want %d (STABLE)\n%v", r.polls, stable, r)
			}
			checkSleeps(t, r, stable-1)
		})
	}
}

// TestWaitForStableService_RunShorterThanStableFails pins CL 118 req 2 and
// req 5: STABLE-1 running polls are not enough. A unit that then waits in
// activating/start until TIMEOUT fails at the timeout.
func TestWaitForStableService_RunShorterThanStableFails(t *testing.T) {
	r := runWait(t, healthEnv{
		base:   "0",
		states: seq(repeat(running, 4), []svcState{state("activating", "start")}),
	}, 5, 12)
	checkFail(t, r, "activating/start")
	if r.polls < 12 || r.polls > 13 {
		t.Errorf("polls = %d, want 12 (TIMEOUT)\n%v", r.polls, r)
	}
}

// TestWaitForStableService_SlowStartPasses pins CL 118 req 3: a unit that
// starts slowly (activating/start for some polls) and then runs steadily
// passes.
func TestWaitForStableService_SlowStartPasses(t *testing.T) {
	r := runWait(t, healthEnv{
		base:   "0",
		states: seq(repeat(state("activating", "start"), 4), []svcState{running}),
	}, 3, 30)
	checkPass(t, r)
	if r.polls < 7 || r.polls > 8 {
		t.Errorf("polls = %d, want 7 (4 starting + 3 running)\n%v", r.polls, r)
	}
}

// TestWaitForStableService_NonRunningPollResetsCount pins CL 118 req 3: a
// non-running state between running polls resets the consecutive count, so
// the unit needs STABLE new running polls after it.
func TestWaitForStableService_NonRunningPollResetsCount(t *testing.T) {
	for _, gap := range []svcState{
		state("activating", "start"),
		state("active", "exited"),
		state("reloading", "reload"),
	} {
		t.Run(gap.active+"/"+gap.sub, func(t *testing.T) {
			r := runWait(t, healthEnv{
				base:   "0",
				states: seq(repeat(running, 2), []svcState{gap}, []svcState{running}),
			}, 3, 30)
			checkPass(t, r)
			// 2 running, the gap, then 3 running. Without the reset the
			// count reaches 3 at poll 4.
			if r.polls < 6 || r.polls > 7 {
				t.Errorf("polls = %d, want 6; the gap at poll 3 must reset the count\n%v", r.polls, r)
			}
		})
	}
}

// TestWaitForStableService_FlappingTimesOut pins CL 118 req 3 and req 5: a
// unit that never runs for STABLE polls in a row, because a non-running poll
// keeps breaking the run, fails when TIMEOUT polls are used.
func TestWaitForStableService_FlappingTimesOut(t *testing.T) {
	var states []svcState
	for len(states) < 40 {
		states = append(states, repeat(running, 2)...)
		states = append(states, state("activating", "start"))
	}
	states = append(states, state("activating", "start"))
	r := runWait(t, healthEnv{base: "0", states: states}, 3, 20)
	if r.rc != 1 {
		t.Errorf("rc = %d, want 1\n%v", r.rc, r)
	}
	if strings.TrimSpace(r.stderr) == "" {
		t.Errorf("stderr is empty; a timeout must print a reason\n%v", r)
	}
	if r.polls < 20 || r.polls > 21 {
		t.Errorf("polls = %d, want 20 (TIMEOUT)\n%v", r.polls, r)
	}
}

// TestWaitForStableService_TimeoutWaitsOutTimeout pins CL 118 req 5 and
// req 6: a unit that stays in activating/start fails after TIMEOUT polls,
// not before, sleeps between them, and names the last state on stderr.
func TestWaitForStableService_TimeoutWaitsOutTimeout(t *testing.T) {
	for _, timeout := range []int{3, 10} {
		t.Run(fmt.Sprint("timeout=", timeout), func(t *testing.T) {
			r := runWait(t, healthEnv{base: "0", states: []svcState{state("activating", "start")}}, 5, timeout)
			checkFail(t, r, "activating/start")
			if r.polls < timeout || r.polls > timeout+1 {
				t.Errorf("polls = %d, want %d (TIMEOUT)\n%v", r.polls, timeout, r)
			}
			checkSleeps(t, r, timeout-1)
		})
	}
}

// TestWaitForStableService_B107Sequence pins b/107 and CL 118 req 4: the
// unit runs for one poll, crashes, and waits in activating/auto-restart for
// RestartSec. The old check passed at the first `active`; the new one fails
// at the auto-restart poll, without waiting out the timeout.
func TestWaitForStableService_B107Sequence(t *testing.T) {
	r := runWait(t, healthEnv{
		base:   "0",
		states: []svcState{running, state("activating", "auto-restart")},
	}, 5, 30)
	checkFail(t, r, "activating/auto-restart")
	if r.polls != 2 {
		t.Errorf("polls = %d, want 2: fail at the auto-restart poll\n%v", r.polls, r)
	}
}

// TestWaitForStableService_FailsFast pins CL 118 req 4 and req 6: the
// auto-restart sub-state (with any active state), a failed or inactive unit
// fail at the poll that shows them, after earlier running polls too, and the
// reason names the state.
func TestWaitForStableService_FailsFast(t *testing.T) {
	bad := []svcState{
		state("activating", "auto-restart"),
		state("active", "auto-restart"),
		state("deactivating", "auto-restart"),
		state("failed", "failed"),
		state("failed", "auto-restart"),
		state("inactive", "dead"),
		state("inactive", "exited"),
	}
	for _, s := range bad {
		for _, before := range []int{0, 2} {
			name := fmt.Sprintf("%s/%s after %d running", s.active, s.sub, before)
			t.Run(name, func(t *testing.T) {
				r := runWait(t, healthEnv{
					base:   "0",
					states: seq(repeat(running, before), []svcState{s}, []svcState{running}),
				}, 5, 30)
				checkFail(t, r, s.active+"/"+s.sub)
				if r.polls != before+1 {
					t.Errorf("polls = %d, want %d: fail at the %s/%s poll\n%v", r.polls, before+1, s.active, s.sub, r)
				}
			})
		}
	}
}

// TestWaitForStableService_RestartCountIncreaseFails pins CL 118 req 4 and
// req 6: an NRestarts higher than the value read at the start fails at once,
// even while the unit shows active/running (systemd restarted it between two
// polls), and the reason names the state.
func TestWaitForStableService_RestartCountIncreaseFails(t *testing.T) {
	for _, tc := range []struct {
		base, now string
	}{
		{"0", "1"},
		{"2", "3"},
		{"9", "10"}, // a numeric compare, not a string compare
	} {
		t.Run(tc.base+"->"+tc.now, func(t *testing.T) {
			r := runWait(t, healthEnv{
				base: tc.base,
				states: []svcState{
					{"active", "running", tc.base},
					{"active", "running", tc.now},
					{"active", "running", tc.now},
				},
			}, 5, 30)
			checkFail(t, r, "active/running")
			if r.polls != 2 {
				t.Errorf("polls = %d, want 2: fail at the poll with the higher NRestarts\n%v", r.polls, r)
			}
		})
	}
}

// TestWaitForStableService_UnchangedRestartCountPasses pins CL 118 req 4:
// only an increase over the start value fails. A unit with earlier restarts
// (from before the installer ran) that keeps the same count passes.
func TestWaitForStableService_UnchangedRestartCountPasses(t *testing.T) {
	r := runWait(t, healthEnv{
		base:   "10",
		states: []svcState{{"active", "running", "10"}},
	}, 3, 30)
	checkPass(t, r)
	if r.polls != 3 {
		t.Errorf("polls = %d, want 3\n%v", r.polls, r)
	}
}

// TestWaitForStableService_BadInitialRestartCountIsZero pins CL 118 req 7: an
// empty, non-numeric, or unreadable initial NRestarts counts as 0. A current
// count of 0 then passes, and a current count of 1 fails.
func TestWaitForStableService_BadInitialRestartCountIsZero(t *testing.T) {
	for _, base := range []string{"", "abc", "[not set]", "-1", "1x", baseFail} {
		t.Run(fmt.Sprintf("base=%q", base), func(t *testing.T) {
			r := runWait(t, healthEnv{base: base, states: []svcState{running}}, 3, 30)
			checkPass(t, r)
			if r.polls != 3 {
				t.Errorf("polls = %d, want 3\n%v", r.polls, r)
			}

			r = runWait(t, healthEnv{
				base:   base,
				states: []svcState{{"active", "running", "1"}},
			}, 3, 30)
			checkFail(t, r, "active/running")
			if r.polls != 1 {
				t.Errorf("polls = %d, want 1: NRestarts=1 is higher than 0\n%v", r.polls, r)
			}
		})
	}
}

// TestWaitForStableService_BadCurrentRestartCountIgnored pins CL 118 req 7: a
// missing, empty, or non-numeric current NRestarts does not fail the check
// by itself; a steady active/running unit still passes.
func TestWaitForStableService_BadCurrentRestartCountIgnored(t *testing.T) {
	for _, now := range []string{restartsOmit, "", "abc", "[not set]"} {
		t.Run(fmt.Sprintf("now=%q", now), func(t *testing.T) {
			r := runWait(t, healthEnv{
				base:   "0",
				states: []svcState{{"active", "running", now}},
			}, 3, 30)
			checkPass(t, r)
			if r.polls != 3 {
				t.Errorf("polls = %d, want 3\n%v", r.polls, r)
			}
		})
	}
}

// installerHealthSection returns the installer lines from the unconditional
// `systemctl restart s-hole` to the `(service is running)` line, with the
// resolved_stub_on_53 function in front, followed by a marker that shows the
// installer went on to the banners.
func installerHealthSection(t *testing.T) string {
	t.Helper()
	lines := strings.Split(string(readDeployFile(t, "install-linux.sh")), "\n")
	start, end := -1, -1
	for i, l := range lines {
		if start < 0 && l == "systemctl restart s-hole" {
			start = i
		}
		if start >= 0 && strings.Contains(l, "(service is running)") {
			end = i
			break
		}
	}
	if start < 0 || end < 0 {
		t.Fatalf("install-linux.sh: no top-level `systemctl restart s-hole` line followed by a `(service is running)` line (start %d, end %d)", start, end)
	}
	return installerFunc(t, "resolved_stub_on_53") +
		strings.Join(lines[start:end+1], "\n") + "\necho CONTINUED-TO-BANNERS\n"
}

// TestInstallerHealthCheck_FailureStopsAndExits pins CL 118 req 8 with the
// b/107 sequence: the installer restarts the unit, checks it with
// wait_for_stable_service, then prints the journal, stops the unit (it does
// not disable it), says it is stopped and still enabled with `systemctl
// restart s-hole` as the next step, and exits 1 before the banners. With the
// resolved stub on port 53 it also names --free-port-53.
func TestInstallerHealthCheck_FailureStopsAndExits(t *testing.T) {
	body := installerHealthSection(t)
	for _, tc := range []struct {
		name     string
		ss       string
		wantHint bool
	}{
		{"resolved stub on 53", "UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\nLISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\n", true},
		{"port 53 free", "UNCONN 0 0 0.0.0.0:68 0.0.0.0:*\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runHealthScript(t, healthEnv{
				base:   "0",
				states: []svcState{running, state("activating", "auto-restart")},
				ss:     tc.ss,
			}, body)
			if r.rc != 1 {
				t.Errorf("rc = %d, want 1\n%v", r.rc, r)
			}
			if strings.Contains(r.stdout, "CONTINUED-TO-BANNERS") || strings.Contains(r.stdout, "(service is running)") {
				t.Errorf("a failed check went on to the success line or the banners\n%v", r)
			}
			if r.polls != 2 {
				t.Errorf("polls = %d, want 2\n%v", r.polls, r)
			}

			restart := r.index("systemctl restart s-hole")
			firstShow := r.index("systemctl show -p NRestarts --value s-hole")
			journal := r.index("journalctl -u s-hole -n 20 --no-pager")
			stop := r.index("systemctl stop s-hole")
			if restart < 0 || firstShow < 0 || journal < 0 || stop < 0 {
				t.Fatalf("missing call: restart %d, first show %d, journalctl %d, stop %d\n%v", restart, firstShow, journal, stop, r)
			}
			if restart >= firstShow || firstShow >= journal || journal >= stop {
				t.Errorf("order: want restart (%d) < health check (%d) < journalctl (%d) < stop (%d)\n%v", restart, firstShow, journal, stop, r)
			}
			for _, c := range r.calls("systemctl") {
				if strings.HasPrefix(c, "disable") || strings.HasPrefix(c, "mask") {
					t.Errorf("systemctl %s: a failed check stops the unit; it must stay enabled", c)
				}
				if strings.HasPrefix(c, "is-active") {
					t.Errorf("systemctl %s: the is-active health poll must be gone (CL 118 req 9)", c)
				}
			}
			if !strings.Contains(r.stderr, "fake journal line") {
				t.Errorf("the journal lines do not reach the operator (stderr): %q", r.stderr)
			}
			for _, want := range []string{"stopped", "enabled", "systemctl restart s-hole", "activating/auto-restart"} {
				if !strings.Contains(r.stderr, want) {
					t.Errorf("stderr does not contain %q:\n%s", want, r.stderr)
				}
			}
			if got := strings.Contains(r.stderr, "--free-port-53"); got != tc.wantHint {
				t.Errorf("--free-port-53 hint shown = %v, want %v:\n%s", got, tc.wantHint, r.stderr)
			}
		})
	}
}

// TestInstallerHealthCheck_SuccessContinues pins CL 118 req 8: a unit that
// runs steadily passes after 5 polls (the call is `wait_for_stable_service
// s-hole 5 30`), the installer prints `(service is running)`, does not stop
// the unit, and goes on to the banners.
func TestInstallerHealthCheck_SuccessContinues(t *testing.T) {
	r := runHealthScript(t, healthEnv{base: "0", states: []svcState{running}}, installerHealthSection(t))
	if r.rc != 0 {
		t.Errorf("rc = %d, want 0\n%v", r.rc, r)
	}
	if !strings.Contains(r.stdout, "(service is running)") {
		t.Errorf("stdout does not say the service is running\n%v", r)
	}
	if !strings.Contains(r.stdout, "CONTINUED-TO-BANNERS") {
		t.Errorf("the installer did not go on to the banners\n%v", r)
	}
	if r.stderr != "" {
		t.Errorf("stderr is not empty on success: %q", r.stderr)
	}
	if r.polls != 5 {
		t.Errorf("polls = %d, want 5 (STABLE in `wait_for_stable_service s-hole 5 30`)\n%v", r.polls, r)
	}
	for _, c := range r.calls("systemctl") {
		if c == "stop s-hole" || strings.HasPrefix(c, "disable") {
			t.Errorf("systemctl %s on success", c)
		}
	}
	if j := r.calls("journalctl"); len(j) != 0 {
		t.Errorf("journalctl called on success: %q", j)
	}
}

// TestInstallerHealthCheck_TimeoutIs30Polls pins CL 118 req 8: the installer
// gives the unit 30 polls (the TIMEOUT in `wait_for_stable_service s-hole 5
// 30`) before it fails and stops the unit.
func TestInstallerHealthCheck_TimeoutIs30Polls(t *testing.T) {
	r := runHealthScript(t, healthEnv{base: "0", states: []svcState{state("activating", "start")}}, installerHealthSection(t))
	if r.rc != 1 {
		t.Errorf("rc = %d, want 1\n%v", r.rc, r)
	}
	if r.polls < 30 || r.polls > 31 {
		t.Errorf("polls = %d, want 30\n%v", r.polls, r)
	}
	if r.index("systemctl stop s-hole") < 0 {
		t.Errorf("a timed-out check did not stop the unit\n%v", r)
	}
}

// installerCode returns the installer lines with comment lines removed, so a
// check does not match the text of a comment.
func installerCode(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(string(readDeployFile(t, "install-linux.sh")), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// TestInstaller_HealthCheckCallAndBranch pins CL 118 req 8 in the installer
// text, for hosts that cannot run the shell tests: the call is
// `wait_for_stable_service s-hole 5 30` after `systemctl restart s-hole`, and
// its failure branch prints the journal, stops the unit, gives the
// --free-port-53 hint under resolved_stub_on_53, and exits 1, with no
// `disable`.
func TestInstaller_HealthCheckCallAndBranch(t *testing.T) {
	code := installerCode(t)
	restart, call := -1, -1
	for i, l := range code {
		if restart < 0 && l == "systemctl restart s-hole" {
			restart = i
		}
		if strings.Contains(l, "wait_for_stable_service s-hole 5 30") {
			if call >= 0 {
				t.Errorf("install-linux.sh calls wait_for_stable_service s-hole 5 30 twice")
			}
			call = i
		}
	}
	if restart < 0 {
		t.Fatal("install-linux.sh has no top-level `systemctl restart s-hole` line")
	}
	if call < 0 {
		t.Fatal("install-linux.sh does not call `wait_for_stable_service s-hole 5 30`")
	}
	if call < restart {
		t.Fatalf("the health check (line %d of the code) runs before `systemctl restart s-hole` (line %d)", call, restart)
	}
	if !strings.HasPrefix(code[call], "if ! wait_for_stable_service s-hole 5 30") {
		t.Fatalf("the call is not `if ! wait_for_stable_service ...`; this test cannot find the failure branch: %q", code[call])
	}
	end := -1
	for i := call + 1; i < len(code); i++ {
		if code[i] == "fi" {
			end = i
			break
		}
	}
	if end < 0 {
		t.Fatal("no top-level `fi` closes the failure branch")
	}
	branch := strings.Join(code[call+1:end], "\n")
	order := []string{
		"journalctl -u s-hole -n 20 --no-pager",
		"systemctl stop s-hole",
		"if resolved_stub_on_53",
		"--free-port-53",
		"exit 1",
	}
	last := -1
	for _, want := range order {
		i := strings.Index(branch, want)
		if i < 0 {
			t.Errorf("the failure branch has no %q:\n%s", want, branch)
			continue
		}
		if i < last {
			t.Errorf("the failure branch has %q out of order (want %q)", want, order)
		}
		last = i
	}
	for _, bad := range []string{"systemctl disable", "systemctl mask"} {
		if strings.Contains(branch, bad) {
			t.Errorf("the failure branch runs %q; it must leave the unit enabled", bad)
		}
	}
	if !strings.Contains(branch, "systemctl restart s-hole") {
		t.Error("the failure branch does not name `systemctl restart s-hole` as the next step")
	}
	for i := end + 1; i < len(code); i++ {
		if strings.TrimSpace(code[i]) == "" {
			continue
		}
		if !strings.Contains(code[i], "(service is running)") {
			t.Errorf("the line after the failure branch is %q, want the `(service is running)` echo", code[i])
		}
		break
	}
}

// TestInstaller_NoIsActivePoll pins CL 118 req 9 (b/107): the
// pass-at-first-`active` health poll is gone. No installer command runs
// `systemctl is-active`.
func TestInstaller_NoIsActivePoll(t *testing.T) {
	for _, l := range installerCode(t) {
		if strings.Contains(l, "is-active") {
			t.Errorf("install-linux.sh still runs is-active: %q", strings.TrimSpace(l))
		}
	}
}
