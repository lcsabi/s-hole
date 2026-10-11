package privacylint

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Tests for the privacy lint of CL 119. They are written from the
// requirements of the lint, not from its code:
//
//   - TestRepository is the gate: the module has no finding, and
//     exceptions.txt lists every comment that the code needs.
//   - The rule tests (rules_test.go) give each rule fixtures that must be
//     reported and fixtures that must not be reported.
//   - The directive tests (directive_test.go) check the //privacy: comments,
//     the exceptions, and the exceptions.txt format.
//   - The Run tests here load a small module from a temporary directory, to
//     check the test-file exclusion and the merge of several GOOS passes.
//
// The tests do not use t.Parallel: the lint keeps a package-level cache.

var update = flag.Bool("update", false, "rewrite exceptions.txt from the //privacy: comments in the code")

// moduleRoot is the s-hole module, relative to this package.
var moduleRoot = filepath.Join("..", "..")

// fixturePkg is the import path of a fixture that is not internal/api.
const fixturePkg = "github.com/lcsabi/s-hole/internal/fixture"

// apiPkg is the import path where newErrorLog is the allowed ErrorLog.
const apiPkg = "github.com/lcsabi/s-hole/internal/api"

// ---- the repository gate ----

// TestRepository runs the lint over the whole module. Each finding fails the
// test. exceptions.txt must equal the exceptions that the code needs; with
// -update, the test rewrites the file instead.
func TestRepository(t *testing.T) {
	res, err := Run(moduleRoot)
	if err != nil {
		t.Fatalf("Run(%q): %v", moduleRoot, err)
	}
	for _, f := range res.Findings {
		t.Error(f.String())
	}

	const path = "exceptions.txt"
	want := FormatExceptions(res.Exceptions)
	got, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read %s: %v", path, err)
	}
	if bytes.Equal(got, want) {
		return
	}
	if *update {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("rewrote %s; review the change like any other privacy change", path)
		return
	}
	missing, extra := lineDiff(got, want)
	var b strings.Builder
	b.WriteString(path + " does not match the //privacy: comments in the code.\n")
	for _, l := range missing {
		b.WriteString("  missing from the file: " + strconv.Quote(l) + "\n")
	}
	for _, l := range extra {
		b.WriteString("  extra in the file:     " + strconv.Quote(l) + "\n")
	}
	b.WriteString("If the change is intended, run:\n  go test ./internal/privacylint -run TestRepository -update")
	t.Error(b.String())
}

// lineDiff returns the lines of want that got does not have (missing), and
// the lines of got that want does not have (extra). It counts repeats.
func lineDiff(got, want []byte) (missing, extra []string) {
	count := map[string]int{}
	for _, l := range strings.Split(string(got), "\n") {
		count[l]++
	}
	for _, l := range strings.Split(string(want), "\n") {
		if count[l] > 0 {
			count[l]--
			continue
		}
		missing = append(missing, l)
	}
	for l, n := range count {
		for ; n > 0; n-- {
			extra = append(extra, l)
		}
	}
	sort.Strings(extra)
	return missing, extra
}

func TestLineDiff(t *testing.T) {
	missing, extra := lineDiff([]byte("# h\na\tb\nold\n"), []byte("# h\na\tb\nnew\n"))
	if !reflect.DeepEqual(missing, []string{"new"}) || !reflect.DeepEqual(extra, []string{"old"}) {
		t.Errorf("lineDiff = missing %q, extra %q; want [new], [old]", missing, extra)
	}
}

// ---- the exported API ----

func TestRules_AreTheFourRules(t *testing.T) {
	want := map[string]bool{RuleClientAddress: true, RuleOutbound: true, RuleServerErrorLog: true, RuleMetricLabels: true}
	got := map[string]bool{}
	for _, r := range Rules() {
		if got[r.ID] {
			t.Errorf("Rules() lists %q twice", r.ID)
		}
		got[r.ID] = true
		if r.ID == RuleDirective {
			t.Errorf("Rules() lists %q, which no comment can allow", RuleDirective)
		}
		if strings.TrimSpace(r.Policy) == "" {
			t.Errorf("rule %q has no Policy", r.ID)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Rules() IDs = %v, want %v", got, want)
	}
}

func TestRules_ReturnsACopy(t *testing.T) {
	rs := Rules()
	rs[0].ID = "changed"
	rs[0].Policy = "changed"
	for _, r := range Rules() {
		if r.ID == "changed" || r.Policy == "changed" {
			t.Fatal("a change to the slice from Rules() changed the rules of the lint")
		}
	}
}

func TestFinding_String(t *testing.T) {
	f := Finding{File: "internal/x/a.go", Line: 12, Rule: RuleOutbound, Message: "net.Dial can open a connection."}
	if got, want := f.String(), "internal/x/a.go:12: [outbound] net.Dial can open a connection."; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestDefaultGOOS(t *testing.T) {
	got := DefaultGOOS()
	want := []string{runtime.GOOS, "windows"}
	if runtime.GOOS == "windows" {
		want = []string{"windows"}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DefaultGOOS() = %q, want %q", got, want)
	}
}

func TestCheckFiles_ErrorOnBadSource(t *testing.T) {
	for name, src := range map[string]string{
		"type error":  "package fixture\n\nfunc f() { undefinedName() }\n",
		"parse error": "package fixture\n\nfunc f( {\n",
		"bad import":  "package fixture\n\nimport \"example.com/does/not/exist\"\n\nvar _ = exist.X\n",
	} {
		t.Run(name, func(t *testing.T) {
			if res, err := CheckFiles(moduleRoot, fixturePkg, map[string]string{"f.go": src}); err == nil {
				t.Errorf("CheckFiles returned no error, result %+v", res)
			}
		})
	}
}

// ---- Run over a temporary module ----

// writeModule writes a module with the path example.com/m into a new
// temporary directory and returns the directory.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["go.mod"] = "module example.com/m\n\ngo 1.22\n"
	for name, src := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// findingKeys returns "file:line:rule" for each finding.
func findingKeys(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.File+":"+strconv.Itoa(f.Line)+":"+f.Rule)
	}
	return out
}

func TestRun_SkipsTestFiles(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"sub/a.go": `package sub

import "net"

func Dial() (net.Conn, error) {
	return net.Dial("tcp", "example.com:1")
}
`,
		"sub/a_test.go": `package sub

import (
	"net"
	"testing"
)

func TestX(t *testing.T) {
	c, err := net.Dial("tcp", "example.com:1")
	if err == nil {
		t.Log(c.RemoteAddr())
	}
}
`,
		"sub/b_test.go": `package sub_test

import (
	"net/http"
	"testing"
)

func TestY(t *testing.T) {
	_, _ = http.Get("http://example.com")
	_ = &http.Server{}
}
`,
	})
	res, err := Run(dir, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := findingKeys(res.Findings), []string{"sub/a.go:6:outbound"}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %q, want %q (test files must not be checked)", got, want)
	}
}

func TestRun_ChecksEachGOOS(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"a.go": "package m\n",
		"w_windows.go": `package m

import "net"

var _, _ = net.Dial("tcp", "example.com:1")
`,
	})
	res, err := Run(dir, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("GOOS=linux: findings = %q, want none (w_windows.go is not built)", findingKeys(res.Findings))
	}
	res, err = Run(dir, "linux", "windows")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := findingKeys(res.Findings), []string{"w_windows.go:5:outbound"}; !reflect.DeepEqual(got, want) {
		t.Errorf("GOOS=linux,windows: findings = %q, want %q", got, want)
	}
}

func TestRun_DefaultGOOSIncludesWindows(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"a.go": "package m\n",
		"w_windows.go": `package m

import "os/exec"

var _ = exec.Command("x")
`,
	})
	res, err := Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := findingKeys(res.Findings), []string{"w_windows.go:5:outbound"}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %q, want %q", got, want)
	}
}

// A comment in a file that every GOOS builds can be used by one GOOS only.
// It counts as used when any pass used it.
func TestRun_CommentUsedByOneGOOSIsUsed(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"t_linux.go": `package m

import "net/http"

type T = http.Client
`,
		"t_windows.go": `package m

type T = struct{}
`,
		"shared.go": `package m

//privacy:allow outbound CL 1: the client is only on Linux
var client T

var _ = &client
`,
	})
	res, err := Run(dir, "linux", "windows")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %q, want none", findingKeys(res.Findings))
	}
	want := []Exception{{File: "shared.go", Func: "-", Kind: "allow", Rule: RuleOutbound, ID: "CL 1"}}
	if !reflect.DeepEqual(res.Exceptions, want) {
		t.Errorf("exceptions = %+v, want %+v", res.Exceptions, want)
	}

	// Alone, the Windows pass uses the comment for nothing.
	res, err = Run(dir, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := findingKeys(res.Findings), []string{"shared.go:3:directive"}; !reflect.DeepEqual(got, want) {
		t.Errorf("windows only: findings = %q, want %q", got, want)
	}
	if len(res.Exceptions) != 0 {
		t.Errorf("windows only: exceptions = %+v, want none", res.Exceptions)
	}
}

// Run checks the whole main module, also when dir is a directory below the
// one that holds go.mod.
func TestRun_FromSubdirectoryChecksWholeModule(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"a.go": `package m

import "net"

var _, _ = net.LookupHost("example.com")
`,
		"sub/b.go": "package sub\n",
	})
	res, err := Run(filepath.Join(dir, "sub"), "linux")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := findingKeys(res.Findings), []string{"a.go:5:outbound"}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %q, want %q", got, want)
	}
}

func TestRun_ErrorOutsideAModule(t *testing.T) {
	if _, err := Run(t.TempDir(), "linux"); err == nil {
		t.Error("Run in a directory with no go.mod returned no error")
	}
}

func TestRun_ErrorOnBrokenPackage(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"a.go": "package m\n\nfunc f() { undefinedName() }\n",
	})
	if _, err := Run(dir, "linux"); err == nil {
		t.Error("Run on a module that does not type-check returned no error")
	}
}
