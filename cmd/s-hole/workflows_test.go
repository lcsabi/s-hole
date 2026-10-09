package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Tests for the supply-chain rules of CL 108. They read the GitHub workflows,
// the Dockerfile, and the Makefile from the repository and check:
//
//   - SEC-04: every action is pinned to a full commit SHA with a version
//     comment, and golangci-lint is pinned once, in the Makefile.
//   - SEC-05: every workflow and job declares the minimum token permissions,
//     and no checkout keeps the token in .git/config.
//   - SEC-06: the release signs provenance attestations for the archives and
//     the image, the image gets an SBOM, and a release build restores no cache.
//   - SEC-07: the Docker images are pinned by digest, every workflow builds
//     with the one Go release that the Dockerfile's golang image pins (read
//     with .github/go-version.sh), and a weekly scan checks master and the
//     latest release binaries.
//
// The checks are functions that return a list of problems, so the negative
// tests can feed them broken input without editing the repository files.
// Every workflow file in .github/workflows is checked, also a new one.

// readRepoFile reads a file from the repository root.
func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

type workflow struct {
	file string // base name, for example "ci.yml"
	raw  string

	On          yaml.Node         `yaml:"on"`
	Permissions yaml.Node         `yaml:"permissions"`
	Jobs        map[string]*wfJob `yaml:"jobs"`
}

type wfJob struct {
	Permissions yaml.Node `yaml:"permissions"`
	Uses        string    `yaml:"uses"` // a reusable workflow
	Steps       []wfStep  `yaml:"steps"`
}

type wfStep struct {
	ID   string               `yaml:"id"`
	Name string               `yaml:"name"`
	Uses string               `yaml:"uses"`
	Run  string               `yaml:"run"`
	With map[string]yaml.Node `yaml:"with"`

	Shell string            `yaml:"shell"`
	Env   map[string]string `yaml:"env"`
}

// with returns the value of a `with:` input and whether the step sets it.
func (s wfStep) with(key string) (string, bool) {
	n, ok := s.With[key]
	if !ok {
		return "", false
	}
	return n.Value, true
}

// usesAction reports whether the step runs the action owner/repo[/path].
func (s wfStep) usesAction(action string) bool {
	return strings.HasPrefix(s.Uses, action+"@")
}

func (s wfStep) label() string {
	switch {
	case s.Name != "":
		return fmt.Sprintf("step %q", s.Name)
	case s.ID != "":
		return fmt.Sprintf("step id %q", s.ID)
	case s.Uses != "":
		return fmt.Sprintf("step %q", s.Uses)
	}
	return "unnamed step"
}

// sortedJobs returns the job names in a fixed order.
func (w *workflow) sortedJobs() []string {
	names := make([]string, 0, len(w.Jobs))
	for name := range w.Jobs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func parseWorkflow(file, raw string) (*workflow, error) {
	var w workflow
	if err := yaml.Unmarshal([]byte(raw), &w); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	w.file = file
	w.raw = raw
	return &w, nil
}

func mustParseWorkflow(t *testing.T, file, raw string) *workflow {
	t.Helper()
	w, err := parseWorkflow(file, raw)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// repoWorkflows parses every workflow file in .github/workflows.
func repoWorkflows(t *testing.T) []*workflow {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.y*ml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no workflow files found in .github/workflows")
	}
	sort.Strings(paths)
	var out []*workflow
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		w := mustParseWorkflow(t, filepath.Base(p), string(data))
		if len(w.Jobs) == 0 {
			t.Fatalf("%s: no jobs parsed", w.file)
		}
		out = append(out, w)
	}
	return out
}

// repoWorkflow returns one named workflow file.
func repoWorkflow(t *testing.T, file string) *workflow {
	t.Helper()
	for _, w := range repoWorkflows(t) {
		if w.file == file {
			return w
		}
	}
	t.Fatalf("workflow %s not found", file)
	return nil
}

// reportProblems fails the test once per problem.
func reportProblems(t *testing.T, problems []string) {
	t.Helper()
	for _, p := range problems {
		t.Error(p)
	}
}

// wantProblem checks that a check found at least one problem that contains
// substr. It is for the negative tests.
func wantProblem(t *testing.T, problems []string, substr string) {
	t.Helper()
	for _, p := range problems {
		if strings.Contains(p, substr) {
			return
		}
	}
	t.Errorf("want a problem that contains %q, got %q", substr, problems)
}

// TestRepoWorkflows_Found checks that the glob finds the three workflows that
// CL 108 hardens, so a moved directory cannot make the other tests pass on
// an empty list.
func TestRepoWorkflows_Found(t *testing.T) {
	got := map[string]bool{}
	for _, w := range repoWorkflows(t) {
		got[w.file] = true
	}
	for _, want := range []string{"ci.yml", "release.yml", "vulncheck.yml"} {
		if !got[want] {
			t.Errorf("workflow %s not found; found %v", want, got)
		}
	}
}

// ---- SEC-04: actions pinned to a commit SHA ----

// usesLineRE finds a `uses:` key in a raw workflow line, with its value and
// the comment after it.
var usesLineRE = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*(.*?)\s*$`)

// pinnedUsesRE is the only accepted form of a raw `uses:` value:
// owner/repo[/path]@<40 lowercase hex> # vX.Y.Z
var pinnedUsesRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}\s+#\s*v\d+\.\d+\.\d+$`)

// pinnedRefRE is the parsed `uses:` value (YAML drops the comment).
var pinnedRefRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$`)

// pinProblems checks every `uses:` of a workflow. It reads the raw lines for
// the version comment and the parsed YAML for the value, and checks that the
// two agree on the count, so a `uses` in flow style cannot hide from the line
// scan. A local action (./...) and a docker:// image fail: they need their
// own rule first.
func pinProblems(w *workflow) []string {
	var problems []string
	rawCount := 0
	for i, line := range strings.Split(w.raw, "\n") {
		m := usesLineRE.FindStringSubmatch(strings.TrimSuffix(line, "\r"))
		if m == nil {
			continue
		}
		rawCount++
		if !pinnedUsesRE.MatchString(m[1]) {
			problems = append(problems, fmt.Sprintf("%s:%d: uses %q is not owner/repo@<40-hex commit SHA> # vX.Y.Z", w.file, i+1, m[1]))
		}
	}
	parsedCount := 0
	for _, jn := range w.sortedJobs() {
		j := w.Jobs[jn]
		refs := []string{}
		if j.Uses != "" {
			refs = append(refs, j.Uses)
		}
		for _, s := range j.Steps {
			if s.Uses != "" {
				refs = append(refs, s.Uses)
			}
		}
		for _, ref := range refs {
			parsedCount++
			if !pinnedRefRE.MatchString(ref) {
				problems = append(problems, fmt.Sprintf("%s: job %s: uses %q is not pinned to a full commit SHA", w.file, jn, ref))
			}
		}
	}
	if rawCount != parsedCount {
		problems = append(problems, fmt.Sprintf("%s: %d uses: lines but %d parsed uses; write each uses: on its own line", w.file, rawCount, parsedCount))
	}
	return problems
}

// TestWorkflows_ActionsPinnedToCommit pins SEC-04 (CL 108): a moved or
// changed tag cannot run new code in CI or in the release job.
func TestWorkflows_ActionsPinnedToCommit(t *testing.T) {
	total := 0
	for _, w := range repoWorkflows(t) {
		reportProblems(t, pinProblems(w))
		total += strings.Count(w.raw, "uses:")
	}
	if total == 0 {
		t.Fatal("no uses: lines found; the check ran on nothing")
	}
}

// TestPinProblems_RejectsUnpinned is the negative test for pinProblems.
func TestPinProblems_RejectsUnpinned(t *testing.T) {
	sha := "3d3c42e5aac5ba805825da76410c181273ba90b1"
	good := []string{
		"actions/checkout@" + sha + " # v7.0.1",
		"github/codeql-action/init@" + sha + " # v3.29.0",
	}
	bad := []string{
		"actions/checkout@v7",
		"actions/checkout@v7.0.1 # v7.0.1",
		"actions/checkout@main",
		"actions/checkout@" + sha,                   // no version comment
		"actions/checkout@" + sha + " # main",       // comment is not a version
		"actions/checkout@" + sha + " # v7",         // not vX.Y.Z
		"actions/checkout@" + sha[:7] + " # v7.0.1", // short SHA
		"actions/checkout@" + sha + "0 # v7.0.1",    // 41 hex
		"actions/checkout@" + strings.ToUpper(sha) + " # v7.0.1",
		"./.github/actions/local",
		"docker://alpine:3.24",
	}
	wf := func(ref string) string {
		return "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + ref + "\n"
	}
	for _, ref := range good {
		w := mustParseWorkflow(t, "x.yml", wf(ref))
		if p := pinProblems(w); len(p) != 0 {
			t.Errorf("uses %q: unexpected problems %q", ref, p)
		}
	}
	for _, ref := range bad {
		w := mustParseWorkflow(t, "x.yml", wf(ref))
		if p := pinProblems(w); len(p) == 0 {
			t.Errorf("uses %q: accepted, want a problem", ref)
		}
	}

	// A reusable workflow at job level is checked too.
	w := mustParseWorkflow(t, "x.yml", "on: push\npermissions: {}\njobs:\n  a:\n    uses: owner/repo/.github/workflows/w.yml@v1\n")
	wantProblem(t, pinProblems(w), "not pinned")

	// A uses in flow style hides from the line scan; the count check finds it.
	w = mustParseWorkflow(t, "x.yml", "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{uses: \"actions/checkout@"+sha+"\"}]\n")
	wantProblem(t, pinProblems(w), "parsed uses")
}

// ---- SEC-04: golangci-lint pinned once, in the Makefile ----

var lintVersionLineRE = regexp.MustCompile(`(?m)^GOLANGCI_LINT_VERSION\s*\?=\s*(\S*)\s*$`)
var lintV2VersionRE = regexp.MustCompile(`^v2\.\d+\.\d+$`)

// makefileLintVersion returns the golangci-lint version that the Makefile
// pins, with the problems found.
func makefileLintVersion(makefile string) (string, []string) {
	var problems []string
	ms := lintVersionLineRE.FindAllStringSubmatch(makefile, -1)
	if len(ms) != 1 {
		return "", []string{fmt.Sprintf("Makefile: want one GOLANGCI_LINT_VERSION ?= line, found %d", len(ms))}
	}
	v := ms[0][1]
	if !lintV2VersionRE.MatchString(v) {
		problems = append(problems, fmt.Sprintf("Makefile: GOLANGCI_LINT_VERSION %q is not an exact v2 release (v2.X.Y)", v))
	}
	return v, problems
}

// toolsInstallProblems checks that `make tools-install` installs the pinned
// golangci-lint v2 version.
func toolsInstallProblems(makefile string) []string {
	lines := strings.Split(strings.ReplaceAll(makefile, "\r\n", "\n"), "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "tools-install:") {
			start = i
			break
		}
	}
	if start < 0 {
		return []string{"Makefile: no tools-install target"}
	}
	const install = "go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)"
	found := false
	for _, l := range lines[start+1:] {
		if !strings.HasPrefix(l, "\t") {
			break
		}
		cmd := strings.TrimSpace(l)
		if strings.Contains(cmd, "golangci-lint@") {
			if cmd != install {
				return []string{fmt.Sprintf("Makefile: tools-install runs %q, want %q", cmd, install)}
			}
			found = true
		}
	}
	if !found {
		return []string{"Makefile: tools-install does not install golangci-lint@$(GOLANGCI_LINT_VERSION)"}
	}
	return nil
}

// TestMakefile_GolangciLintPinned pins SEC-04 (CL 108): one exact v2 version,
// never latest, and tools-install uses it.
func TestMakefile_GolangciLintPinned(t *testing.T) {
	mk := readRepoFile(t, "Makefile")
	_, problems := makefileLintVersion(mk)
	reportProblems(t, problems)
	reportProblems(t, toolsInstallProblems(mk))
}

// TestMakefileLintChecks_RejectBadPins is the negative test for the Makefile
// checks.
func TestMakefileLintChecks_RejectBadPins(t *testing.T) {
	for _, mk := range []string{
		"GOLANGCI_LINT_VERSION ?= latest\n",
		"GOLANGCI_LINT_VERSION ?= v1.64.8\n",
		"GOLANGCI_LINT_VERSION ?= v2.14\n",
		"GOLANGCI_LINT_VERSION ?= 2.14.0\n",
		"GOLANGCI_LINT_VERSION ?= v2.14.0\nGOLANGCI_LINT_VERSION ?= v2.13.0\n",
		"LINT ?= v2.14.0\n",
	} {
		if _, p := makefileLintVersion(mk); len(p) == 0 {
			t.Errorf("Makefile %q: accepted, want a problem", mk)
		}
	}
	for _, mk := range []string{
		"tools-install:\n\tgo install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest\n",
		"tools-install:\n\tgo install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0\n",
		"tools-install:\n\tgo install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)\n",
		"tools-install:\n\t@echo nothing\n",
		"lint:\n\tgolangci-lint run\n",
	} {
		if p := toolsInstallProblems(mk); len(p) == 0 {
			t.Errorf("Makefile %q: accepted, want a problem", mk)
		}
	}
}

var stepOutputRE = regexp.MustCompile(`^\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*\}\}$`)

// lintActionProblems checks that every golangci-lint-action step gets its
// version from a step output, and that the step reads it from the Makefile
// line. It returns the run script of that step.
func lintActionProblems(w *workflow) (runs []string, problems []string) {
	for _, jn := range w.sortedJobs() {
		steps := w.Jobs[jn].Steps
		for i, s := range steps {
			if !s.usesAction("golangci/golangci-lint-action") {
				continue
			}
			v, ok := s.with("version")
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: job %s: golangci-lint-action has no version input (the action then picks latest)", w.file, jn))
				continue
			}
			m := stepOutputRE.FindStringSubmatch(strings.TrimSpace(v))
			if m == nil {
				problems = append(problems, fmt.Sprintf("%s: job %s: golangci-lint-action version %q does not come from the Makefile (want a step output)", w.file, jn, v))
				continue
			}
			var src *wfStep
			for k := 0; k < i; k++ {
				if steps[k].ID == m[1] {
					src = &steps[k]
				}
			}
			if src == nil {
				problems = append(problems, fmt.Sprintf("%s: job %s: version output step %q is not an earlier step of the job", w.file, jn, m[1]))
				continue
			}
			if !strings.Contains(src.Run, "GOLANGCI_LINT_VERSION") || !strings.Contains(src.Run, "Makefile") || !strings.Contains(src.Run, m[2]+"=") {
				problems = append(problems, fmt.Sprintf("%s: job %s: step %q does not write %s= from the Makefile GOLANGCI_LINT_VERSION line", w.file, jn, m[1], m[2]))
				continue
			}
			runs = append(runs, src.Run)
		}
	}
	return runs, problems
}

// TestCI_LintVersionFromMakefile pins SEC-04 (CL 108): the CI lint job runs
// the golangci-lint version that the Makefile pins. When a POSIX shell is
// available, the test runs the version step from the repository root and
// checks that it outputs the Makefile version.
func TestCI_LintVersionFromMakefile(t *testing.T) {
	want, problems := makefileLintVersion(readRepoFile(t, "Makefile"))
	reportProblems(t, problems)

	ci := repoWorkflow(t, "ci.yml")
	runs, problems := lintActionProblems(ci)
	reportProblems(t, problems)
	if len(runs) == 0 && len(problems) == 0 {
		t.Fatal("ci.yml has no golangci-lint-action step")
	}
	for _, w := range repoWorkflows(t) {
		if w.file == "ci.yml" {
			continue
		}
		_, p := lintActionProblems(w)
		reportProblems(t, p)
	}

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX shell; the version step was not run")
	}
	for _, run := range runs {
		out := filepath.Join(t.TempDir(), "github_output")
		cmd := exec.Command(sh, "-c", run)
		cmd.Dir = filepath.Join("..", "..")
		cmd.Env = append(os.Environ(), "GITHUB_OUTPUT="+out)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("run the version step: %v\n%s", err, b)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(data)); got != "version="+want {
			t.Errorf("version step wrote %q, want %q", got, "version="+want)
		}
	}
}

// TestLintActionProblems_RejectsHardCodedVersion is the negative test for
// lintActionProblems.
func TestLintActionProblems_RejectsHardCodedVersion(t *testing.T) {
	head := "on: push\npermissions: {}\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n"
	lintStep := "      - uses: golangci/golangci-lint-action@x\n"
	readStep := "      - id: lintver\n        run: echo \"version=$(sed -n 's/^GOLANGCI_LINT_VERSION ?= //p' Makefile)\" >> \"$GITHUB_OUTPUT\"\n"
	cases := map[string]string{
		"latest":        head + lintStep + "        with:\n          version: latest\n",
		"hard-coded":    head + lintStep + "        with:\n          version: v2.13.0\n",
		"no version":    head + lintStep,
		"unknown step":  head + lintStep + "        with:\n          version: ${{ steps.nope.outputs.version }}\n",
		"step after":    head + lintStep + "        with:\n          version: ${{ steps.lintver.outputs.version }}\n" + readStep,
		"not from make": head + "      - id: lintver\n        run: echo version=v2.14.0 >> \"$GITHUB_OUTPUT\"\n" + lintStep + "        with:\n          version: ${{ steps.lintver.outputs.version }}\n",
		"other output":  head + readStep + lintStep + "        with:\n          version: ${{ steps.lintver.outputs.other }}\n",
	}
	for name, raw := range cases {
		if _, p := lintActionProblems(mustParseWorkflow(t, "ci.yml", raw)); len(p) == 0 {
			t.Errorf("%s: accepted, want a problem", name)
		}
	}
	ok := head + readStep + lintStep + "        with:\n          version: ${{ steps.lintver.outputs.version }}\n"
	if _, p := lintActionProblems(mustParseWorkflow(t, "ci.yml", ok)); len(p) != 0 {
		t.Errorf("good workflow: unexpected problems %q", p)
	}
}

// ---- SEC-05: token permissions ----

// allowedWrites lists, for each workflow file and job, the only scopes that
// may be write. No other job and no workflow top level may grant a write
// scope.
var allowedWrites = map[string]map[string][]string{
	"release.yml": {
		"build":   {"id-token", "attestations"},
		"release": {"contents"},
		"docker":  {"packages", "id-token", "attestations"},
	},
}

// permMap reads a permissions node. A scalar (read-all, write-all) or an
// unknown level is an error.
func permMap(n yaml.Node) (map[string]string, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("permissions %q is not a map of scopes", n.Value)
	}
	m := map[string]string{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i].Value, n.Content[i+1].Value
		switch v {
		case "read", "write", "none":
		default:
			return nil, fmt.Errorf("permission %s: %q is not read, write, or none", k, v)
		}
		m[k] = v
	}
	return m, nil
}

func permissionProblems(w *workflow) []string {
	var problems []string
	if w.Permissions.Kind == 0 {
		problems = append(problems, fmt.Sprintf("%s: no top-level permissions", w.file))
	} else if top, err := permMap(w.Permissions); err != nil {
		problems = append(problems, fmt.Sprintf("%s: top level: %v", w.file, err))
	} else {
		for scope, level := range top {
			if level == "write" {
				problems = append(problems, fmt.Sprintf("%s: top level grants %s: write; grant it to the job that needs it", w.file, scope))
			}
		}
		if len(top) == 0 {
			// With no top-level rights, every job states what it needs.
			for _, jn := range w.sortedJobs() {
				if w.Jobs[jn].Permissions.Kind == 0 {
					problems = append(problems, fmt.Sprintf("%s: job %s: no permissions (the top level is {})", w.file, jn))
				}
			}
		}
	}
	for _, jn := range w.sortedJobs() {
		j := w.Jobs[jn]
		if j.Permissions.Kind == 0 {
			continue
		}
		perms, err := permMap(j.Permissions)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: job %s: %v", w.file, jn, err))
			continue
		}
		allowed := map[string]bool{}
		for _, s := range allowedWrites[w.file][jn] {
			allowed[s] = true
		}
		for _, scope := range sortedKeys(perms) {
			if perms[scope] == "write" && !allowed[scope] {
				problems = append(problems, fmt.Sprintf("%s: job %s: %s: write is not allowed", w.file, jn, scope))
			}
		}
	}
	return problems
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestWorkflows_PermissionsMinimal pins SEC-05 (CL 108) for every workflow:
// a top-level permissions key, no read-all or write-all, and write scopes
// only on the jobs that need them.
func TestWorkflows_PermissionsMinimal(t *testing.T) {
	for _, w := range repoWorkflows(t) {
		reportProblems(t, permissionProblems(w))
		for _, bad := range []string{"write-all", "read-all"} {
			if strings.Contains(w.raw, bad) {
				t.Errorf("%s: contains %q", w.file, bad)
			}
		}
	}
}

// TestWorkflows_ExactPermissions pins the permissions that CL 108 sets in
// ci.yml and release.yml.
func TestWorkflows_ExactPermissions(t *testing.T) {
	check := func(where string, n yaml.Node, want map[string]string) {
		t.Helper()
		if n.Kind == 0 {
			t.Errorf("%s: no permissions", where)
			return
		}
		got, err := permMap(n)
		if err != nil {
			t.Errorf("%s: %v", where, err)
			return
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: permissions %v, want %v", where, got, want)
		}
	}

	ci := repoWorkflow(t, "ci.yml")
	check("ci.yml top level", ci.Permissions, map[string]string{"contents": "read"})

	rel := repoWorkflow(t, "release.yml")
	check("release.yml top level", rel.Permissions, map[string]string{})
	want := map[string]map[string]string{
		"build":   {"contents": "read", "id-token": "write", "attestations": "write"},
		"release": {"contents": "write"},
		"docker":  {"contents": "read", "packages": "write", "id-token": "write", "attestations": "write"},
	}
	for _, jn := range rel.sortedJobs() {
		w, ok := want[jn]
		if !ok {
			t.Errorf("release.yml: job %s has no expected permissions in this test; add them", jn)
			continue
		}
		check("release.yml job "+jn, rel.Jobs[jn].Permissions, w)
	}
	for jn := range want {
		if rel.Jobs[jn] == nil {
			t.Errorf("release.yml: job %s not found", jn)
		}
	}
}

// TestPermissionProblems_RejectsWideRights is the negative test for
// permissionProblems.
func TestPermissionProblems_RejectsWideRights(t *testing.T) {
	job := func(perms string) string {
		return "  a:\n    runs-on: ubuntu-latest\n" + perms + "    steps:\n      - run: true\n"
	}
	cases := []struct {
		name, file, raw, want string
	}{
		{"no top level", "ci.yml", "on: push\njobs:\n" + job(""), "no top-level permissions"},
		{"write-all top", "ci.yml", "on: push\npermissions: write-all\njobs:\n" + job(""), "not a map"},
		{"read-all job", "ci.yml", "on: push\npermissions: {}\njobs:\n" + job("    permissions: read-all\n"), "not a map"},
		{"write top", "ci.yml", "on: push\npermissions:\n  contents: write\njobs:\n" + job(""), "top level grants contents: write"},
		{"bad level", "ci.yml", "on: push\npermissions:\n  contents: admin\njobs:\n" + job(""), "not read, write, or none"},
		{"ci id-token", "ci.yml", "on: push\npermissions:\n  contents: read\njobs:\n" + job("    permissions:\n      id-token: write\n"), "id-token: write is not allowed"},
		{"vulncheck attestations", "vulncheck.yml", "on: push\npermissions:\n  contents: read\njobs:\n" + job("    permissions:\n      attestations: write\n"), "attestations: write is not allowed"},
		{"job without rights under {}", "release.yml", "on: push\npermissions: {}\njobs:\n" + job(""), "no permissions (the top level is {})"},
	}
	for _, c := range cases {
		wantProblem(t, permissionProblems(mustParseWorkflow(t, c.file, c.raw)), c.want)
	}

	// The release.yml jobs may not swap their write scopes.
	swap := "on: push\npermissions: {}\njobs:\n" +
		"  build:\n    runs-on: x\n    permissions:\n      contents: write\n    steps:\n      - run: true\n" +
		"  release:\n    runs-on: x\n    permissions:\n      packages: write\n    steps:\n      - run: true\n" +
		"  docker:\n    runs-on: x\n    permissions:\n      contents: write\n    steps:\n      - run: true\n"
	p := permissionProblems(mustParseWorkflow(t, "release.yml", swap))
	wantProblem(t, p, "job build: contents: write")
	wantProblem(t, p, "job release: packages: write")
	wantProblem(t, p, "job docker: contents: write")
}

// checkoutProblems checks that no checkout keeps the token: every
// actions/checkout step sets persist-credentials: false, and every
// govulncheck-action step sets repo-checkout: false after the job's own
// checkout (the action's checkout would keep the token).
func checkoutProblems(w *workflow) []string {
	var problems []string
	for _, jn := range w.sortedJobs() {
		checkedOut := false
		for _, s := range w.Jobs[jn].Steps {
			if s.usesAction("actions/checkout") {
				if v, _ := s.with("persist-credentials"); v != "false" {
					problems = append(problems, fmt.Sprintf("%s: job %s: actions/checkout without persist-credentials: false", w.file, jn))
				}
				checkedOut = true
			}
			if s.usesAction("golang/govulncheck-action") {
				if v, _ := s.with("repo-checkout"); v != "false" {
					problems = append(problems, fmt.Sprintf("%s: job %s: govulncheck-action without repo-checkout: false", w.file, jn))
				}
				if !checkedOut {
					problems = append(problems, fmt.Sprintf("%s: job %s: govulncheck-action has no actions/checkout before it", w.file, jn))
				}
			}
		}
	}
	return problems
}

// TestWorkflows_CheckoutDropsToken pins SEC-05 (CL 108): no job in these
// workflows pushes to git, so no checkout keeps the token in .git/config.
func TestWorkflows_CheckoutDropsToken(t *testing.T) {
	checkouts, vulnchecks := 0, 0
	for _, w := range repoWorkflows(t) {
		reportProblems(t, checkoutProblems(w))
		for _, j := range w.Jobs {
			for _, s := range j.Steps {
				if s.usesAction("actions/checkout") {
					checkouts++
				}
				if s.usesAction("golang/govulncheck-action") {
					vulnchecks++
				}
			}
		}
	}
	if checkouts == 0 || vulnchecks == 0 {
		t.Fatalf("found %d checkout and %d govulncheck-action steps; the check ran on nothing", checkouts, vulnchecks)
	}
}

// TestCheckoutProblems_RejectsKeptToken is the negative test for
// checkoutProblems.
func TestCheckoutProblems_RejectsKeptToken(t *testing.T) {
	head := "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n"
	co := "      - uses: actions/checkout@x\n"
	vc := "      - uses: golang/govulncheck-action@x\n"
	cases := map[string]string{
		"checkout default":      head + co,
		"checkout true":         head + co + "        with:\n          persist-credentials: true\n",
		"vulncheck own":         head + co + "        with:\n          persist-credentials: false\n" + vc,
		"vulncheck repo true":   head + co + "        with:\n          persist-credentials: false\n" + vc + "        with:\n          repo-checkout: true\n",
		"vulncheck no checkout": head + vc + "        with:\n          repo-checkout: false\n",
	}
	for name, raw := range cases {
		if p := checkoutProblems(mustParseWorkflow(t, "x.yml", raw)); len(p) == 0 {
			t.Errorf("%s: accepted, want a problem", name)
		}
	}
}

// ---- SEC-06: release integrity ----

// attestProblems checks that the jobs that sign attestations and the jobs
// that hold id-token: write or attestations: write are the same jobs.
func attestProblems(w *workflow) []string {
	var problems []string
	for _, jn := range w.sortedJobs() {
		j := w.Jobs[jn]
		attests := false
		for _, s := range j.Steps {
			if s.usesAction("actions/attest") || s.usesAction("actions/attest-build-provenance") {
				attests = true
			}
		}
		var perms map[string]string
		if j.Permissions.Kind != 0 {
			perms, _ = permMap(j.Permissions)
		}
		signs := perms["id-token"] == "write" && perms["attestations"] == "write"
		switch {
		case attests && !signs:
			problems = append(problems, fmt.Sprintf("%s: job %s: signs an attestation without id-token: write and attestations: write", w.file, jn))
		case !attests && (perms["id-token"] == "write" || perms["attestations"] == "write"):
			problems = append(problems, fmt.Sprintf("%s: job %s: id-token or attestations write without an attestation step", w.file, jn))
		}
	}
	return problems
}

// TestWorkflows_AttestRightsOnlyWhereSigned pins SEC-05 and SEC-06 (CL 108):
// the signing rights go only to a job that signs.
func TestWorkflows_AttestRightsOnlyWhereSigned(t *testing.T) {
	for _, w := range repoWorkflows(t) {
		reportProblems(t, attestProblems(w))
	}
	bad := "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    permissions:\n      id-token: write\n    steps:\n      - run: true\n"
	wantProblem(t, attestProblems(mustParseWorkflow(t, "x.yml", bad)), "without an attestation step")
	bad = "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    permissions:\n      contents: read\n    steps:\n      - uses: actions/attest@x\n"
	wantProblem(t, attestProblems(mustParseWorkflow(t, "x.yml", bad)), "without id-token")
}

// findStep returns the index of the first step in the job that uses the
// action, or -1.
func findStep(j *wfJob, action string) int {
	for i, s := range j.Steps {
		if s.usesAction(action) {
			return i
		}
	}
	return -1
}

// TestRelease_ArchivesAttested pins SEC-06 (CL 108): the build job signs a
// provenance attestation for the archive and for the binary in it. The
// archives get no SBOM (the maintainer decided on an SBOM for the image
// only).
func TestRelease_ArchivesAttested(t *testing.T) {
	rel := repoWorkflow(t, "release.yml")
	build := rel.Jobs["build"]
	if build == nil {
		t.Fatal("release.yml: no build job")
	}
	ai := findStep(build, "actions/attest")
	if ai < 0 {
		t.Fatal("release.yml: the build job has no actions/attest step")
	}
	attest := build.Steps[ai]
	subjects, _ := attest.with("subject-path")
	if _, ok := attest.with("sbom-path"); ok {
		t.Error("release.yml build: the archive attestation has an sbom-path; the SBOM is for the image only")
	}

	// Each subject is the output of an earlier step that writes it to
	// GITHUB_OUTPUT. One is the archive and one is the binary.
	outs := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(subjects), "\n") {
		m := stepOutputRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			t.Errorf("release.yml build: subject-path line %q is not a step output", line)
			continue
		}
		found := false
		for _, s := range build.Steps[:ai] {
			if s.ID == m[1] && strings.Contains(s.Run, m[2]+"=") && strings.Contains(s.Run, "GITHUB_OUTPUT") {
				found = true
			}
		}
		if !found {
			t.Errorf("release.yml build: subject %q is not written by an earlier step", line)
		}
		outs[m[2]] = true
	}
	if !outs["archive"] || !outs["binary"] {
		t.Errorf("release.yml build: attestation subjects %v, want the archive and the binary", outs)
	}

	// The attestation is signed before the archive leaves the job.
	if ui := findStep(build, "actions/upload-artifact"); ui >= 0 && ui < ai {
		t.Error("release.yml build: the archive is uploaded before it is attested")
	}
}

// TestRelease_ImageAttestedWithSBOM pins SEC-06 (CL 108): the image gets an
// SBOM and BuildKit provenance (mode=max), and an actions/attest provenance
// attestation for the pushed digest, stored in the registry.
func TestRelease_ImageAttestedWithSBOM(t *testing.T) {
	rel := repoWorkflow(t, "release.yml")
	docker := rel.Jobs["docker"]
	if docker == nil {
		t.Fatal("release.yml: no docker job")
	}
	bi := findStep(docker, "docker/build-push-action")
	if bi < 0 {
		t.Fatal("release.yml docker: no docker/build-push-action step")
	}
	push := docker.Steps[bi]
	for key, want := range map[string]string{"sbom": "true", "provenance": "mode=max", "push": "true"} {
		if got, _ := push.with(key); got != want {
			t.Errorf("release.yml docker: build-push-action %s = %q, want %q", key, got, want)
		}
	}
	if push.ID == "" {
		t.Fatal("release.yml docker: the build-push step has no id, so its digest cannot be attested")
	}

	ai := findStep(docker, "actions/attest")
	if ai < 0 {
		t.Fatal("release.yml docker: no actions/attest step")
	}
	if ai < bi {
		t.Error("release.yml docker: the attestation runs before the image is pushed")
	}
	attest := docker.Steps[ai]
	if got, _ := attest.with("push-to-registry"); got != "true" {
		t.Errorf("release.yml docker: attest push-to-registry = %q, want true", got)
	}
	digest, _ := attest.with("subject-digest")
	m := stepOutputRE.FindStringSubmatch(strings.TrimSpace(digest))
	if m == nil || m[1] != push.ID || m[2] != "digest" {
		t.Errorf("release.yml docker: attest subject-digest %q, want ${{ steps.%s.outputs.digest }}", digest, push.ID)
	}
	if name, _ := attest.with("subject-name"); strings.TrimSpace(name) == "" {
		t.Error("release.yml docker: attest has no subject-name")
	}
}

// TestRelease_NoRestoredCache pins SEC-06 (CL 108): a release build restores
// no Go cache that another workflow saved.
func TestRelease_NoRestoredCache(t *testing.T) {
	rel := repoWorkflow(t, "release.yml")
	setups := 0
	for _, jn := range rel.sortedJobs() {
		for _, s := range rel.Jobs[jn].Steps {
			if s.usesAction("actions/setup-go") {
				setups++
				if v, ok := s.with("cache"); !ok || v != "false" {
					t.Errorf("release.yml job %s: setup-go cache = %q (set %v), want false", jn, v, ok)
				}
			}
			if s.usesAction("actions/cache") || strings.HasPrefix(s.Uses, "actions/cache/") {
				t.Errorf("release.yml job %s: uses %s", jn, s.Uses)
			}
		}
	}
	if setups == 0 {
		t.Fatal("release.yml: no setup-go step; the check ran on nothing")
	}
}

// ---- SEC-07: toolchain and binary monitoring ----

var (
	fromImageRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*(?::[0-9]+)?(?:/[a-z0-9._-]+)*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)
	golangImageRE = regexp.MustCompile(`^golang:(\d+)\.(\d+)\.(\d+)-[A-Za-z0-9._-]*@sha256:[0-9a-f]{64}$`)
	// releaseGoRE is the Go form of the sed expression in
	// .github/go-version.sh that reads the builder Go release.
	releaseGoRE = regexp.MustCompile(`^FROM .*golang:([0-9]+\.[0-9]+\.[0-9]+)-`)
)

// dockerfileProblems checks every FROM line: the image is name:tag pinned by
// sha256 digest, or the name of an earlier stage. It returns the builder Go
// version (X.Y.Z) from the one golang:X.Y.Z-... image.
func dockerfileProblems(dockerfile string) (goVersion string, problems []string) {
	stages := map[string]bool{}
	froms, golangs, sedHits := 0, 0, 0
	for i, line := range strings.Split(dockerfile, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if m := releaseGoRE.FindStringSubmatch(line); m != nil {
			sedHits++
		}
		f := strings.Fields(line)
		if len(f) == 0 || !strings.EqualFold(f[0], "FROM") {
			continue
		}
		froms++
		args := []string{}
		for _, a := range f[1:] {
			if !strings.HasPrefix(a, "--") {
				args = append(args, a)
			}
		}
		if len(args) == 0 {
			problems = append(problems, fmt.Sprintf("Dockerfile:%d: FROM without an image", i+1))
			continue
		}
		image := args[0]
		isStage := stages[strings.ToLower(image)]
		if len(args) >= 3 && strings.EqualFold(args[1], "AS") {
			stages[strings.ToLower(args[2])] = true
		}
		if isStage {
			continue
		}
		if !fromImageRE.MatchString(image) {
			problems = append(problems, fmt.Sprintf("Dockerfile:%d: image %q is not name:tag@sha256:<64 hex>", i+1, image))
		}
		if strings.HasPrefix(image, "golang:") {
			golangs++
			m := golangImageRE.FindStringSubmatch(image)
			if m == nil {
				problems = append(problems, fmt.Sprintf("Dockerfile:%d: builder %q is not golang:X.Y.Z-...@sha256:...", i+1, image))
				continue
			}
			goVersion = m[1] + "." + m[2] + "." + m[3]
		}
	}
	if froms == 0 {
		problems = append(problems, "Dockerfile: no FROM line")
	}
	if golangs != 1 {
		problems = append(problems, fmt.Sprintf("Dockerfile: want one golang builder image, found %d", golangs))
	}
	if sedHits != 1 {
		problems = append(problems, fmt.Sprintf("Dockerfile: .github/go-version.sh reads the Go release from one FROM golang:X.Y.Z- line; %d lines match", sedHits))
	}
	return goVersion, problems
}

// goModMinor returns the major.minor of the go.mod go line (1.26 for
// "go 1.26.0").
func goModMinor(t *testing.T) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^go (\d+\.\d+)(?:\.\d+)?\s*$`).FindStringSubmatch(readRepoFile(t, "go.mod"))
	if m == nil {
		t.Fatal("go.mod: no go line")
	}
	return m[1]
}

// TestDockerfile_ImagesPinnedByDigest pins SEC-07 (CL 108): both images are
// pinned by digest, the builder names an exact Go patch, and that patch is
// a release of the go.mod minor version.
func TestDockerfile_ImagesPinnedByDigest(t *testing.T) {
	v, problems := dockerfileProblems(readRepoFile(t, "Dockerfile"))
	reportProblems(t, problems)
	if minor := goModMinor(t); v != "" && !strings.HasPrefix(v, minor+".") {
		t.Errorf("Dockerfile builder Go %s is not a %s release (go.mod)", v, minor)
	}
}

// TestDockerfileProblems_RejectsUnpinned is the negative test for
// dockerfileProblems.
func TestDockerfileProblems_RejectsUnpinned(t *testing.T) {
	d := "cdfd4fe2da6b225d8b40c6b7a105736e548e83ff56d5d8f9394446eeb5eb84e0"
	builder := "FROM --platform=$BUILDPLATFORM golang:1.26.9-alpine3.24@sha256:" + d + " AS builder\n"
	runtime := "FROM alpine:3.24@sha256:" + d + "\n"

	v, p := dockerfileProblems(builder + runtime)
	if len(p) != 0 || v != "1.26.9" {
		t.Fatalf("good Dockerfile: version %q, problems %q", v, p)
	}
	// A later stage may start from an earlier one by name.
	if _, p := dockerfileProblems(builder + "FROM builder AS test\n" + runtime); len(p) != 0 {
		t.Errorf("stage reference: unexpected problems %q", p)
	}

	cases := map[string]string{
		"runtime tag only":    builder + "FROM alpine:3.24\n",
		"runtime digest only": builder + "FROM alpine@sha256:" + d + "\n",
		"short digest":        builder + "FROM alpine:3.24@sha256:" + d[:12] + "\n",
		"latest no digest":    builder + "FROM alpine:latest\n",
		"builder tag only":    "FROM golang:1.26.9-alpine3.24 AS builder\n" + runtime,
		"builder minor only":  "FROM golang:1.26-alpine3.24@sha256:" + d + " AS builder\n" + runtime,
		"builder no golang":   runtime,
		"two golang images":   builder + "FROM golang:1.26.8-alpine3.24@sha256:" + d + "\n" + runtime,
		"stage name later":    "FROM builder\n" + builder + runtime,
	}
	for name, df := range cases {
		if _, p := dockerfileProblems(df); len(p) == 0 {
			t.Errorf("%s: accepted, want a problem", name)
		}
	}
}

// weeklyCronRE matches a cron line that runs once a week: a fixed minute,
// hour, and day of the week, on every day of the month and every month.
var weeklyCronRE = regexp.MustCompile(`^\d{1,2} \d{1,2} \* \* ([0-7]|(?i:mon|tue|wed|thu|fri|sat|sun))$`)

// vulncheckProblems checks the weekly scan: a weekly schedule and a manual
// trigger, a govulncheck scan of the default branch source, and a
// -mode=binary scan of the latest release binaries.
func vulncheckProblems(w *workflow) []string {
	var problems []string
	triggers := map[string]*yaml.Node{}
	if w.On.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(w.On.Content); i += 2 {
			triggers[w.On.Content[i].Value] = w.On.Content[i+1]
		}
	}
	if _, ok := triggers["workflow_dispatch"]; !ok {
		problems = append(problems, w.file+": no workflow_dispatch trigger")
	}
	sched, ok := triggers["schedule"]
	if !ok || sched.Kind != yaml.SequenceNode || len(sched.Content) == 0 {
		problems = append(problems, w.file+": no schedule trigger")
	} else {
		for _, entry := range sched.Content {
			var e struct {
				Cron string `yaml:"cron"`
			}
			if err := entry.Decode(&e); err != nil || !weeklyCronRE.MatchString(strings.TrimSpace(e.Cron)) {
				problems = append(problems, fmt.Sprintf("%s: schedule cron %q does not run once a week", w.file, e.Cron))
			}
		}
	}

	source, binary := false, false
	for _, jn := range w.sortedJobs() {
		steps := w.Jobs[jn].Steps
		for _, s := range steps {
			if s.usesAction("golang/govulncheck-action") {
				source = true
			}
		}
		if source {
			for _, s := range steps {
				if ref, ok := s.with("ref"); ok && s.usesAction("actions/checkout") && ref != "master" {
					problems = append(problems, fmt.Sprintf("%s: job %s: the source scan checks out %q, not master", w.file, jn, ref))
				}
			}
		}
		download := -1
		for i, s := range steps {
			if strings.Contains(s.Run, "gh release download") {
				download = i
			}
			if strings.Contains(s.Run, "govulncheck -mode=binary") {
				if download < 0 || download > i {
					problems = append(problems, fmt.Sprintf("%s: job %s: the binary scan does not follow a gh release download step", w.file, jn))
				}
				binary = true
			}
		}
	}
	if !source {
		problems = append(problems, w.file+": no govulncheck source scan (golang/govulncheck-action)")
	}
	if !binary {
		problems = append(problems, w.file+": no govulncheck -mode=binary scan of the release binaries")
	}
	return problems
}

// TestVulncheck_WeeklySourceAndBinaryScan pins SEC-07 (CL 108): a new
// advisory is found in master and in the latest release within a week.
func TestVulncheck_WeeklySourceAndBinaryScan(t *testing.T) {
	reportProblems(t, vulncheckProblems(repoWorkflow(t, "vulncheck.yml")))
}

// TestVulncheckProblems_RejectsMissingParts is the negative test for
// vulncheckProblems.
func TestVulncheckProblems_RejectsMissingParts(t *testing.T) {
	jobs := "jobs:\n" +
		"  source:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@x\n      - uses: golang/govulncheck-action@x\n" +
		"  release:\n    runs-on: x\n    steps:\n      - run: gh release download\n      - run: govulncheck -mode=binary s-hole\n"
	ok := "on:\n  schedule:\n    - cron: \"17 6 * * 1\"\n  workflow_dispatch:\npermissions: {}\n" + jobs
	if p := vulncheckProblems(mustParseWorkflow(t, "vulncheck.yml", ok)); len(p) != 0 {
		t.Fatalf("good workflow: unexpected problems %q", p)
	}
	cases := map[string]string{
		"no dispatch": strings.Replace(ok, "  workflow_dispatch:\n", "", 1),
		"no schedule": strings.Replace(ok, "  schedule:\n    - cron: \"17 6 * * 1\"\n", "", 1),
		"daily":       strings.Replace(ok, "17 6 * * 1", "17 6 * * *", 1),
		"hourly":      strings.Replace(ok, "17 6 * * 1", "17 * * * 1", 1),
		"monthly":     strings.Replace(ok, "17 6 * * 1", "17 6 1 * *", 1),
		"push only":   "on: push\npermissions: {}\n" + jobs,
		"no source":   strings.Replace(ok, "      - uses: golang/govulncheck-action@x\n", "", 1),
		"no binary":   strings.Replace(ok, "govulncheck -mode=binary s-hole", "govulncheck ./...", 1),
		"no download": strings.Replace(ok, "      - run: gh release download\n", "", 1),
		"other ref":   strings.Replace(ok, "      - uses: actions/checkout@x\n", "      - uses: actions/checkout@x\n        with:\n          ref: dev\n", 1),
	}
	for name, raw := range cases {
		if p := vulncheckProblems(mustParseWorkflow(t, "vulncheck.yml", raw)); len(p) == 0 {
			t.Errorf("%s: accepted, want a problem", name)
		}
	}
}

// ---- SEC-07: one Go release, pinned in the Dockerfile ----

// CL 108, SEC-07 (decided 2026-10-09): actions/setup-go resolves a minor
// version such as "1.26" from GitHub's actions/go-versions list. That list
// was a month behind go.dev (it ended at go1.26.8 while go1.26.9 had
// security fixes), so a floating minor did not bring the Go security
// patches. The Go release is now pinned once, in the tag of the Dockerfile's
// golang builder image, and Dependabot moves it. .github/go-version.sh
// prints that release, and every workflow reads it there. setup-go downloads
// an exact release from go.dev when its list does not have it yet.

// goVersionScript is the script that prints the Go release of the
// Dockerfile pin, relative to the repository root.
const goVersionScript = ".github/go-version.sh"

// testDigest is a well-formed sha256 digest for the test Dockerfiles.
const testDigest = "cdfd4fe2da6b225d8b40c6b7a105736e548e83ff56d5d8f9394446eeb5eb84e0"

// testRuntime is a runtime stage, pinned by digest, for the test Dockerfiles.
const testRuntime = "FROM alpine:3.24@sha256:" + testDigest + "\n"

// testBuilder returns a builder FROM line for a golang image tag.
func testBuilder(tag string) string {
	return "FROM --platform=$BUILDPLATFORM golang:" + tag + "@sha256:" + testDigest + " AS builder\n"
}

var exactGoRE = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// repoGoVersion returns the X.Y.Z of the repository Dockerfile's builder
// pin, read in Go (not with the script under test).
func repoGoVersion(t *testing.T) string {
	t.Helper()
	v, problems := dockerfileProblems(readRepoFile(t, "Dockerfile"))
	reportProblems(t, problems)
	if !exactGoRE.MatchString(v) {
		t.Fatalf("Dockerfile: builder Go release %q is not X.Y.Z", v)
	}
	return v
}

// repoRoot returns the absolute path of the repository root.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// lookShell returns the path of a shell, or skips the test when the host
// has none (Windows without Git Bash).
func lookShell(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("no %s; the scripts were not run", name)
	}
	return p
}

func writeTestFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// goVersionTree makes a directory with a copy of .github/go-version.sh and
// the given Dockerfile, so a test can run a script or a step against a
// Dockerfile that is not the repository's.
func goVersionTree(t *testing.T, dockerfile string) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, filepath.FromSlash(goVersionScript)), readRepoFile(t, goVersionScript))
	writeTestFile(t, filepath.Join(dir, "Dockerfile"), dockerfile)
	return dir
}

// runGoVersionScript runs the repository's .github/go-version.sh with sh in
// dir.
func runGoVersionScript(t *testing.T, sh, dir string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	script := filepath.Join(repoRoot(t), filepath.FromSlash(goVersionScript))
	cmd := exec.Command(sh, append([]string{script}, args...)...)
	cmd.Dir = dir
	var o, e strings.Builder
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	return o.String(), e.String(), err
}

// TestGoVersionScript_PrintsDockerfilePin pins SEC-07 (CL 108): the script
// prints the X.Y.Z of the repository Dockerfile's golang builder tag as one
// line with no "go" prefix. It reads Dockerfile in the current directory by
// default, or the Dockerfile given as the first argument.
func TestGoVersionScript_PrintsDockerfilePin(t *testing.T) {
	want := repoGoVersion(t)
	first, _, _ := strings.Cut(readRepoFile(t, goVersionScript), "\n")
	if strings.TrimSuffix(first, "\r") != "#!/bin/sh" {
		t.Errorf("%s: first line %q, want #!/bin/sh (a POSIX sh script)", goVersionScript, first)
	}

	sh := lookShell(t, "sh")
	root := repoRoot(t)
	cases := []struct {
		name, dir string
		args      []string
	}{
		{"default Dockerfile", root, nil},
		{"relative argument", root, []string{"Dockerfile"}},
		{"absolute argument from another directory", t.TempDir(), []string{filepath.Join(root, "Dockerfile")}},
	}
	for _, c := range cases {
		out, errOut, err := runGoVersionScript(t, sh, c.dir, c.args...)
		if err != nil {
			t.Errorf("%s: %v\n%s", c.name, err, errOut)
			continue
		}
		if out != want+"\n" {
			t.Errorf("%s: stdout %q, want %q (one line, no go prefix)", c.name, out, want+"\n")
		}
		if errOut != "" {
			t.Errorf("%s: unexpected stderr %q", c.name, errOut)
		}
	}
}

// TestGoVersionScript_ReadsOtherPins checks that the script reads the pin
// from the Dockerfile and does not print a fixed release: a Dependabot bump
// of the tag changes what it prints.
func TestGoVersionScript_ReadsOtherPins(t *testing.T) {
	sh := lookShell(t, "sh")
	cases := []struct{ name, dockerfile, want string }{
		{"next release", testBuilder("1.27.3-alpine3.25") + testRuntime, "1.27.3"},
		{"two-digit parts", testBuilder("1.30.12-bookworm") + testRuntime, "1.30.12"},
		{"no platform flag", "FROM golang:1.26.10-alpine3.24@sha256:" + testDigest + " AS builder\n" + testRuntime, "1.26.10"},
		{"other tag in a comment", "# FROM golang:1.25.1-alpine3.22\n" + testBuilder("1.26.9-alpine3.24") + "FROM builder AS test\n" + testRuntime, "1.26.9"},
	}
	for _, c := range cases {
		dir := goVersionTree(t, c.dockerfile)
		for _, run := range []struct {
			how, dir string
			args     []string
		}{
			{"default", dir, nil},
			{"argument", t.TempDir(), []string{filepath.Join(dir, "Dockerfile")}},
		} {
			out, errOut, err := runGoVersionScript(t, sh, run.dir, run.args...)
			if err != nil || out != c.want+"\n" {
				t.Errorf("%s (%s): stdout %q, err %v, stderr %q; want %q", c.name, run.how, out, err, errOut, c.want+"\n")
			}
		}
	}
}

// wantScriptFailure checks that the script exited non-zero with a message on
// stderr and printed nothing on stdout, so a caller cannot read a partial
// or wrong release.
func wantScriptFailure(t *testing.T, name, stdout, stderr string, err error) {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Errorf("%s: err %v, want a non-zero exit status", name, err)
	}
	if stdout != "" {
		t.Errorf("%s: stdout %q, want nothing", name, stdout)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Errorf("%s: no message on stderr", name)
	}
}

// TestGoVersionScript_RejectsNoExactPin is the negative test for the script:
// with no golang:X.Y.Z- builder line, more than one, or only a tag that is
// not an exact release, it fails and prints no release.
func TestGoVersionScript_RejectsNoExactPin(t *testing.T) {
	sh := lookShell(t, "sh")
	cases := map[string]string{
		"no golang image":     testRuntime,
		"empty Dockerfile":    "",
		"minor only":          testBuilder("1.26-alpine3.24") + testRuntime,
		"minor, no suffix":    testBuilder("1.26") + testRuntime,
		"latest":              testBuilder("latest") + testRuntime,
		"alpine":              testBuilder("alpine") + testRuntime,
		"release, no suffix":  testBuilder("1.26.9") + testRuntime,
		"release candidate":   testBuilder("1.27rc1-alpine3.24") + testRuntime,
		"two releases":        testBuilder("1.26.9-alpine3.24") + testBuilder("1.26.8-alpine3.24") + testRuntime,
		"same release twice":  testBuilder("1.26.9-alpine3.24") + testBuilder("1.26.9-alpine3.24") + testRuntime,
		"pin in comment only": "# FROM golang:1.26.9-alpine3.24\n" + testRuntime,
	}
	for name, df := range cases {
		dir := goVersionTree(t, df)
		out, errOut, err := runGoVersionScript(t, sh, dir)
		wantScriptFailure(t, name, out, errOut, err)
		out, errOut, err = runGoVersionScript(t, sh, t.TempDir(), filepath.Join(dir, "Dockerfile"))
		wantScriptFailure(t, name+" (argument)", out, errOut, err)
	}

	out, errOut, err := runGoVersionScript(t, sh, t.TempDir())
	wantScriptFailure(t, "no Dockerfile in the current directory", out, errOut, err)
	out, errOut, err = runGoVersionScript(t, sh, t.TempDir(), filepath.Join("missing", "Dockerfile"))
	wantScriptFailure(t, "missing argument file", out, errOut, err)
}

// goVersionKeyRE finds a go-version, go-version-input, or go-version-file
// key in a raw workflow line, with its value.
var goVersionKeyRE = regexp.MustCompile(`^\s*(?:-\s+)?(go-version(?:-input|-file)?)\s*:\s*(.*?)\s*$`)

// goVersionCallRE finds a call of the script in a run script.
var goVersionCallRE = regexp.MustCompile(`\bsh\s+\.github/go-version\.sh\b`)

// goVersionStep is a step that writes the Go release for a setup-go or
// govulncheck-action step.
type goVersionStep struct {
	where string // file, job, and step id, for messages
	step  wfStep
}

// goVersionProblems checks SEC-07 for one workflow: every setup-go step sets
// go-version, and every govulncheck-action step sets go-version-input, to
// ${{ steps.<id>.outputs.version }}. The step <id> comes earlier in the same
// job and after a checkout, runs sh .github/go-version.sh, and writes
// version= to $GITHUB_OUTPUT. No go-version key names a release, and no step
// uses go-version-file. It returns the version steps, so a test can run them.
func goVersionProblems(w *workflow) ([]goVersionStep, []string) {
	var problems []string
	// The raw lines also find a key that the step structs do not parse, for
	// example in the with: of a reusable workflow job.
	for i, line := range strings.Split(w.raw, "\n") {
		m := goVersionKeyRE.FindStringSubmatch(strings.TrimSuffix(line, "\r"))
		if m == nil {
			continue
		}
		if m[1] == "go-version-file" {
			problems = append(problems, fmt.Sprintf("%s:%d: go-version-file; the Go release comes from %s only", w.file, i+1, goVersionScript))
			continue
		}
		val := m[2]
		if j := strings.Index(val, " #"); j >= 0 {
			val = strings.TrimSpace(val[:j])
		}
		val = strings.Trim(val, `"'`)
		if o := stepOutputRE.FindStringSubmatch(val); o == nil || o[2] != "version" {
			problems = append(problems, fmt.Sprintf("%s:%d: %s %q names a Go release; want ${{ steps.<id>.outputs.version }} from %s", w.file, i+1, m[1], val, goVersionScript))
		}
	}

	var steps []goVersionStep
	seen := map[string]bool{}
	for _, jn := range w.sortedJobs() {
		js := w.Jobs[jn].Steps
		checkout := -1
		for i, s := range js {
			if s.usesAction("actions/checkout") {
				checkout = i
				break
			}
		}
		for i, s := range js {
			where := fmt.Sprintf("%s: job %s: %s", w.file, jn, s.label())
			if _, ok := s.With["go-version-file"]; ok {
				problems = append(problems, where+": sets go-version-file")
			}
			var key string
			switch {
			case s.usesAction("actions/setup-go"):
				key = "go-version"
			case s.usesAction("golang/govulncheck-action"):
				key = "go-version-input"
			default:
				continue
			}
			v, ok := s.with(key)
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: no %s (the action then picks a Go release itself)", where, key))
				continue
			}
			m := stepOutputRE.FindStringSubmatch(strings.TrimSpace(v))
			if m == nil || m[2] != "version" {
				problems = append(problems, fmt.Sprintf("%s: %s %q is not ${{ steps.<id>.outputs.version }}", where, key, v))
				continue
			}
			src := -1
			for k := 0; k < i; k++ {
				if js[k].ID == m[1] {
					src = k
				}
			}
			if src < 0 {
				problems = append(problems, fmt.Sprintf("%s: version step %q is not an earlier step of the job", where, m[1]))
				continue
			}
			if checkout < 0 || checkout > src {
				problems = append(problems, fmt.Sprintf("%s: version step %q does not come after actions/checkout (the script needs the repository)", where, m[1]))
			}
			r := js[src].Run
			if !goVersionCallRE.MatchString(r) || !strings.Contains(r, "version=") || !strings.Contains(r, "GITHUB_OUTPUT") {
				problems = append(problems, fmt.Sprintf("%s: version step %q does not run sh %s and write version= to $GITHUB_OUTPUT", where, m[1], goVersionScript))
				continue
			}
			id := jn + "/" + m[1]
			if !seen[id] {
				seen[id] = true
				steps = append(steps, goVersionStep{fmt.Sprintf("%s: job %s: step id %q", w.file, jn, m[1]), js[src]})
			}
		}
	}
	return steps, problems
}

// runStep runs a workflow run script the way a GitHub Linux runner runs it:
// bash --noprofile --norc -eo pipefail by default, sh -e for shell: sh. It
// returns the combined output.
func runStep(t *testing.T, s wfStep, dir string, env ...string) (string, error) {
	t.Helper()
	var argv []string
	switch s.Shell {
	case "", "bash":
		argv = []string{lookShell(t, "bash"), "--noprofile", "--norc", "-eo", "pipefail"}
	case "sh":
		argv = []string{lookShell(t, "sh"), "-e"}
	default:
		t.Fatalf("%s: shell %q; this test runs only bash and sh steps", s.label(), s.Shell)
	}
	script := filepath.Join(t.TempDir(), "step.sh")
	writeTestFile(t, script, s.Run)
	cmd := exec.Command(argv[0], append(argv[1:], script)...)
	cmd.Dir = dir
	for _, kv := range os.Environ() {
		switch strings.SplitN(kv, "=", 2)[0] {
		case "BASH_ENV", "ENV", "GITHUB_OUTPUT", "GITHUB_REF_NAME":
		default:
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// versionStepProblems runs a version step twice. In the repository root it
// must write version=<want> to $GITHUB_OUTPUT. Next to a Dockerfile that the
// script rejects, it must fail: a step that swallows the script's exit
// status would hand setup-go an empty version.
func versionStepProblems(t *testing.T, where string, s wfStep, want string) []string {
	t.Helper()
	var problems []string
	out := filepath.Join(t.TempDir(), "github_output")
	if log, err := runStep(t, s, repoRoot(t), "GITHUB_OUTPUT="+out); err != nil {
		problems = append(problems, fmt.Sprintf("%s: the step fails in the repository: %v\n%s", where, err, log))
	} else {
		data, _ := os.ReadFile(out)
		if got := strings.TrimSpace(string(data)); got != "version="+want {
			problems = append(problems, fmt.Sprintf("%s: the step wrote %q to $GITHUB_OUTPUT, want %q", where, got, "version="+want))
		}
	}
	for name, df := range map[string]string{
		"no golang builder":   testRuntime,
		"a minor-only tag":    testBuilder("1.26-alpine3.24") + testRuntime,
		"two golang builders": testBuilder("1.26.9-alpine3.24") + testBuilder("1.26.8-alpine3.24") + testRuntime,
	} {
		dir := goVersionTree(t, df)
		out := filepath.Join(t.TempDir(), "github_output")
		if _, err := runStep(t, s, dir, "GITHUB_OUTPUT="+out); err == nil {
			problems = append(problems, fmt.Sprintf("%s: the step succeeds with a Dockerfile that has %s; it swallows the exit status of %s", where, name, goVersionScript))
		}
	}
	return problems
}

// TestWorkflows_GoVersionFromDockerfile pins SEC-07 (CL 108): every
// workflow builds and scans with the Go release of the Dockerfile pin, read
// with .github/go-version.sh, and names no Go release itself. When bash is
// available, the test runs each version step: it must write the pin, and it
// must fail when the script fails.
func TestWorkflows_GoVersionFromDockerfile(t *testing.T) {
	want := repoGoVersion(t)
	var all []goVersionStep
	uses := map[string]int{}
	for _, w := range repoWorkflows(t) {
		steps, problems := goVersionProblems(w)
		reportProblems(t, problems)
		all = append(all, steps...)
		for _, j := range w.Jobs {
			for _, s := range j.Steps {
				if s.usesAction("actions/setup-go") || s.usesAction("golang/govulncheck-action") {
					uses[w.file]++
				}
			}
		}
	}
	for _, f := range []string{"ci.yml", "release.yml", "vulncheck.yml"} {
		if uses[f] == 0 {
			t.Errorf("%s: no setup-go or govulncheck-action step; the check ran on nothing", f)
		}
	}
	if len(all) == 0 {
		t.Fatal("no version step found")
	}

	for _, s := range all {
		reportProblems(t, versionStepProblems(t, s.where, s.step, want))
	}
}

// TestGoVersionProblems_RejectsOtherSources is the negative test for
// goVersionProblems.
func TestGoVersionProblems_RejectsOtherSources(t *testing.T) {
	head := "  a:\n    runs-on: x\n    steps:\n"
	other := "  b:\n    runs-on: x\n    steps:\n"
	co := "      - uses: actions/checkout@x\n        with:\n          persist-credentials: false\n"
	parse := func(jobs string) *workflow {
		return mustParseWorkflow(t, "x.yml", "on: push\npermissions: {}\njobs:\n"+jobs)
	}
	vs := "      - id: go\n        run: |\n          version=\"$(sh .github/go-version.sh)\"\n          echo \"version=${version}\" >> \"$GITHUB_OUTPUT\"\n"
	setup := func(v string) string {
		return "      - uses: actions/setup-go@x\n        with:\n          go-version: " + v + "\n"
	}
	vuln := func(v string) string {
		return "      - uses: golang/govulncheck-action@x\n        with:\n          go-version-input: " + v + "\n          repo-checkout: false\n"
	}
	ref := "${{ steps.go.outputs.version }}"

	ok := head + co + vs + setup(ref) + vuln(ref)
	steps, p := goVersionProblems(parse(ok))
	if len(p) != 0 {
		t.Fatalf("good workflow: unexpected problems %q", p)
	}
	if len(steps) != 1 || steps[0].step.ID != "go" {
		t.Errorf("good workflow: version steps %v, want the one step id go", steps)
	}

	cases := map[string]string{
		"minor, quoted":           head + co + vs + setup(`"1.26"`),
		"minor, unquoted":         head + co + vs + setup("1.26"),
		"release":                 head + co + vs + setup(`"1.26.9"`),
		"go prefix":               head + co + vs + setup("go1.26.9"),
		"stable":                  head + co + vs + setup("stable"),
		"oldstable":               head + co + vs + setup("oldstable"),
		"matrix":                  head + co + vs + setup("${{ matrix.go }}"),
		"env":                     head + co + vs + setup("${{ env.GO_VERSION }}"),
		"other output":            head + co + vs + setup("${{ steps.go.outputs.other }}"),
		"vulncheck release":       head + co + vs + vuln(`"1.26.9"`),
		"vulncheck stable":        head + co + vs + vuln("stable"),
		"vulncheck no input":      head + co + "      - uses: golang/govulncheck-action@x\n        with:\n          repo-checkout: false\n",
		"setup-go no input":       head + co + "      - uses: actions/setup-go@x\n",
		"setup-go file":           head + co + "      - uses: actions/setup-go@x\n        with:\n          go-version-file: go.mod\n",
		"file next to the output": head + co + vs + setup(ref) + "          go-version-file: go.mod\n",
		"vulncheck file":          head + co + "      - uses: golang/govulncheck-action@x\n        with:\n          go-version-file: go.mod\n",
		"unknown step":            head + co + vs + "      - uses: actions/setup-go@x\n        with:\n          go-version: ${{ steps.nope.outputs.version }}\n",
		"step after":              head + co + setup(ref) + vs,
		"step in other job":       head + co + vs + other + co + setup(ref),
		"no checkout":             head + vs + setup(ref),
		"checkout after":          head + vs + co + setup(ref),
		"checkout in other job":   other + co + head + vs + setup(ref),
		"fixed release":           head + co + "      - id: go\n        run: echo \"version=1.26.9\" >> \"$GITHUB_OUTPUT\"\n" + setup(ref),
		"not run with sh":         head + co + "      - id: go\n        run: echo \"version=$(./.github/go-version.sh)\" >> \"$GITHUB_OUTPUT\"\n" + setup(ref),
		"not to GITHUB_OUTPUT":    head + co + "      - id: go\n        run: echo \"version=$(sh .github/go-version.sh)\"\n" + setup(ref),
		"reusable workflow input": head + co + vs + setup(ref) + "  b:\n    uses: o/r/.github/workflows/go.yml@x\n    with:\n      go-version: \"1.26\"\n",
	}
	for name, jobs := range cases {
		if _, p := goVersionProblems(parse(jobs)); len(p) == 0 {
			t.Errorf("%s: accepted, want a problem", name)
		}
	}
}

// TestVersionStepProblems_RejectsSwallowedFailure is the negative test for
// versionStepProblems: a step that does not pass on the script's exit
// status, or that writes a value other than the pin, is found.
func TestVersionStepProblems_RejectsSwallowedFailure(t *testing.T) {
	want := repoGoVersion(t)
	lookShell(t, "bash")
	lookShell(t, "sh")

	good := map[string]wfStep{
		"assignment":    {Run: "version=\"$(sh .github/go-version.sh)\"\necho \"version=${version}\" >> \"$GITHUB_OUTPUT\"\n"},
		"bash pipefail": {Run: "sh .github/go-version.sh | sed 's/^/version=/' >> \"$GITHUB_OUTPUT\"\n"},
		"sh assignment": {Shell: "sh", Run: "version=\"$(sh .github/go-version.sh)\"\necho \"version=${version}\" >> \"$GITHUB_OUTPUT\"\n"},
	}
	for name, s := range good {
		if p := versionStepProblems(t, name, s, want); len(p) != 0 {
			t.Errorf("%s: unexpected problems %q", name, p)
		}
	}

	bad := map[string]wfStep{
		"echo":          {Run: "echo \"version=$(sh .github/go-version.sh)\" >> \"$GITHUB_OUTPUT\"\n"},
		"printf":        {Run: "printf 'version=%s\\n' \"$(sh .github/go-version.sh)\" >> \"$GITHUB_OUTPUT\"\n"},
		"or true":       {Run: "version=\"$(sh .github/go-version.sh)\" || true\necho \"version=${version}\" >> \"$GITHUB_OUTPUT\"\n"},
		"set +e":        {Run: "set +e\nversion=\"$(sh .github/go-version.sh)\"\necho \"version=${version}\" >> \"$GITHUB_OUTPUT\"\n"},
		"local":         {Run: "f() { local version=\"$(sh .github/go-version.sh)\"; echo \"version=${version}\" >> \"$GITHUB_OUTPUT\"; }\nf\n"},
		"sh pipe":       {Shell: "sh", Run: "sh .github/go-version.sh | sed 's/^/version=/' >> \"$GITHUB_OUTPUT\"\n"},
		"fixed release": {Run: "echo \"version=" + want + "\" >> \"$GITHUB_OUTPUT\" # sh .github/go-version.sh\n"},
		"go prefix":     {Run: "version=\"go$(sh .github/go-version.sh)\"\necho \"version=${version}\" >> \"$GITHUB_OUTPUT\"\n"},
		"other key":     {Run: "version=\"$(sh .github/go-version.sh)\"\necho \"go=${version}\" >> \"$GITHUB_OUTPUT\"\n"},
	}
	for name, s := range bad {
		if p := versionStepProblems(t, name, s, want); len(p) == 0 {
			t.Errorf("%s: accepted, want a problem", name)
		}
	}
}

// releaseCreateStep returns the job and the index of the one step that
// creates the GitHub Release.
func releaseCreateStep(w *workflow) (job string, idx int, problems []string) {
	n := 0
	for _, jn := range w.sortedJobs() {
		for i, s := range w.Jobs[jn].Steps {
			if strings.Contains(s.Run, "gh release create") || s.usesAction("softprops/action-gh-release") {
				job, idx = jn, i
				n++
			}
		}
	}
	if n != 1 {
		return "", -1, []string{fmt.Sprintf("%s: want one step that creates the GitHub Release, found %d", w.file, n)}
	}
	return job, idx, nil
}

var notesFileRE = regexp.MustCompile(`--notes-file\s+"?([^"\s]+)"?`)

// releaseNotes is the step of the release job that writes the release notes.
type releaseNotes struct {
	step      wfStep
	notesFile string // the file that the create step publishes
	artifacts string // the directory that the build jobs' files are downloaded to
}

// releaseNotesProblems checks that the job that creates the GitHub Release
// has one earlier step that reads the Go release with .github/go-version.sh
// and the build jobs' goversion_<slug>.txt files, and writes the notes file
// that the create step publishes. The build jobs' files are downloaded
// before it.
func releaseNotesProblems(w *workflow) (releaseNotes, []string) {
	jn, ci, p := releaseCreateStep(w)
	if len(p) != 0 {
		return releaseNotes{}, p
	}
	j := w.Jobs[jn]
	m := notesFileRE.FindStringSubmatch(j.Steps[ci].Run)
	if m == nil {
		return releaseNotes{}, []string{fmt.Sprintf("%s: job %s: the create step publishes no --notes-file", w.file, jn)}
	}
	found, n := -1, 0
	for k := 0; k < ci; k++ {
		r := j.Steps[k].Run
		if goVersionCallRE.MatchString(r) && strings.Contains(r, "goversion_") {
			found = k
			n++
		}
	}
	if n != 1 {
		return releaseNotes{}, []string{fmt.Sprintf("%s: job %s: want one step before the release is created that reads %s and the goversion_<slug>.txt files, found %d", w.file, jn, goVersionScript, n)}
	}
	var problems []string
	notes := releaseNotes{step: j.Steps[found], notesFile: m[1]}
	if !strings.Contains(notes.step.Run, notes.notesFile) {
		problems = append(problems, fmt.Sprintf("%s: job %s: %s does not write %s", w.file, jn, notes.step.label(), notes.notesFile))
	}
	dl := findStep(j, "actions/download-artifact")
	if dl < 0 || dl > found {
		problems = append(problems, fmt.Sprintf("%s: job %s: the build jobs' files are not downloaded before %s", w.file, jn, notes.step.label()))
	} else {
		notes.artifacts, _ = j.Steps[dl].with("path")
	}
	return notes, problems
}

var goEnvVersionRE = regexp.MustCompile(`go env GOVERSION\s*>>?\s*"?([^"\s;]+)"?`)

// releaseBuildGoProblems checks that every job that runs go build writes
// go env GOVERSION to a goversion_<slug>.txt file, after setup-go, inside
// the path that the job uploads.
func releaseBuildGoProblems(w *workflow) []string {
	const slugExpr = "${{ matrix.target.slug }}"
	var problems []string
	builds := 0
	for _, jn := range w.sortedJobs() {
		j := w.Jobs[jn]
		built := false
		for _, s := range j.Steps {
			if strings.Contains(s.Run, "go build") {
				built = true
			}
		}
		if !built {
			continue
		}
		builds++
		where := fmt.Sprintf("%s: job %s", w.file, jn)
		rec, target := -1, ""
		for i, s := range j.Steps {
			if m := goEnvVersionRE.FindStringSubmatch(s.Run); m != nil {
				rec, target = i, m[1]
			}
		}
		if rec < 0 {
			problems = append(problems, where+": runs go build but does not write go env GOVERSION to a file")
			continue
		}
		if setup := findStep(j, "actions/setup-go"); setup < 0 || setup > rec {
			problems = append(problems, where+": writes go env GOVERSION before actions/setup-go")
		}
		name := strings.ReplaceAll(target, slugExpr, "linux_amd64")
		if strings.TrimSpace(j.Steps[rec].Env["SLUG"]) == slugExpr {
			name = strings.ReplaceAll(strings.ReplaceAll(name, "${SLUG}", "linux_amd64"), "$SLUG", "linux_amd64")
		}
		if path.Base(name) != "goversion_linux_amd64.txt" {
			problems = append(problems, fmt.Sprintf("%s: writes go env GOVERSION to %q, want goversion_<matrix slug>.txt", where, target))
		}
		up := findStep(j, "actions/upload-artifact")
		if up < rec {
			problems = append(problems, where+": does not upload the go env GOVERSION file after it writes it")
			continue
		}
		pats, _ := j.Steps[up].with("path")
		uploaded := false
		for _, pat := range strings.Split(pats, "\n") {
			if ok, _ := path.Match(strings.TrimSpace(pat), name); ok {
				uploaded = true
			}
		}
		if !uploaded {
			problems = append(problems, fmt.Sprintf("%s: the upload path %q does not hold %s", where, pats, target))
		}
	}
	if builds == 0 {
		problems = append(problems, w.file+": no job runs go build")
	}
	return problems
}

// testSlugs are the build targets of the test release tree.
var testSlugs = []string{"linux_amd64", "linux_arm64", "linux_armv7", "windows_amd64"}

// runReleaseNotes runs the release notes step in a directory with the given
// Dockerfile, a CHANGELOG with a 2.1.0 section, an archive per test slug,
// and a goversion_<slug>.txt file per entry of goVersions, as the build jobs
// upload them. It returns the notes file.
func runReleaseNotes(t *testing.T, n releaseNotes, dockerfile string, goVersions map[string]string) (notes, log string, err error) {
	t.Helper()
	dir := goVersionTree(t, dockerfile)
	writeTestFile(t, filepath.Join(dir, "docs", "CHANGELOG.md"), "# Changelog\n\n## [2.1.0] - 2026-10-09\n\n- A change from the CHANGELOG.\n\n## [2.0.1] - 2026-10-08\n\n- An older change.\n")
	art := filepath.Join(dir, filepath.FromSlash(strings.TrimSpace(n.artifacts)))
	for _, slug := range testSlugs {
		writeTestFile(t, filepath.Join(art, "s-hole_v2.1.0_"+slug+".tar.gz"), "archive "+slug+"\n")
	}
	for slug, v := range goVersions {
		writeTestFile(t, filepath.Join(art, "goversion_"+slug+".txt"), v+"\n")
	}
	log, err = runStep(t, n.step, dir, "GITHUB_REF_NAME=v2.1.0")
	data, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(n.notesFile)))
	return string(data), log, err
}

// allSlugs returns a goversion file content for every test slug.
func allSlugs(v string) map[string]string {
	m := map[string]string{}
	for _, s := range testSlugs {
		m[s] = v
	}
	return m
}

var buildHeadingRE = regexp.MustCompile(`(?m)^#{1,6} Build\s*$`)

// TestRelease_BuildJobsRecordGoVersion pins SEC-07 (CL 108): each release
// build job records the Go release that built its archive, in a file that
// the release job downloads.
func TestRelease_BuildJobsRecordGoVersion(t *testing.T) {
	reportProblems(t, releaseBuildGoProblems(repoWorkflow(t, "release.yml")))
}

// TestRelease_NotesNameDockerfileGo pins SEC-07 (CL 108): before the job
// creates the GitHub Release, it reads the Go release with
// .github/go-version.sh, fails when a build job used another Go release,
// and adds a Build section that names go<X.Y.Z> to the release notes. When
// bash is available, the test runs the notes step in a test tree.
func TestRelease_NotesNameDockerfileGo(t *testing.T) {
	want := repoGoVersion(t)
	n, problems := releaseNotesProblems(repoWorkflow(t, "release.yml"))
	reportProblems(t, problems)
	if len(problems) != 0 {
		t.FailNow()
	}
	lookShell(t, "bash")

	repoDockerfile := readRepoFile(t, "Dockerfile")
	good := []struct{ name, dockerfile, want string }{
		{"repository pin", repoDockerfile, want},
		{"other pin", testBuilder("1.27.3-alpine3.25") + testRuntime, "1.27.3"},
	}
	for _, c := range good {
		notes, log, err := runReleaseNotes(t, n, c.dockerfile, allSlugs("go"+c.want))
		if err != nil {
			t.Errorf("%s: the notes step failed: %v\n%s", c.name, err, log)
			continue
		}
		loc := buildHeadingRE.FindStringIndex(notes)
		if loc == nil {
			t.Errorf("%s: the release notes have no Build section:\n%s", c.name, notes)
			continue
		}
		if !strings.Contains(notes[loc[1]:], "go"+c.want) || strings.Contains(notes, "gogo") {
			t.Errorf("%s: the Build section does not name go%s:\n%s", c.name, c.want, notes)
		}
		if c.want != want && strings.Contains(notes, "go"+want) {
			t.Errorf("%s: the notes name go%s, the repository pin, not the test pin:\n%s", c.name, want, notes)
		}
		if !strings.Contains(notes, "A change from the CHANGELOG.") {
			t.Errorf("%s: the CHANGELOG section is not in the notes:\n%s", c.name, notes)
		}
	}

	// One odd release sorts before the pin and one after it, so a check
	// that reads only the first or the last line is found.
	older, newer := allSlugs("go"+want), allSlugs("go"+want)
	older["linux_armv7"] = "go1.0.0"
	newer["linux_armv7"] = "go9.0.0"
	bad := []struct {
		name, dockerfile string
		goVersions       map[string]string
	}{
		{"one build job used an older release", repoDockerfile, older},
		{"one build job used a newer release", repoDockerfile, newer},
		{"every build job used another release", repoDockerfile, allSlugs("go1.26.0")},
		{"build jobs used the floating list", testBuilder("1.27.3-alpine3.25") + testRuntime, allSlugs("go" + want)},
		{"no goversion files", repoDockerfile, nil},
		{"Dockerfile has no exact pin", testBuilder("1.26-alpine3.24") + testRuntime, allSlugs("go" + want)},
		{"Dockerfile has no golang builder", testRuntime, allSlugs("go" + want)},
	}
	for _, c := range bad {
		if _, log, err := runReleaseNotes(t, n, c.dockerfile, c.goVersions); err == nil {
			t.Errorf("%s: the notes step succeeded, want a failure before the release is created\n%s", c.name, log)
		}
	}
}

// TestReleaseGoChecks_RejectMissingParts is the negative test for
// releaseNotesProblems and releaseBuildGoProblems.
func TestReleaseGoChecks_RejectMissingParts(t *testing.T) {
	co := "      - uses: actions/checkout@x\n        with:\n          persist-credentials: false\n"
	vs := "      - id: go\n        run: |\n          version=\"$(sh .github/go-version.sh)\"\n          echo \"version=${version}\" >> \"$GITHUB_OUTPUT\"\n"
	setup := "      - uses: actions/setup-go@x\n        with:\n          go-version: ${{ steps.go.outputs.version }}\n"
	record := "      - env:\n          SLUG: ${{ matrix.target.slug }}\n        run: |\n          go build -o out/s-hole ./cmd/s-hole\n          go env GOVERSION > \"out/goversion_${SLUG}.txt\"\n"
	upload := "      - uses: actions/upload-artifact@x\n        with:\n          path: out/*\n"
	build := "  build:\n    runs-on: x\n    strategy:\n      matrix:\n        target:\n          - { slug: linux_amd64 }\n    steps:\n" + co + vs + setup + record + upload
	download := "      - uses: actions/download-artifact@x\n        with:\n          path: artifacts\n"
	notes := "      - run: |\n          go_image=\"go$(sh .github/go-version.sh)\"\n          [ \"$(sort -u artifacts/goversion_*.txt)\" = \"$go_image\" ]\n          echo \"### Build\" >> notes.md\n"
	create := "      - run: gh release create \"$TAG\" --notes-file notes.md artifacts/s-hole_*\n"
	release := func(steps string) string {
		return "  release:\n    runs-on: x\n    needs: build\n    steps:\n" + co + steps
	}
	wf := func(jobs string) *workflow {
		return mustParseWorkflow(t, "release.yml", "on: push\npermissions: {}\njobs:\n"+jobs)
	}

	ok := wf(build + release(download+notes+create))
	n, p := releaseNotesProblems(ok)
	if len(p) != 0 {
		t.Fatalf("good release: unexpected notes problems %q", p)
	}
	if n.notesFile != "notes.md" || n.artifacts != "artifacts" {
		t.Errorf("good release: notes file %q, artifacts %q", n.notesFile, n.artifacts)
	}
	if p := releaseBuildGoProblems(ok); len(p) != 0 {
		t.Fatalf("good release: unexpected build problems %q", p)
	}

	notesCases := map[string]string{
		"fixed release":        build + release(download+strings.Replace(notes, "go$(sh .github/go-version.sh)", "go1.26.9", 1)+create),
		"no goversion files":   build + release(download+strings.Replace(notes, "artifacts/goversion_*.txt", "/dev/null", 1)+create),
		"notes after create":   build + release(download+create+notes),
		"no create":            build + release(download+notes),
		"two creates":          build + release(download+notes+create+create),
		"no notes file":        build + release(download+notes+strings.Replace(create, "--notes-file notes.md ", "", 1)),
		"other notes file":     build + release(download+notes+strings.Replace(create, "notes.md", "other.md", 1)),
		"no download":          build + release(notes+create),
		"download after":       build + release(notes+download+create),
		"notes in another job": build + "  notes:\n    runs-on: x\n    steps:\n" + co + download + notes + release(download+create),
	}
	for name, jobs := range notesCases {
		if _, p := releaseNotesProblems(wf(jobs)); len(p) == 0 {
			t.Errorf("notes %s: accepted, want a problem", name)
		}
	}

	buildWith := func(steps string) string {
		return "  build:\n    runs-on: x\n    steps:\n" + steps
	}
	rel := release(download + notes + create)
	buildCases := map[string]string{
		"no record":           buildWith(co + vs + setup + strings.Replace(record, "          go env GOVERSION > \"out/goversion_${SLUG}.txt\"\n", "", 1) + upload),
		"record before setup": buildWith(co + vs + record + setup + upload),
		"no slug":             buildWith(co + vs + setup + strings.Replace(record, "goversion_${SLUG}.txt", "goversion.txt", 1) + upload),
		"fixed slug":          buildWith(co + vs + setup + strings.Replace(record, "SLUG: ${{ matrix.target.slug }}", "SLUG: linux_amd64", 1) + upload),
		"outside the upload":  buildWith(co + vs + setup + strings.Replace(record, "\"out/goversion_${SLUG}.txt\"", "\"/tmp/goversion_${SLUG}.txt\"", 1) + upload),
		"no upload":           buildWith(co + vs + setup + record),
		"upload before":       buildWith(co + vs + setup + upload + record),
		"no build job":        "",
	}
	for name, jobs := range buildCases {
		if p := releaseBuildGoProblems(wf(jobs + rel)); len(p) == 0 {
			t.Errorf("build %s: accepted, want a problem", name)
		}
	}
}

// shellcheckGlobs are the script globs that make lint-sh and the CI
// shellcheck job must both check.
var shellcheckGlobs = []string{"deploy/*.sh", ".github/*.sh"}

// isShellcheckLine reports whether a command line runs shellcheck on every
// glob in shellcheckGlobs.
func isShellcheckLine(line string) bool {
	f := strings.Fields(line)
	if len(f) == 0 || f[0] != "shellcheck" {
		return false
	}
	for _, g := range shellcheckGlobs {
		found := false
		for _, a := range f[1:] {
			if a == g {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// lintShProblems checks that the Makefile lint-sh target and a CI step run
// shellcheck on the deploy scripts and on the .github scripts.
func lintShProblems(makefile string, ci *workflow) []string {
	var problems []string
	lines := strings.Split(strings.ReplaceAll(makefile, "\r\n", "\n"), "\n")
	inTarget, found := false, false
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "lint-sh:"):
			inTarget = true
		case inTarget && strings.HasPrefix(l, "\t"):
			if isShellcheckLine(strings.TrimSpace(l)) {
				found = true
			}
		default:
			inTarget = false
		}
	}
	if !found {
		problems = append(problems, fmt.Sprintf("Makefile: lint-sh does not run shellcheck %s", strings.Join(shellcheckGlobs, " ")))
	}
	found = false
	for _, jn := range ci.sortedJobs() {
		for _, s := range ci.Jobs[jn].Steps {
			for _, l := range strings.Split(s.Run, "\n") {
				if isShellcheckLine(strings.TrimSpace(l)) {
					found = true
				}
			}
		}
	}
	if !found {
		problems = append(problems, fmt.Sprintf("%s: no step runs shellcheck %s", ci.file, strings.Join(shellcheckGlobs, " ")))
	}
	return problems
}

// TestLintSh_ChecksGoVersionScript pins SEC-07 (CL 108): shellcheck checks
// .github/go-version.sh next to the deploy scripts, in make lint-sh and in
// CI.
func TestLintSh_ChecksGoVersionScript(t *testing.T) {
	reportProblems(t, lintShProblems(readRepoFile(t, "Makefile"), repoWorkflow(t, "ci.yml")))
	matches, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "*.sh"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range matches {
		if filepath.Base(m) == "go-version.sh" {
			found = true
		}
	}
	if !found {
		t.Errorf(".github/*.sh matches %v, want %s in it", matches, goVersionScript)
	}
}

// TestLintShProblems_RejectsMissingGlob is the negative test for
// lintShProblems.
func TestLintShProblems_RejectsMissingGlob(t *testing.T) {
	ci := func(run string) *workflow {
		return mustParseWorkflow(t, "ci.yml", "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: "+run+"\n")
	}
	goodMk := "lint-sh:\n\t@command -v shellcheck >/dev/null\n\tshellcheck deploy/*.sh .github/*.sh\n"
	goodCI := ci("shellcheck deploy/*.sh .github/*.sh")
	if p := lintShProblems(goodMk, goodCI); len(p) != 0 {
		t.Fatalf("good input: unexpected problems %q", p)
	}
	for name, mk := range map[string]string{
		"deploy only":     "lint-sh:\n\tshellcheck deploy/*.sh\n",
		"workflows glob":  "lint-sh:\n\tshellcheck deploy/*.sh .github/workflows/*.sh\n",
		"other target":    "lint-sh:\n\tshellcheck deploy/*.sh\n\nlint-ci:\n\tshellcheck deploy/*.sh .github/*.sh\n",
		"no lint-sh":      "lint:\n\tshellcheck deploy/*.sh .github/*.sh\n",
		"commented out":   "lint-sh:\n\t# shellcheck deploy/*.sh .github/*.sh\n\tshellcheck deploy/*.sh\n",
		"echo, not a run": "lint-sh:\n\techo shellcheck deploy/*.sh .github/*.sh\n",
	} {
		if p := lintShProblems(mk, goodCI); len(p) == 0 {
			t.Errorf("Makefile %s: accepted, want a problem", name)
		}
	}
	for name, run := range map[string]string{
		"deploy only":    "shellcheck deploy/*.sh",
		"github only":    "shellcheck .github/*.sh",
		"workflows glob": "shellcheck deploy/*.sh .github/workflows/*.sh",
	} {
		if p := lintShProblems(goodMk, ci(run)); len(p) == 0 {
			t.Errorf("ci %s: accepted, want a problem", name)
		}
	}
}
