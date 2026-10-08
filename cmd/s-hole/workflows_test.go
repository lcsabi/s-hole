package main

import (
	"fmt"
	"os"
	"os/exec"
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
//   - SEC-07: the Docker images are pinned by digest, the workflows follow the
//     newest Go patch of the go.mod minor release, and a weekly scan checks
//     master and the latest release binaries.
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
	// releaseGoRE is the Go form of the sed expression in release.yml that
	// reads the builder Go version for the release notes.
	releaseGoRE = regexp.MustCompile(`^FROM .*golang:([0-9][0-9.]*)-`)
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
		problems = append(problems, fmt.Sprintf("Dockerfile: the release notes read the Go version from one FROM golang:X.Y.Z- line; %d lines match", sedHits))
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

// TestRelease_GoVersionFromDockerfile pins SEC-07 (CL 108): the release notes
// name the builder Go version, which the release job reads from the
// Dockerfile with sed. When a POSIX shell is available, the test runs that
// sed command against the Dockerfile.
func TestRelease_GoVersionFromDockerfile(t *testing.T) {
	want, problems := dockerfileProblems(readRepoFile(t, "Dockerfile"))
	reportProblems(t, problems)

	rel := repoWorkflow(t, "release.yml")
	sedRE := regexp.MustCompile(`sed -n '([^']+)' Dockerfile`)
	var exprs []string
	for _, jn := range rel.sortedJobs() {
		for _, s := range rel.Jobs[jn].Steps {
			for _, m := range sedRE.FindAllStringSubmatch(s.Run, -1) {
				exprs = append(exprs, m[1])
			}
		}
	}
	if len(exprs) != 1 {
		t.Fatalf("release.yml: want one sed command that reads the Go version from the Dockerfile, found %d", len(exprs))
	}

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX shell; the sed command was not run")
	}
	cmd := exec.Command(sh, "-c", "sed -n '"+exprs[0]+"' Dockerfile")
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run the sed command: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "go"+want {
		t.Errorf("release.yml sed reads %q from the Dockerfile, want %q", got, "go"+want)
	}
}

// goVersionProblems checks that every setup-go step and every
// govulncheck-action step asks for the go.mod minor version as a quoted
// string, with no patch, so each run gets the newest patch.
func goVersionProblems(w *workflow, minor string) []string {
	var problems []string
	check := func(jn string, s wfStep, key string) {
		n, ok := s.With[key]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s: job %s: %s has no %s", w.file, jn, s.label(), key))
		case n.Tag != "!!str" || n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) == 0:
			problems = append(problems, fmt.Sprintf("%s: job %s: %s %s %s is not a quoted string (YAML reads 1.30 as 1.3)", w.file, jn, s.label(), key, n.Value))
		case n.Value != minor:
			problems = append(problems, fmt.Sprintf("%s: job %s: %s %s = %q, want %q (the minor release, no patch)", w.file, jn, s.label(), key, n.Value, minor))
		}
		if _, ok := s.With["go-version-file"]; ok {
			problems = append(problems, fmt.Sprintf("%s: job %s: %s sets go-version-file", w.file, jn, s.label()))
		}
	}
	for _, jn := range w.sortedJobs() {
		for _, s := range w.Jobs[jn].Steps {
			switch {
			case s.usesAction("actions/setup-go"):
				check(jn, s, "go-version")
			case s.usesAction("golang/govulncheck-action"):
				check(jn, s, "go-version-input")
			}
		}
	}
	return problems
}

// TestWorkflows_GoVersionMinorOnly pins SEC-07 (CL 108): the workflows keep
// the minor version ("1.26"), so Go patches arrive without a change here.
func TestWorkflows_GoVersionMinorOnly(t *testing.T) {
	minor := goModMinor(t)
	for _, w := range repoWorkflows(t) {
		reportProblems(t, goVersionProblems(w, minor))
	}
}

// TestGoVersionProblems_RejectsPatchPin is the negative test for
// goVersionProblems.
func TestGoVersionProblems_RejectsPatchPin(t *testing.T) {
	head := "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n"
	cases := map[string]string{
		"patch":       head + "      - uses: actions/setup-go@x\n        with:\n          go-version: \"1.26.9\"\n",
		"unquoted":    head + "      - uses: actions/setup-go@x\n        with:\n          go-version: 1.26\n",
		"other minor": head + "      - uses: actions/setup-go@x\n        with:\n          go-version: \"1.25\"\n",
		"missing":     head + "      - uses: actions/setup-go@x\n",
		"file":        head + "      - uses: actions/setup-go@x\n        with:\n          go-version: \"1.26\"\n          go-version-file: go.mod\n",
		"vulncheck":   head + "      - uses: golang/govulncheck-action@x\n        with:\n          go-version-input: \"1.26.9\"\n",
		"stable":      head + "      - uses: actions/setup-go@x\n        with:\n          go-version: stable\n",
	}
	for name, raw := range cases {
		if p := goVersionProblems(mustParseWorkflow(t, "x.yml", raw), "1.26"); len(p) == 0 {
			t.Errorf("%s: accepted, want a problem", name)
		}
	}
	ok := head + "      - uses: actions/setup-go@x\n        with:\n          go-version: \"1.26\"\n"
	if p := goVersionProblems(mustParseWorkflow(t, "x.yml", ok), "1.26"); len(p) != 0 {
		t.Errorf("good workflow: unexpected problems %q", p)
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
