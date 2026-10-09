package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Tests for the static analysis gates of CL 111 (SEC-08). They read
// .golangci.yml, the Makefile, the CI workflow, SECURITY.md, and every Go
// file in the repository, and check:
//
//   - golangci-lint runs gosec, and nolintlint requires a linter name and a
//     reason on each //nolint, and fails a //nolint that no finding needs.
//   - gosec is off for _test.go files only: no preset, rule list, path,
//     text, or generated-file marker turns it off for other code.
//   - every //nolint in the Go files names its linters and gives a reason,
//     and no #nosec comment goes around nolintlint.
//   - `make lint` and the CI lint job use the repository config and do not
//     turn gosec off or hide findings.
//   - SECURITY.md states the gosec and CodeQL gates, and no workflow runs
//     CodeQL (default setup is a repository setting).
//
// The checks are functions over file contents, so the negative tests feed
// them broken input without editing the repository files.

// ---- Go files of the repository ----

// repoGoFiles returns every Go file of the repository as a path relative to
// the repository root, with forward slashes. It skips hidden, vendor, and
// testdata directories.
func repoGoFiles(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func isTestFile(rel string) bool { return strings.HasSuffix(rel, "_test.go") }

// repoNonTestGoFiles returns the Go files that gosec must check.
func repoNonTestGoFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, f := range repoGoFiles(t) {
		if !isTestFile(f) {
			out = append(out, f)
		}
	}
	return out
}

// TestRepoGoFiles_Found checks that the walk finds known non-test files
// (among them files that carry a //nolint:gosec), so a moved root cannot
// make the other tests pass on an empty list.
func TestRepoGoFiles_Found(t *testing.T) {
	got := map[string]bool{}
	for _, f := range repoNonTestGoFiles(t) {
		got[f] = true
	}
	for _, want := range []string{"cmd/s-hole/main.go", "internal/querylog/db.go", "internal/config/config.go", "internal/service/svc_windows.go"} {
		if !got[want] {
			t.Errorf("non-test Go file %s not found", want)
		}
	}
	for f := range got {
		if isTestFile(f) {
			t.Errorf("test file %s in the non-test list", f)
		}
	}
}

// ---- .golangci.yml ----

func yMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// yStrings reads a YAML list of scalars. A single scalar counts as a list of
// one, so a config cannot hide a value from the check by its YAML form.
func yStrings(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	default:
		return []string{fmt.Sprint(x)}
	}
}

func hasString(list []string, s string) bool {
	for _, e := range list {
		if strings.EqualFold(strings.TrimSpace(e), s) {
			return true
		}
	}
	return false
}

// yTrue reports whether a YAML value is set to something other than false,
// zero, or empty.
func yTrue(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != "" && x != "false"
	case int:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// testFileProbe is a test file path for the _test.go exclusion check.
const testFileProbe = "internal/querylog/db_test.go"

// lintConfigProblems checks a .golangci.yml against SEC-08. nonTest lists
// the non-test Go files (relative, forward slashes); an exclusion that
// matches one of them and covers gosec is a problem.
func lintConfigProblems(raw string, nonTest []string) []string {
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		return []string{fmt.Sprintf(".golangci.yml: %v", err)}
	}
	var problems []string
	add := func(format string, a ...any) {
		problems = append(problems, fmt.Sprintf(".golangci.yml: "+format, a...))
	}
	if fmt.Sprint(cfg["version"]) != "2" {
		add("version is %v, want \"2\"", cfg["version"])
	}
	linters := yMap(cfg["linters"])
	enable := yStrings(linters["enable"])
	disable := yStrings(linters["disable"])

	// gosec and nolintlint run.
	for _, l := range []string{"gosec", "nolintlint"} {
		if !hasString(enable, l) {
			add("linters.enable does not list %s", l)
		}
		if hasString(disable, l) {
			add("linters.disable lists %s", l)
		}
	}

	settings := yMap(linters["settings"])

	// nolintlint: a linter name and a reason on each //nolint, and no unused
	// //nolint.
	nl := yMap(settings["nolintlint"])
	if nl["require-specific"] != true {
		add("nolintlint.require-specific is %v, want true", nl["require-specific"])
	}
	if nl["require-explanation"] != true {
		add("nolintlint.require-explanation is %v, want true", nl["require-explanation"])
	}
	if v, ok := nl["allow-unused"]; !ok || v != false {
		add("nolintlint.allow-unused is %v, want false", v)
	}
	if yTrue(nl["allow-no-explanation"]) {
		add("nolintlint.allow-no-explanation is %v; every //nolint needs a reason", nl["allow-no-explanation"])
	}

	// gosec settings: no rule list and no threshold that drops findings.
	gs := yMap(settings["gosec"])
	for _, k := range []string{"excludes", "includes", "exclude-generated"} {
		if yTrue(gs[k]) {
			add("gosec.%s is set (%v); fix the finding or add a //nolint:gosec with a reason", k, gs[k])
		}
	}
	for _, k := range []string{"severity", "confidence"} {
		if v, ok := gs[k]; ok && !strings.EqualFold(fmt.Sprint(v), "low") {
			add("gosec.%s is %v; a higher threshold drops findings", k, v)
		}
	}

	// Exclusions.
	ex := yMap(linters["exclusions"])
	if yTrue(ex["presets"]) {
		add("linters.exclusions.presets is set (%v)", ex["presets"])
	}
	if yTrue(ex["paths-except"]) {
		add("linters.exclusions.paths-except is set (%v)", ex["paths-except"])
	}
	for _, p := range yStrings(ex["paths"]) {
		re, err := regexp.Compile(p)
		if err != nil {
			add("linters.exclusions.paths %q: %v", p, err)
			continue
		}
		for _, f := range nonTest {
			if re.MatchString(f) {
				add("linters.exclusions.paths %q turns every linter off for %s", p, f)
				break
			}
		}
	}
	testRule := false
	rules, _ := ex["rules"].([]any)
	for i, r := range rules {
		rule := yMap(r)
		rl := yStrings(rule["linters"])
		if len(rl) > 0 && !hasString(rl, "gosec") {
			continue
		}
		name := fmt.Sprintf("linters.exclusions.rules[%d]", i)
		if len(rl) == 0 {
			name += " (no linters: every linter)"
		}
		if yTrue(rule["path-except"]) {
			add("%s turns gosec off with path-except %v", name, rule["path-except"])
			continue
		}
		path, _ := rule["path"].(string)
		if path == "" {
			add("%s turns gosec off for every file (no path)", name)
			continue
		}
		re, err := regexp.Compile(path)
		if err != nil {
			add("%s path %q: %v", name, path, err)
			continue
		}
		blanket := false
		for _, f := range nonTest {
			if re.MatchString(f) {
				add("%s path %q turns gosec off for the non-test file %s", name, path, f)
				blanket = true
				break
			}
		}
		if !blanket && re.MatchString(testFileProbe) && !yTrue(rule["text"]) && !yTrue(rule["source"]) && hasString(rl, "errcheck") {
			testRule = true
		}
	}
	if !testRule {
		add("no exclusion rule turns gosec and errcheck off for _test.go files")
	}

	// issues: no setting that reports only new findings.
	issues := yMap(cfg["issues"])
	for _, k := range []string{"new", "new-from-rev", "new-from-merge-base", "new-from-patch"} {
		if yTrue(issues[k]) {
			add("issues.%s is set (%v); it hides the findings in older code", k, issues[k])
		}
	}
	return problems
}

// TestLintConfig_GosecAndNolintlint pins SEC-08 (CL 111) on the repository
// config.
func TestLintConfig_GosecAndNolintlint(t *testing.T) {
	reportProblems(t, lintConfigProblems(readRepoFile(t, ".golangci.yml"), repoNonTestGoFiles(t)))
}

// goodLintConfig is a minimal config that passes lintConfigProblems. The
// negative test changes one part of it at a time.
const goodLintConfig = `version: "2"
linters:
  default: standard
  enable:
    - errcheck
    - gosec
    - nolintlint
  settings:
    nolintlint:
      require-specific: true
      require-explanation: true
      allow-unused: false
  exclusions:
    rules:
      - path: _test\.go
        linters:
          - errcheck
          - gosec
      - path: static/
        linters:
          - misspell
`

// TestLintConfigProblems_RejectsWeakConfig is the negative test for
// lintConfigProblems.
func TestLintConfigProblems_RejectsWeakConfig(t *testing.T) {
	probe := []string{"cmd/s-hole/main.go", "internal/querylog/db.go", "internal/service/acl.go"}
	if p := lintConfigProblems(goodLintConfig, probe); len(p) != 0 {
		t.Fatalf("good config: unexpected problems %q", p)
	}
	rep := func(old, repl string) string {
		if !strings.Contains(goodLintConfig, old) {
			t.Fatalf("test bug: %q not in goodLintConfig", old)
		}
		return strings.Replace(goodLintConfig, old, repl, 1)
	}
	rules := "  exclusions:\n    rules:\n"
	cases := map[string]struct{ raw, want string }{
		"no gosec":           {rep("    - gosec\n    - nolintlint\n", "    - nolintlint\n"), "does not list gosec"},
		"gosec disabled":     {rep("  default: standard\n", "  default: standard\n  disable:\n    - gosec\n"), "linters.disable lists gosec"},
		"no nolintlint":      {rep("    - nolintlint\n", ""), "does not list nolintlint"},
		"not specific":       {rep("require-specific: true", "require-specific: false"), "require-specific"},
		"no explanation":     {rep("require-explanation: true", "require-explanation: false"), "require-explanation"},
		"explanation absent": {rep("      require-explanation: true\n", ""), "require-explanation"},
		"unused allowed":     {rep("allow-unused: false", "allow-unused: true"), "allow-unused"},
		"unused absent":      {rep("      allow-unused: false\n", ""), "allow-unused"},
		"gosec unexplained":  {rep("      allow-unused: false\n", "      allow-unused: false\n      allow-no-explanation:\n        - gosec\n"), "allow-no-explanation"},
		"gosec excludes":     {rep("    nolintlint:\n", "    gosec:\n      excludes:\n        - G304\n    nolintlint:\n"), "gosec.excludes"},
		"gosec includes":     {rep("    nolintlint:\n", "    gosec:\n      includes:\n        - G101\n    nolintlint:\n"), "gosec.includes"},
		"gosec severity":     {rep("    nolintlint:\n", "    gosec:\n      severity: high\n    nolintlint:\n"), "gosec.severity"},
		"gosec confidence":   {rep("    nolintlint:\n", "    gosec:\n      confidence: medium\n    nolintlint:\n"), "gosec.confidence"},
		"presets":            {rep(rules, "  exclusions:\n    presets:\n      - common-false-positives\n    rules:\n"), "presets"},
		"paths":              {rep(rules, "  exclusions:\n    paths:\n      - internal/\n    rules:\n"), "linters.exclusions.paths"},
		"paths-except":       {rep(rules, "  exclusions:\n    paths-except:\n      - cmd/\n    rules:\n"), "paths-except"},
		"rule text only":     {rep(rules, rules+"      - text: G304\n        linters:\n          - gosec\n"), "no path"},
		"rule all linters":   {rep(rules, rules+"      - path: internal/\n"), "every linter"},
		"rule wide path":     {rep(rules, rules+"      - path: querylog/\n        linters:\n          - gosec\n"), "internal/querylog/db.go"},
		"rule path-except":   {rep(rules, rules+"      - path-except: _test\\.go\n        linters:\n          - gosec\n"), "path-except"},
		"test rule too wide": {rep(`path: _test\.go`, `path: \.go$`), "non-test file"},
		"no test rule":       {rep("      - path: _test\\.go\n        linters:\n          - errcheck\n          - gosec\n", ""), "for _test.go files"},
		"test rule no gosec": {rep("          - errcheck\n          - gosec\n", "          - errcheck\n"), "for _test.go files"},
		"test rule errcheck": {rep("          - errcheck\n          - gosec\n", "          - gosec\n"), "for _test.go files"},
		"new only":           {goodLintConfig + "issues:\n  new: true\n", "issues.new"},
		"new from rev":       {goodLintConfig + "issues:\n  new-from-rev: HEAD~1\n", "issues.new-from-rev"},
		"version 1":          {rep(`version: "2"`, `version: "1"`), "version"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			wantProblem(t, lintConfigProblems(c.raw, probe), c.want)
		})
	}
}

// ---- //nolint and #nosec comments in the Go files ----

// nolintRE is the accepted form of a nolint directive: //nolint:<linters>
// and a reason after a second //.
var nolintRE = regexp.MustCompile(`^//nolint:([a-z0-9-]+(?:,[a-z0-9-]+)*)(?:\s*//\s*(.*?))?\s*$`)

// nolintLikeRE finds a comment that golangci-lint or nolintlint can read as
// a nolint directive, also a badly written one (a space, upper case, or the
// /* */ form). "nolintlint" in prose does not match.
var nolintLikeRE = regexp.MustCompile(`(?i)^(?://|/\*)\s*nolint(?:$|[^a-z0-9_])`)

// gosecRuleRE is a gosec rule ID at the start of a reason.
var gosecRuleRE = regexp.MustCompile(`^G\d{3}:`)

// generatedMarkers are the markers that make golangci-lint (generated mode
// "lax", the default) skip a file, in lower case.
var generatedMarkers = []string{"code generated", "do not edit", "autogenerated file", "* generated by: swagger codegen "}

// nolintProblems checks the comments of one Go file:
//
//   - every nolint directive is //nolint:<linters> // <reason>, with no
//     "all" and a reason that is not empty;
//   - a //nolint:gosec reason that starts with a rule ID has the form
//     G123: (the convention; a plain reason is also accepted);
//   - a non-test file has no #nosec comment (gosec reads it, but nolintlint
//     does not check it) and no generated-file marker before its package
//     clause (golangci-lint skips such a file).
func nolintProblems(rel string, src []byte) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.ParseComments)
	if err != nil {
		return []string{fmt.Sprintf("%s: parse: %v", rel, err)}
	}
	var problems []string
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			pos := fset.Position(c.Slash)
			where := fmt.Sprintf("%s:%d", rel, pos.Line)
			if !isTestFile(rel) && strings.Contains(strings.ToLower(c.Text), "#nosec") {
				problems = append(problems, fmt.Sprintf("%s: #nosec comment %q; use //nolint:gosec // <reason>", where, c.Text))
			}
			if !nolintLikeRE.MatchString(c.Text) {
				continue
			}
			m := nolintRE.FindStringSubmatch(c.Text)
			if m == nil {
				problems = append(problems, fmt.Sprintf("%s: %q is not //nolint:<linter> // <reason>", where, c.Text))
				continue
			}
			linters := strings.Split(m[1], ",")
			if hasString(linters, "all") {
				problems = append(problems, fmt.Sprintf("%s: %q names no specific linter", where, c.Text))
			}
			reason := strings.TrimSpace(m[2])
			if reason == "" {
				problems = append(problems, fmt.Sprintf("%s: %q gives no reason", where, c.Text))
				continue
			}
			if hasString(linters, "gosec") && regexp.MustCompile(`^G\d`).MatchString(reason) && !gosecRuleRE.MatchString(reason) {
				problems = append(problems, fmt.Sprintf("%s: %q: the rule ID is not G123: before the reason", where, c.Text))
			}
		}
	}
	if !isTestFile(rel) {
		head, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.PackageClauseOnly|parser.ParseComments)
		if err == nil {
			var doc []string
			for _, cg := range head.Comments {
				doc = append(doc, strings.TrimSpace(cg.Text()))
			}
			lower := strings.ToLower(strings.Join(doc, "\n"))
			for _, mk := range generatedMarkers {
				if strings.Contains(lower, mk) {
					problems = append(problems, fmt.Sprintf("%s: the comments before the package clause contain %q, so golangci-lint skips the file as generated", rel, mk))
				}
			}
		}
	}
	return problems
}

// TestGoFiles_NolintSpecificAndExplained pins SEC-08 (CL 111) on every Go
// file of the repository. It also counts the //nolint:gosec comments in
// non-test code, so the check cannot pass because it reads no comment.
func TestGoFiles_NolintSpecificAndExplained(t *testing.T) {
	gosecNolints := 0
	for _, rel := range repoGoFiles(t) {
		src, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		reportProblems(t, nolintProblems(rel, src))
		if isTestFile(rel) {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.ParseComments)
		if err != nil {
			continue // nolintProblems reported it
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if m := nolintRE.FindStringSubmatch(c.Text); m != nil && hasString(strings.Split(m[1], ","), "gosec") {
					gosecNolints++
				}
			}
		}
	}
	if gosecNolints == 0 {
		t.Error("found no //nolint:gosec comment in non-test code; the walk or the parse reads nothing")
	}
}

// TestNolintProblems_RejectsBadDirectives is the negative test for
// nolintProblems.
func TestNolintProblems_RejectsBadDirectives(t *testing.T) {
	file := func(comment string) []byte {
		return []byte("package p\n\nimport \"os\"\n\nfunc f(p string) {\n\t_, _ = os.Open(p) " + comment + "\n}\n")
	}
	bad := map[string]struct{ comment, want string }{
		"no linter":        {"//nolint // the path is fixed", "is not //nolint:<linter>"},
		"bare":             {"//nolint", "is not //nolint:<linter>"},
		"all":              {"//nolint:all // the path is fixed", "no specific linter"},
		"no reason":        {"//nolint:gosec", "no reason"},
		"empty reason":     {"//nolint:gosec //", "no reason"},
		"space":            {"// nolint:gosec // the path is fixed", "is not //nolint:<linter>"},
		"upper case":       {"//NOLINT:gosec // the path is fixed", "is not //nolint:<linter>"},
		"block comment":    {"/* nolint:gosec */", "is not //nolint:<linter>"},
		"reason no colon":  {"//nolint:gosec // G304 the path is fixed", "rule ID"},
		"short rule ID":    {"//nolint:gosec // G30: the path is fixed", "rule ID"},
		"nosec":            {"// #nosec G304", "#nosec"},
		"nosec in nolint":  {"//nolint:errcheck // #nosec", "#nosec"},
		"two, one missing": {"//nolint:gosec,errcheck", "no reason"},
	}
	for name, c := range bad {
		t.Run(name, func(t *testing.T) {
			wantProblem(t, nolintProblems("internal/x/x.go", file(c.comment)), c.want)
		})
	}

	gen := []byte("// Code generated by hand. DO NOT EDIT.\n\npackage p\n")
	wantProblem(t, nolintProblems("internal/x/x.go", gen), "generated")
	lax := []byte("// Package p is small; do not edit it by hand.\npackage p\n")
	wantProblem(t, nolintProblems("internal/x/x.go", lax), "generated")

	good := []string{
		"//nolint:gosec // G304: the path is fixed",
		"//nolint:gosec // the service SID is defined by SHA-1",
		"//nolint:gosec,errcheck // G104: best effort",
		"//nolint:unconvert // Dev is not uint64 on every unix",
		"// nolintlint fails a //nolint with no reason",
		"// plain comment",
	}
	for _, c := range good {
		if p := nolintProblems("internal/x/x.go", file(c)); len(p) != 0 {
			t.Errorf("%q: unexpected problems %q", c, p)
		}
	}
	// A test file may hold a #nosec text and a generated marker: gosec does
	// not check test files.
	if p := nolintProblems("internal/x/x_test.go", file("// #nosec G304")); len(p) != 0 {
		t.Errorf("#nosec in a test file: unexpected problems %q", p)
	}
}

// ---- how make lint and CI run golangci-lint ----

// lintFlagBans are golangci-lint flags that turn a linter off, use another
// config, or hide findings.
var lintFlagBans = []string{
	"--disable", "-D", "--disable-all", "--enable-only", "--default",
	"--no-config", "--config", "-c",
	"--new", "--new-from-rev", "--new-from-merge-base", "--new-from-patch",
	"--issues-exit-code", "--exclude", "--skip-dirs", "--skip-files",
}

// lintArgProblems checks a golangci-lint command line or args input.
func lintArgProblems(where, args string) []string {
	var problems []string
	for _, tok := range strings.Fields(args) {
		for _, ban := range lintFlagBans {
			if tok == ban || strings.HasPrefix(tok, ban+"=") || (len(ban) == 2 && strings.HasPrefix(tok, ban) && !strings.HasPrefix(tok, "--")) {
				problems = append(problems, fmt.Sprintf("%s: golangci-lint flag %q", where, tok))
			}
		}
	}
	return problems
}

// makefileLintRunProblems checks that the Makefile lint target runs
// `golangci-lint run` with the repository config.
func makefileLintRunProblems(makefile string) []string {
	var problems []string
	in, found := false, false
	for _, line := range strings.Split(makefile, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "lint:") {
			in = true
			continue
		}
		if !in {
			continue
		}
		if !strings.HasPrefix(line, "\t") {
			break
		}
		cmd := strings.TrimSpace(line)
		if strings.Contains(cmd, "golangci-lint") {
			if strings.Contains(cmd, "golangci-lint run") {
				found = true
			}
			if strings.HasPrefix(cmd, "-") {
				problems = append(problems, fmt.Sprintf("Makefile lint: %q ignores the exit status", cmd))
			}
			if strings.Contains(cmd, "|| true") || strings.Contains(cmd, "||true") {
				problems = append(problems, fmt.Sprintf("Makefile lint: %q ignores the exit status", cmd))
			}
			problems = append(problems, lintArgProblems("Makefile lint", cmd)...)
		}
	}
	if !found {
		problems = append(problems, "Makefile lint target does not run `golangci-lint run`")
	}
	return problems
}

// ciLintView is the part of a workflow that ciLintRunProblems reads.
type ciLintView struct {
	Jobs map[string]struct {
		ContinueOnError any `yaml:"continue-on-error"`
		Steps           []struct {
			Uses            string         `yaml:"uses"`
			With            map[string]any `yaml:"with"`
			ContinueOnError any            `yaml:"continue-on-error"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// ciLintRunProblems checks that a workflow's golangci-lint-action steps run
// the linter in full and that a failure fails the job. It returns the number
// of such steps.
func ciLintRunProblems(file, raw string) (int, []string) {
	var w ciLintView
	if err := yaml.Unmarshal([]byte(raw), &w); err != nil {
		return 0, []string{fmt.Sprintf("%s: %v", file, err)}
	}
	var problems []string
	n := 0
	names := make([]string, 0, len(w.Jobs))
	for jn := range w.Jobs {
		names = append(names, jn)
	}
	sort.Strings(names)
	for _, jn := range names {
		j := w.Jobs[jn]
		for _, s := range j.Steps {
			if !strings.HasPrefix(s.Uses, "golangci/golangci-lint-action@") {
				continue
			}
			n++
			where := fmt.Sprintf("%s: job %s: golangci-lint-action", file, jn)
			if yTrue(j.ContinueOnError) {
				problems = append(problems, fmt.Sprintf("%s: the job has continue-on-error", where))
			}
			if yTrue(s.ContinueOnError) {
				problems = append(problems, fmt.Sprintf("%s: the step has continue-on-error", where))
			}
			for _, k := range []string{"only-new-issues", "install-only"} {
				if yTrue(s.With[k]) {
					problems = append(problems, fmt.Sprintf("%s: %s is set", where, k))
				}
			}
			if args, ok := s.With["args"]; ok {
				problems = append(problems, lintArgProblems(where, fmt.Sprint(args))...)
			}
		}
	}
	return n, problems
}

// TestLint_MakeAndCIRunFullConfig pins SEC-08 (CL 111): `make lint` and the
// CI lint job run golangci-lint with .golangci.yml, so they run gosec.
func TestLint_MakeAndCIRunFullConfig(t *testing.T) {
	reportProblems(t, makefileLintRunProblems(readRepoFile(t, "Makefile")))
	total := 0
	for _, w := range repoWorkflows(t) {
		n, p := ciLintRunProblems(w.file, w.raw)
		reportProblems(t, p)
		total += n
		if w.file == "ci.yml" && n == 0 {
			t.Error("ci.yml has no golangci-lint-action step")
		}
	}
	if total == 0 {
		t.Error("no workflow runs golangci-lint-action")
	}
}

// TestLintRunChecks_RejectWeakRuns is the negative test for
// makefileLintRunProblems and ciLintRunProblems.
func TestLintRunChecks_RejectWeakRuns(t *testing.T) {
	mk := "lint:\n\tgolangci-lint run ./...\n\nlint-sh:\n\tshellcheck x\n"
	if p := makefileLintRunProblems(mk); len(p) != 0 {
		t.Fatalf("good Makefile: unexpected problems %q", p)
	}
	badMk := map[string]string{
		"disable":     "lint:\n\tgolangci-lint run --disable gosec ./...\n",
		"disable=":    "lint:\n\tgolangci-lint run --disable=gosec ./...\n",
		"-D":          "lint:\n\tgolangci-lint run -Dgosec ./...\n",
		"enable-only": "lint:\n\tgolangci-lint run --enable-only errcheck ./...\n",
		"no-config":   "lint:\n\tgolangci-lint run --no-config ./...\n",
		"config":      "lint:\n\tgolangci-lint run -c other.yml ./...\n",
		"new":         "lint:\n\tgolangci-lint run --new-from-rev HEAD~1 ./...\n",
		"exit 0":      "lint:\n\tgolangci-lint run --issues-exit-code=0 ./...\n",
		"ignored":     "lint:\n\t-golangci-lint run ./...\n",
		"or true":     "lint:\n\tgolangci-lint run ./... || true\n",
		"no run":      "lint:\n\tgo vet ./...\n",
		"no target":   "check:\n\tgolangci-lint run ./...\n",
	}
	for name, m := range badMk {
		if p := makefileLintRunProblems(m); len(p) == 0 {
			t.Errorf("Makefile %s: accepted, want a problem", name)
		}
	}

	head := "on: push\njobs:\n  lint:\n    runs-on: ubuntu-latest\n"
	step := "    steps:\n      - uses: golangci/golangci-lint-action@x\n        with:\n          version: v2.14.0\n"
	if n, p := ciLintRunProblems("ci.yml", head+step); n != 1 || len(p) != 0 {
		t.Fatalf("good workflow: n=%d, problems %q", n, p)
	}
	badCI := map[string]string{
		"args disable":   head + step + "          args: --disable=gosec\n",
		"args config":    head + step + "          args: --config other.yml\n",
		"only new":       head + step + "          only-new-issues: true\n",
		"install only":   head + step + "          install-only: true\n",
		"step continue":  head + step + "        continue-on-error: true\n",
		"job continue":   head + "    continue-on-error: true\n" + step,
		"args new":       head + step + "          args: --new\n",
		"args exit code": head + step + "          args: --issues-exit-code 0\n",
	}
	for name, raw := range badCI {
		if _, p := ciLintRunProblems("ci.yml", raw); len(p) == 0 {
			t.Errorf("workflow %s: accepted, want a problem", name)
		}
	}
}

// ---- SECURITY.md and CodeQL ----

// postureBullets returns the top-level bullets of the "Defensive Posture
// (Summary)" section of SECURITY.md, each with the whitespace folded and the
// backticks removed.
func postureBullets(md string) ([]string, bool) {
	const heading = "## Defensive Posture (Summary)"
	i := strings.Index(md, heading)
	if i < 0 {
		return nil, false
	}
	sec := md[i+len(heading):]
	if j := strings.Index(sec, "\n## "); j >= 0 {
		sec = sec[:j]
	}
	var bullets []string
	cur := ""
	flush := func() {
		if b := strings.Join(strings.Fields(strings.ReplaceAll(cur, "`", "")), " "); b != "" {
			bullets = append(bullets, b)
		}
		cur = ""
	}
	for _, line := range strings.Split(strings.ReplaceAll(sec, "\r", ""), "\n") {
		if strings.HasPrefix(line, "- ") {
			flush()
		}
		cur += " " + line
	}
	flush()
	return bullets, true
}

// securityGateTerms are the facts that the section must state, each as one
// or more accepted wordings (lower case). A fact counts only in a bullet that
// names its gate ("gosec" or "codeql"), so a word in another bullet (the
// weekly govulncheck scan of master) does not count.
var securityGateTerms = []struct {
	gate  string
	fact  string
	words []string
}{
	{"gosec", "gosec runs in golangci-lint", []string{"golangci-lint"}},
	{"gosec", "make lint runs gosec", []string{"make lint"}},
	{"gosec", "the CI lint job runs gosec", []string{"lint job"}},
	{"gosec", "the lint job is required before merge", []string{"cannot merge", "required", "before merge", "before a merge"}},
	{"gosec", "a finding is fixed or has a reasoned nolint", []string{"//nolint:gosec"}},
	{"gosec", "nolintlint checks the nolint comments", []string{"nolintlint"}},
	{"gosec", "gosec does not check tests", []string{"test files", "tests"}},
	{"codeql", "CodeQL uses default setup", []string{"default setup"}},
	{"codeql", "CodeQL checks the Go code", []string{"go code"}},
	{"codeql", "CodeQL checks the workflows", []string{"workflows"}},
	{"codeql", "CodeQL checks the dashboard script", []string{"dashboard script"}},
	{"codeql", "CodeQL runs on push to master", []string{"master"}},
	{"codeql", "CodeQL runs on pull requests", []string{"pull request"}},
	{"codeql", "CodeQL runs weekly", []string{"week"}},
	{"codeql", "CodeQL findings are code scanning alerts", []string{"code scanning"}},
}

// securityGateProblems checks that SECURITY.md states the gosec and CodeQL
// gates in its "Defensive Posture (Summary)" list.
func securityGateProblems(md string) []string {
	bullets, ok := postureBullets(md)
	if !ok {
		return []string{"SECURITY.md: no \"## Defensive Posture (Summary)\" section"}
	}
	gateText := map[string]string{}
	for _, b := range bullets {
		lower := strings.ToLower(b)
		for _, gate := range []string{"gosec", "codeql"} {
			if strings.Contains(lower, gate) {
				gateText[gate] += " " + lower
			}
		}
	}
	var problems []string
	for _, gate := range []string{"gosec", "codeql"} {
		if gateText[gate] == "" {
			problems = append(problems, fmt.Sprintf("SECURITY.md Defensive Posture: no bullet names %s", gate))
		}
	}
	for _, term := range securityGateTerms {
		text := gateText[term.gate]
		if text == "" {
			continue
		}
		found := false
		for _, w := range term.words {
			if strings.Contains(text, w) {
				found = true
				break
			}
		}
		if !found {
			problems = append(problems, fmt.Sprintf("SECURITY.md Defensive Posture: does not state that %s (want one of %q)", term.fact, term.words))
		}
	}
	return problems
}

// TestSecurityMD_StaticAnalysisGates pins SEC-08 (CL 111) in SECURITY.md.
func TestSecurityMD_StaticAnalysisGates(t *testing.T) {
	reportProblems(t, securityGateProblems(readRepoFile(t, "SECURITY.md")))
}

// TestSecurityGateProblems_RejectsMissingGates is the negative test for
// securityGateProblems. It removes one fact at a time from the gate bullets
// of the repository text and keeps the other bullets.
func TestSecurityGateProblems_RejectsMissingGates(t *testing.T) {
	md := readRepoFile(t, "SECURITY.md")
	if p := securityGateProblems(md); len(p) != 0 {
		t.Skipf("SECURITY.md fails the check itself (TestSecurityMD_StaticAnalysisGates reports it): %q", p)
	}
	bullets, _ := postureBullets(md)
	build := func(edit func(b string) string) string {
		var sb strings.Builder
		sb.WriteString("## Defensive Posture (Summary)\n\n")
		for _, b := range bullets {
			sb.WriteString(edit(b) + "\n")
		}
		return sb.String()
	}
	if p := securityGateProblems(build(func(b string) string { return b })); len(p) != 0 {
		t.Fatalf("rebuilt section: unexpected problems %q", p)
	}
	// The section without the posture heading counts as no section.
	wantProblem(t, securityGateProblems(strings.Replace(md, "## Defensive Posture (Summary)", "## Defensive Posture", 1)), "no \"## Defensive Posture")
	// Bullets after the section do not count.
	moved := "## Defensive Posture (Summary)\n\n- Private by default.\n\n## Other\n\n" + strings.Join(bullets, "\n") + "\n"
	wantProblem(t, securityGateProblems(moved), "no bullet names gosec")
	wantProblem(t, securityGateProblems(moved), "no bullet names codeql")
	// Each fact, removed from the bullets of its gate, gives a problem.
	for _, term := range securityGateTerms {
		doc := build(func(b string) string {
			lower := strings.ToLower(b)
			if !strings.Contains(lower, term.gate) {
				return b
			}
			for _, w := range term.words {
				lower = strings.ReplaceAll(lower, w, "")
			}
			return lower
		})
		wantProblem(t, securityGateProblems(doc), term.fact)
	}
	// A CodeQL bullet that leaves out the triggers fails even though the
	// build bullet says "weekly" and "master".
	noTriggers := build(func(b string) string {
		lower := strings.ToLower(b)
		if !strings.Contains(lower, "codeql") {
			return b
		}
		lower = strings.ReplaceAll(lower, "master", "")
		return strings.ReplaceAll(lower, "week", "")
	})
	wantProblem(t, securityGateProblems(noTriggers), "on push to master")
	wantProblem(t, securityGateProblems(noTriggers), "weekly")
}

// codeqlWorkflowProblems reports a workflow that runs CodeQL. CL 111 uses
// CodeQL default setup, a repository setting; GitHub refuses the results of
// an advanced-setup workflow while default setup is on.
func codeqlWorkflowProblems(file, raw string) []string {
	if regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s*["']?github/codeql-action/`).MatchString(raw) {
		return []string{fmt.Sprintf("%s: runs github/codeql-action; CodeQL uses default setup (a repository setting), not a workflow", file)}
	}
	return nil
}

// TestWorkflows_NoCodeQLWorkflow pins the CodeQL default setup of CL 111.
func TestWorkflows_NoCodeQLWorkflow(t *testing.T) {
	for _, w := range repoWorkflows(t) {
		reportProblems(t, codeqlWorkflowProblems(w.file, w.raw))
	}
	bad := "jobs:\n  analyze:\n    steps:\n      - uses: github/codeql-action/init@0123456789012345678901234567890123456789 # v4.0.0\n"
	wantProblem(t, codeqlWorkflowProblems("codeql.yml", bad), "codeql-action")
}

// ---- the Windows build is linted too ----

// makeTarget returns the prerequisites and the recipe lines of a Makefile
// target, and every target-specific variable line (`name: export X=Y` or
// `name: X=Y`).
func makeTarget(makefile, name string) (prereqs []string, recipe []string, vars []string, found bool) {
	lines := strings.Split(strings.ReplaceAll(makefile, "\r", ""), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if !strings.HasPrefix(line, name+":") || strings.HasPrefix(line, name+":=") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, name+":"))
		if strings.HasPrefix(rest, "export ") || strings.Contains(rest, "=") {
			vars = append(vars, rest)
			continue
		}
		found = true
		prereqs = append(prereqs, strings.Fields(rest)...)
		for i+1 < len(lines) && strings.HasPrefix(lines[i+1], "\t") {
			i++
			recipe = append(recipe, strings.TrimSpace(lines[i]))
		}
	}
	return prereqs, recipe, vars, found
}

// targetVarRE is a target-specific GOOS=windows line.
var targetVarRE = regexp.MustCompile(`^(?:export\s+)?GOOS\s*:?=\s*windows$`)

// makefileWindowsLintProblems checks the lint-windows target: it is phony,
// sets GOOS=windows for its recipe, runs `golangci-lint run ./...` with the
// repository config, and `make lint` runs it.
func makefileWindowsLintProblems(makefile string) []string {
	var problems []string
	phony := false
	for _, line := range strings.Split(strings.ReplaceAll(makefile, "\r", ""), "\n") {
		if strings.HasPrefix(line, ".PHONY:") && hasString(strings.Fields(strings.TrimPrefix(line, ".PHONY:")), "lint-windows") {
			phony = true
		}
	}
	if !phony {
		problems = append(problems, "Makefile: lint-windows is not in .PHONY")
	}
	_, recipe, vars, found := makeTarget(makefile, "lint-windows")
	if !found {
		return append(problems, "Makefile: no lint-windows target")
	}
	goos := false
	for _, v := range vars {
		if targetVarRE.MatchString(v) {
			goos = true
		}
	}
	runs := false
	for _, cmd := range recipe {
		if !strings.Contains(cmd, "golangci-lint") {
			continue
		}
		if regexp.MustCompile(`(?:^|\s)GOOS=windows\s`).MatchString(cmd) {
			goos = true
		} else if strings.Contains(cmd, "GOOS=") {
			problems = append(problems, fmt.Sprintf("Makefile lint-windows: %q sets another GOOS", cmd))
		}
		if strings.Contains(cmd, "golangci-lint run") && strings.Contains(cmd, "./...") {
			runs = true
		}
		if strings.HasPrefix(cmd, "-") || strings.Contains(cmd, "|| true") || strings.Contains(cmd, "||true") {
			problems = append(problems, fmt.Sprintf("Makefile lint-windows: %q ignores the exit status", cmd))
		}
		problems = append(problems, lintArgProblems("Makefile lint-windows", cmd)...)
	}
	if !goos {
		problems = append(problems, "Makefile lint-windows: GOOS=windows is not set for the recipe")
	}
	if !runs {
		problems = append(problems, "Makefile lint-windows: the recipe does not run `golangci-lint run ./...`")
	}
	prereqs, lintRecipe, _, _ := makeTarget(makefile, "lint")
	called := hasString(prereqs, "lint-windows")
	for _, cmd := range lintRecipe {
		if strings.Contains(cmd, "$(MAKE)") && strings.Contains(cmd, "lint-windows") {
			called = true
		}
	}
	if !called {
		problems = append(problems, "Makefile: `make lint` does not run lint-windows")
	}
	return problems
}

// TestMakefile_LintWindows pins CL 111 (SEC-08): `make lint` also lints the
// Windows build.
func TestMakefile_LintWindows(t *testing.T) {
	reportProblems(t, makefileWindowsLintProblems(readRepoFile(t, "Makefile")))
}

// TestMakefileWindowsLintProblems_RejectsBadTargets is the negative test for
// makefileWindowsLintProblems.
func TestMakefileWindowsLintProblems_RejectsBadTargets(t *testing.T) {
	good := ".PHONY: lint lint-windows\n\nlint: lint-windows\n\tgolangci-lint run ./...\n\nlint-windows: export GOOS=windows\nlint-windows:\n\tgolangci-lint run ./...\n"
	if p := makefileWindowsLintProblems(good); len(p) != 0 {
		t.Fatalf("good Makefile: unexpected problems %q", p)
	}
	// An inline GOOS on the command and a $(MAKE) call are also correct.
	inline := ".PHONY: lint lint-windows\n\nlint:\n\tgolangci-lint run ./...\n\t$(MAKE) lint-windows\n\nlint-windows:\n\tGOOS=windows golangci-lint run ./...\n"
	if p := makefileWindowsLintProblems(inline); len(p) != 0 {
		t.Errorf("inline Makefile: unexpected problems %q", p)
	}
	rep := func(old, repl string) string {
		if !strings.Contains(good, old) {
			t.Fatalf("test bug: %q not in the good Makefile", old)
		}
		return strings.Replace(good, old, repl, 1)
	}
	cases := map[string]struct{ mk, want string }{
		"not phony":     {rep(".PHONY: lint lint-windows", ".PHONY: lint"), ".PHONY"},
		"no target":     {rep("lint-windows: export GOOS=windows\nlint-windows:\n\tgolangci-lint run ./...\n", ""), "no lint-windows target"},
		"no GOOS":       {rep("lint-windows: export GOOS=windows\n", ""), "GOOS=windows is not set"},
		"GOOS linux":    {rep("export GOOS=windows", "export GOOS=linux"), "GOOS=windows is not set"},
		"recipe GOOS":   {rep("lint-windows:\n\tgolangci-lint", "lint-windows:\n\tGOOS=linux golangci-lint"), "sets another GOOS"},
		"lint skips it": {rep("lint: lint-windows\n", "lint:\n"), "does not run lint-windows"},
		"no run":        {rep("lint-windows:\n\tgolangci-lint run ./...\n", "lint-windows:\n\tgo vet ./...\n"), "does not run `golangci-lint run ./...`"},
		"one package":   {rep("lint-windows:\n\tgolangci-lint run ./...\n", "lint-windows:\n\tgolangci-lint run ./cmd/s-hole\n"), "does not run `golangci-lint run ./...`"},
		"disable gosec": {rep("lint-windows:\n\tgolangci-lint run ./...\n", "lint-windows:\n\tgolangci-lint run --disable=gosec ./...\n"), "--disable=gosec"},
		"exit ignored":  {rep("lint-windows:\n\tgolangci-lint run ./...\n", "lint-windows:\n\t-golangci-lint run ./...\n"), "ignores the exit status"},
		"other config":  {rep("lint-windows:\n\tgolangci-lint run ./...\n", "lint-windows:\n\tgolangci-lint run -c win.yml ./...\n"), "\"-c\""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			wantProblem(t, makefileWindowsLintProblems(c.mk), c.want)
		})
	}
}

// ciJobView is the part of a job that ciWindowsLintProblems reads beyond the
// shared wfJob type.
type ciJobView struct {
	Jobs map[string]struct {
		Name     string            `yaml:"name"`
		Strategy any               `yaml:"strategy"`
		Env      map[string]string `yaml:"env"`
	} `yaml:"jobs"`
}

// ciWindowsLintProblems checks the CI lint job: it stays one job named lint
// (the required check), with a golangci-lint-action step for the runner's
// OS and one with GOOS=windows. Both use the same pinned action, and their
// version is the Makefile pin (lintActionProblems checks how).
func ciWindowsLintProblems(w *workflow) []string {
	var problems []string
	var view ciJobView
	if err := yaml.Unmarshal([]byte(w.raw), &view); err != nil {
		return []string{fmt.Sprintf("%s: %v", w.file, err)}
	}
	j, ok := w.Jobs["lint"]
	if !ok {
		return []string{fmt.Sprintf("%s: no job lint (the required check)", w.file)}
	}
	jv := view.Jobs["lint"]
	if jv.Name != "" && jv.Name != "lint" {
		problems = append(problems, fmt.Sprintf("%s: job lint is named %q; the required check is lint", w.file, jv.Name))
	}
	if jv.Strategy != nil {
		problems = append(problems, fmt.Sprintf("%s: job lint has a strategy; a matrix renames the required lint check", w.file))
	}
	if g, ok := jv.Env["GOOS"]; ok {
		problems = append(problems, fmt.Sprintf("%s: job lint sets GOOS=%s for every step", w.file, g))
	}
	var native, windows []wfStep
	for _, s := range j.Steps {
		if !s.usesAction("golangci/golangci-lint-action") {
			continue
		}
		switch g, set := s.Env["GOOS"]; {
		case !set:
			native = append(native, s)
		case g == "windows":
			windows = append(windows, s)
		default:
			problems = append(problems, fmt.Sprintf("%s: job lint: %s sets GOOS=%s", w.file, s.label(), g))
		}
	}
	if len(native) == 0 {
		problems = append(problems, fmt.Sprintf("%s: job lint has no golangci-lint-action step for the runner's OS", w.file))
	}
	if len(windows) == 0 {
		problems = append(problems, fmt.Sprintf("%s: job lint has no golangci-lint-action step with env GOOS: windows", w.file))
	}
	if len(native) > 0 {
		for _, s := range windows {
			if s.Uses != native[0].Uses {
				problems = append(problems, fmt.Sprintf("%s: job lint: the Windows step uses %q, the first step %q", w.file, s.Uses, native[0].Uses))
			}
			if a, b := fmt.Sprint(s.With["version"].Value), fmt.Sprint(native[0].With["version"].Value); a != b {
				problems = append(problems, fmt.Sprintf("%s: job lint: the Windows step version %q differs from the first step %q", w.file, a, b))
			}
		}
	}
	_, p := lintActionProblems(w)
	problems = append(problems, p...)
	return problems
}

// TestCI_LintWindows pins CL 111 (SEC-08): the CI lint job also lints the
// Windows build.
func TestCI_LintWindows(t *testing.T) {
	ci := repoWorkflow(t, "ci.yml")
	reportProblems(t, ciWindowsLintProblems(ci))
	reportProblems(t, pinProblems(ci))
}

// TestCIWindowsLintProblems_RejectsBadJobs is the negative test for
// ciWindowsLintProblems.
func TestCIWindowsLintProblems_RejectsBadJobs(t *testing.T) {
	const sha = "@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a # v9.3.0"
	head := "on: push\npermissions: {}\njobs:\n  lint:\n    name: lint\n    runs-on: ubuntu-latest\n    steps:\n"
	readStep := "      - id: lintver\n        run: echo \"version=$(sed -n 's/^GOLANGCI_LINT_VERSION ?= //p' Makefile)\" >> \"$GITHUB_OUTPUT\"\n"
	ver := "        with:\n          version: ${{ steps.lintver.outputs.version }}\n"
	native := "      - name: golangci-lint\n        uses: golangci/golangci-lint-action" + sha + "\n" + ver
	win := "      - name: golangci-lint (Windows build)\n        uses: golangci/golangci-lint-action" + sha + "\n        env:\n          GOOS: windows\n" + ver
	good := head + readStep + native + win
	if p := ciWindowsLintProblems(mustParseWorkflow(t, "ci.yml", good)); len(p) != 0 {
		t.Fatalf("good workflow: unexpected problems %q", p)
	}
	cases := map[string]struct{ raw, want string }{
		"linux only":       {head + readStep + native, "no golangci-lint-action step with env GOOS: windows"},
		"windows only":     {head + readStep + win, "for the runner's OS"},
		"GOOS linux":       {head + readStep + native + strings.Replace(win, "GOOS: windows", "GOOS: linux", 1), "sets GOOS=linux"},
		"job GOOS":         {strings.Replace(head, "    runs-on:", "    env:\n      GOOS: windows\n    runs-on:", 1) + readStep + native + win, "sets GOOS=windows for every step"},
		"matrix":           {strings.Replace(head, "    runs-on:", "    strategy:\n      matrix:\n        goos: [linux, windows]\n    runs-on:", 1) + readStep + native + win, "strategy"},
		"renamed":          {strings.Replace(head, "name: lint", "name: lint (linux)", 1) + readStep + native + win, "is named"},
		"no lint job":      {strings.Replace(good, "  lint:\n", "  golangci:\n", 1), "no job lint"},
		"hard-coded":       {head + readStep + native + strings.Replace(win, "${{ steps.lintver.outputs.version }}", "v2.14.0", 1), "does not come from the Makefile"},
		"other output":     {head + readStep + native + strings.Replace(win, "outputs.version", "outputs.other", 1), "version"},
		"no version":       {head + readStep + native + strings.TrimSuffix(win, ver), "no version input"},
		"other action pin": {head + readStep + native + strings.Replace(win, "ba0d7d2e", "0000000e", 1), "the Windows step uses"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			wantProblem(t, ciWindowsLintProblems(mustParseWorkflow(t, "ci.yml", c.raw)), c.want)
		})
	}
	// pinProblems (CL 108) also covers the Windows step: a tag is refused.
	tagged := head + readStep + native + strings.Replace(win, sha, "@v9", 1)
	wantProblem(t, pinProblems(mustParseWorkflow(t, "ci.yml", tagged)), "golangci-lint-action@v9")
}
