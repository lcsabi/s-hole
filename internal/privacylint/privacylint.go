package privacylint

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"runtime"
	"sort"
)

// Rule IDs. A //privacy:allow comment names one of them.
const (
	RuleClientAddress  = "client-address"
	RuleOutbound       = "outbound"
	RuleServerErrorLog = "server-errorlog"
	RuleMetricLabels   = "metric-labels"
	// RuleDirective is the ID of the findings about the //privacy: comments
	// themselves. No comment can allow it.
	RuleDirective = "directive"
)

// Rule is one privacy rule that the lint checks.
type Rule struct {
	// ID is the name that findings and //privacy:allow comments use.
	ID string
	// Policy is the rule from the "Privacy first" section of CLAUDE.md that
	// the check enforces.
	Policy string
	check  func(*pass)
}

// rules is every rule that the lint applies, in report order.
var rules = []*Rule{clientAddressRule, outboundRule, serverErrorLogRule, metricLabelsRule}

// Rules returns a copy of every rule that the lint applies.
func Rules() []Rule {
	out := make([]Rule, len(rules))
	for i, r := range rules {
		out[i] = Rule{ID: r.ID, Policy: r.Policy}
	}
	return out
}

func ruleByID(id string) *Rule {
	for _, r := range rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// Finding is one place where the code breaks a rule.
type Finding struct {
	// File is the path from the module root, with forward slashes (for
	// CheckFiles, the name that the caller gave).
	File    string
	Line    int
	Rule    string
	Message string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: [%s] %s", f.File, f.Line, f.Rule, f.Message)
}

// Exception is one //privacy:allow or //privacy:source comment that the code
// needs. exceptions.txt lists them all.
type Exception struct {
	File string
	// Func is the function that holds the comment: Name, (T).Name, or
	// (*T).Name. It is "-" outside a function.
	Func string
	// Kind is "allow" or "source".
	Kind string
	// Rule is the rule ID for "allow", or the source kind for "source".
	Rule string
	ID   string
}

// Result is what the lint found.
type Result struct {
	// Findings are the rule breaks that no comment allows, and the problems
	// with the comments themselves, sorted by file and line.
	Findings []Finding
	// Exceptions are the comments that allowed a finding, sorted.
	Exceptions []Exception
}

// DefaultGOOS returns the build targets that Run checks by default: the host,
// and Windows, which has files of its own (the service and the Event Log).
func DefaultGOOS() []string {
	if runtime.GOOS == "windows" {
		return []string{"windows"}
	}
	return []string{runtime.GOOS, "windows"}
}

// Run applies every rule to the main module in dir (the directory that holds
// go.mod, or one below it), once for each GOOS in goos (DefaultGOOS when
// empty), and merges the results.
func Run(dir string, goos ...string) (*Result, error) {
	if len(goos) == 0 {
		goos = DefaultGOOS()
	}
	m := newMerger()
	for _, g := range goos {
		u, err := loadModule(dir, g)
		if err != nil {
			return nil, err
		}
		m.add(u.analyze())
	}
	return m.result(), nil
}

// CheckFiles applies every rule to one package made of the given sources
// (file name to Go source), with the import path pkgPath. Imports resolve
// through the module in dir, so a source can import any package that the go
// command can resolve from dir. It checks the host GOOS only.
// The rule fixtures use it.
func CheckFiles(dir, pkgPath string, sources map[string]string) (*Result, error) {
	u, err := loadFiles(dir, runtime.GOOS, pkgPath, sources)
	if err != nil {
		return nil, err
	}
	m := newMerger()
	m.add(u.analyze())
	return m.result(), nil
}

// unit is a set of packages type-checked together for one GOOS.
type unit struct {
	fset *token.FileSet
	pkgs []*pkgInfo
	// sources are the full names (types.Func.FullName) of the functions that
	// a //privacy:source client-address comment marks.
	sources map[string]bool
}

type pkgInfo struct {
	types *types.Package
	info  *types.Info
	files []*fileInfo
}

type fileInfo struct {
	name       string
	ast        *ast.File
	src        []byte
	pkg        *pkgInfo
	directives []*directive
}

// pass is one rule applied to one file.
type pass struct {
	u     *unit
	file  *fileInfo
	info  *types.Info
	rule  *Rule
	found []rawFinding
}

type rawFinding struct {
	line int
	rule string
	msg  string
}

// report records a finding at n. The message is the specific problem; the
// rule's policy follows it.
func (p *pass) report(n ast.Node, format string, args ...any) {
	p.found = append(p.found, rawFinding{
		line: p.u.fset.Position(n.Pos()).Line,
		rule: p.rule.ID,
		msg:  fmt.Sprintf(format, args...) + " Policy: " + p.rule.Policy + ".",
	})
}

// analysis is the outcome of one unit: the findings that no comment allows,
// and every comment with whether it allowed a finding.
type analysis struct {
	findings   []Finding
	directives []*directive
}

func (u *unit) analyze() analysis {
	var a analysis
	u.sources = map[string]bool{}
	for _, p := range u.pkgs {
		for _, f := range p.files {
			bad := f.parseDirectives(u.fset)
			a.findings = append(a.findings, bad...)
			for _, d := range f.directives {
				if d.kind == "source" && d.rule == RuleClientAddress {
					if fn, ok := p.info.Defs[d.fn.Name].(*types.Func); ok {
						u.sources[fn.FullName()] = true
					}
				}
			}
		}
	}
	for _, p := range u.pkgs {
		for _, f := range p.files {
			for _, r := range rules {
				ps := &pass{u: u, file: f, info: p.info, rule: r}
				r.check(ps)
				for _, rf := range ps.found {
					if d := f.allowing(rf); d != nil {
						d.used = true
						continue
					}
					a.findings = append(a.findings, Finding{File: f.name, Line: rf.line, Rule: rf.rule, Message: rf.msg})
				}
			}
			a.directives = append(a.directives, f.directives...)
		}
	}
	return a
}

// merger joins the analyses of several GOOS passes. A file can be in some
// passes only (a _windows.go file), so a comment counts as used when any pass
// used it.
type merger struct {
	findings   map[string]Finding
	directives map[string]*directive
	order      []string
}

func newMerger() *merger {
	return &merger{findings: map[string]Finding{}, directives: map[string]*directive{}}
}

func (m *merger) add(a analysis) {
	for _, f := range a.findings {
		m.findings[f.String()] = f
	}
	for _, d := range a.directives {
		key := fmt.Sprintf("%s:%d", d.file.name, d.line)
		if old, ok := m.directives[key]; ok {
			old.used = old.used || d.used
			continue
		}
		m.directives[key] = d
		m.order = append(m.order, key)
	}
}

func (m *merger) result() *Result {
	r := &Result{}
	for _, key := range m.order {
		d := m.directives[key]
		if !d.used {
			m.findings[key+":unused"] = d.unusedFinding()
			continue
		}
		r.Exceptions = append(r.Exceptions, d.exception())
	}
	for _, f := range m.findings {
		r.Findings = append(r.Findings, f)
	}
	sort.Slice(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Message < b.Message
	})
	sortExceptions(r.Exceptions)
	return r
}

// ---- helpers for the rules ----

// calleeFunc returns the function or method that call calls, or nil (a
// builtin, a conversion, or a call of a func value).
func calleeFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	return funcOf(info, ast.Unparen(call.Fun))
}

// funcOf returns the function or method that the expression e names, or nil.
func funcOf(info *types.Info, e ast.Expr) *types.Func {
	switch e := e.(type) {
	case *ast.Ident:
		fn, _ := info.Uses[e].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		if sel, ok := info.Selections[e]; ok {
			fn, _ := sel.Obj().(*types.Func)
			return fn
		}
		fn, _ := info.Uses[e.Sel].(*types.Func)
		return fn
	case *ast.IndexExpr: // a generic function with explicit type arguments
		return funcOf(info, e.X)
	case *ast.IndexListExpr:
		return funcOf(info, e.X)
	}
	return nil
}

// calleeName returns the full name of the function that call calls, such as
// "net/http.Get" or "(*net/http.Client).Do", or "".
func calleeName(info *types.Info, call *ast.CallExpr) string {
	if fn := calleeFunc(info, call); fn != nil {
		return fn.FullName()
	}
	return ""
}

// typeName returns "path.Name" for a named type, such as "net/http.Client",
// or "" for any other type. A pointer is not followed.
func typeName(t types.Type) string {
	if t == nil {
		return ""
	}
	if n, ok := types.Unalias(t).(*types.Named); ok {
		if obj := n.Obj(); obj.Pkg() != nil {
			return obj.Pkg().Path() + "." + obj.Name()
		}
	}
	return ""
}

// derefName is typeName after one pointer is followed.
func derefName(t types.Type) string {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		return typeName(p.Elem())
	}
	return typeName(t)
}

// isBuiltinNew reports whether call calls the builtin new.
func isBuiltinNew(info *types.Info, call *ast.CallExpr) bool {
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, ok := info.Uses[id].(*types.Builtin)
	return ok && b.Name() == "new"
}

// containsCall reports whether e calls the function with the full name.
func containsCall(info *types.Info, e ast.Expr, name string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && calleeName(info, call) == name {
			found = true
		}
		return !found
	})
	return found
}

// constructions calls fn for each place in file that makes a value of a named
// type in set: a composite literal, new(T), a var declaration with no value,
// and a struct field (each value of the struct holds a ready zero value).
func constructions(p *pass, set map[string]bool, fn func(n ast.Node, name, how string)) {
	ast.Inspect(p.file.ast, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			if name := typeName(p.info.TypeOf(n)); set[name] {
				fn(n, name, "a composite literal")
			}
		case *ast.CallExpr:
			if isBuiltinNew(p.info, n) && len(n.Args) == 1 {
				if name := typeName(p.info.TypeOf(n.Args[0])); set[name] {
					fn(n, name, "new")
				}
			}
		case *ast.ValueSpec:
			if n.Type != nil && len(n.Values) == 0 {
				if name := typeName(p.info.TypeOf(n.Type)); set[name] {
					fn(n, name, "a var declaration")
				}
			}
		case *ast.StructType:
			for _, field := range n.Fields.List {
				if name := typeName(p.info.TypeOf(field.Type)); set[name] {
					fn(field, name, "a struct field")
				}
			}
		}
		return true
	})
}
