package privacylint

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"sort"
	"strings"
)

// A directive is one //privacy: comment:
//
//	//privacy:allow <rule> <ID>: <reason>
//	//privacy:source client-address <ID>: <reason>
//
// An allow comment on its own line covers the simple statement, declaration,
// or struct field that starts on the next line (only the first line of a
// compound statement or a function declaration); a comment after code covers
// its own line. A source comment goes in a function's doc comment. It marks the
// function as a source of the raw client address: a call to it is a read of
// the address, and the client-address findings inside it are allowed.
type directive struct {
	file   *fileInfo
	line   int
	kind   string // "allow" or "source"
	rule   string // the rule ID (allow) or the source kind (source)
	id     string
	from   int // the first line that the comment covers
	to     int // the last line that the comment covers
	fn     *ast.FuncDecl
	fnName string // the function that holds the comment, or "-"
	used   bool
}

var (
	directiveRe = regexp.MustCompile(`^//privacy:(\S*)(.*)$`)
	idReasonRe  = regexp.MustCompile(`^((?:PRIV|SEC)-\d+|b/\d+|CL \d+): (\S.*)$`)
	spacedRe    = regexp.MustCompile(`^(//\s+|/\*\s*)privacy:`)
)

// sourceKinds are the kinds that a //privacy:source comment can name.
var sourceKinds = map[string]bool{RuleClientAddress: true}

// parseDirectives reads the //privacy: comments of f into f.directives and
// returns a finding for each comment that is not valid.
func (f *fileInfo) parseDirectives(fset *token.FileSet) []Finding {
	f.directives = nil
	var bad []Finding
	fail := func(c *ast.Comment, format string, args ...any) {
		bad = append(bad, Finding{
			File: f.name, Line: fset.Position(c.Pos()).Line, Rule: RuleDirective,
			Message: fmt.Sprintf(format, args...),
		})
	}
	docOf := map[*ast.CommentGroup]*ast.FuncDecl{}
	for _, decl := range f.ast.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Doc != nil {
			docOf[fd.Doc] = fd
		}
	}
	reach := f.statementEnds(fset)
	for _, cg := range f.ast.Comments {
		for _, c := range cg.List {
			if spacedRe.MatchString(c.Text) {
				fail(c, "write a privacy comment as a line comment //privacy:..., with no space after //.")
				continue
			}
			m := directiveRe.FindStringSubmatch(c.Text)
			if m == nil {
				continue
			}
			verb, rest := m[1], strings.TrimPrefix(m[2], " ")
			if verb != "allow" && verb != "source" {
				fail(c, "unknown privacy comment //privacy:%s. Use //privacy:allow or //privacy:source.", verb)
				continue
			}
			name, idReason, _ := strings.Cut(rest, " ")
			switch {
			case verb == "allow" && (name == RuleDirective || ruleByID(name) == nil):
				fail(c, "//privacy:allow names an unknown rule %q. The rules are %s.", name, ruleIDs())
				continue
			case verb == "source" && !sourceKinds[name]:
				fail(c, "//privacy:source names an unknown kind %q. The kind is client-address.", name)
				continue
			}
			im := idReasonRe.FindStringSubmatch(idReason)
			if im == nil {
				fail(c, "//privacy:%s %s needs an ID (PRIV-NN, SEC-NN, b/NNN, or CL NN), a colon, and a reason.", verb, name)
				continue
			}
			line := fset.Position(c.Pos()).Line
			d := &directive{file: f, line: line, kind: verb, rule: name, id: im[1]}
			if verb == "source" {
				fd := docOf[cg]
				if fd == nil {
					fail(c, "put //privacy:source in the doc comment of a function.")
					continue
				}
				d.fn = fd
				d.fnName = funcDeclName(fd)
				d.from = fset.Position(fd.Pos()).Line
				d.to = fset.Position(fd.End()).Line
			} else {
				d.fnName = f.enclosingFunc(fset, c.Pos())
				if f.codeBefore(fset, c) {
					d.from, d.to = line, line
				} else {
					d.from, d.to = line+1, line+1
					if end, ok := reach[line+1]; ok {
						d.to = end
					}
				}
			}
			f.directives = append(f.directives, d)
		}
	}
	return bad
}

// allowing returns the comment that allows the finding, or nil.
func (f *fileInfo) allowing(rf rawFinding) *directive {
	for _, d := range f.directives {
		if d.rule == rf.rule && d.from <= rf.line && rf.line <= d.to {
			return d
		}
	}
	return nil
}

// codeBefore reports whether code comes before the comment c on its line.
func (f *fileInfo) codeBefore(fset *token.FileSet, c *ast.Comment) bool {
	off := fset.Position(c.Pos()).Offset
	start := bytes.LastIndexByte(f.src[:off], '\n') + 1
	return len(bytes.TrimSpace(f.src[start:off])) > 0
}

// statementEnds maps a line to the last line of the longest simple statement,
// declaration, or struct field that starts on it. A compound statement (if,
// for, switch, select, a block) or a function declaration is not included: an
// allow comment above one covers its first line only.
func (f *fileInfo) statementEnds(fset *token.FileSet) map[int]int {
	ends := map[int]int{}
	ast.Inspect(f.ast, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.AssignStmt, *ast.ExprStmt, *ast.ReturnStmt, *ast.DeclStmt,
			*ast.SendStmt, *ast.GoStmt, *ast.DeferStmt, *ast.IncDecStmt,
			*ast.GenDecl, *ast.ValueSpec, *ast.Field:
			start := fset.Position(n.Pos()).Line
			if end := fset.Position(n.End()).Line; end > ends[start] {
				ends[start] = end
			}
		}
		return true
	})
	return ends
}

// enclosingFunc returns the name of the function declaration that holds pos,
// or "-".
func (f *fileInfo) enclosingFunc(fset *token.FileSet, pos token.Pos) string {
	for _, decl := range f.ast.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Pos() <= pos && pos < fd.End() {
			return funcDeclName(fd)
		}
	}
	return "-"
}

// funcDeclName returns Name, (T).Name, or (*T).Name.
func funcDeclName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	star := ""
	if s, ok := t.(*ast.StarExpr); ok {
		star, t = "*", s.X
	}
	switch x := t.(type) {
	case *ast.IndexExpr:
		t = x.X
	case *ast.IndexListExpr:
		t = x.X
	}
	name := "?"
	if id, ok := t.(*ast.Ident); ok {
		name = id.Name
	}
	return "(" + star + name + ")." + fd.Name.Name
}

func ruleIDs() string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return strings.Join(ids, ", ")
}

func (d *directive) unusedFinding() Finding {
	msg := fmt.Sprintf("this //privacy:allow %s comment allows no finding. Remove it.", d.rule)
	if d.kind == "source" {
		msg = fmt.Sprintf("this //privacy:source %s comment marks a function that reads no client address. Remove it.", d.rule)
	}
	return Finding{File: d.file.name, Line: d.line, Rule: RuleDirective, Message: msg}
}

func (d *directive) exception() Exception {
	return Exception{File: d.file.name, Func: d.fnName, Kind: d.kind, Rule: d.rule, ID: d.id}
}

func sortExceptions(ex []Exception) {
	sort.Slice(ex, func(i, j int) bool {
		a, b := ex[i], ex[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Func != b.Func {
			return a.Func < b.Func
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.ID < b.ID
	})
}

// exceptionsHeader starts exceptions.txt.
const exceptionsHeader = `# Privacy lint exceptions: every //privacy:allow and //privacy:source comment
# that the code needs. This file is generated. Do not edit it. When you add,
# move, or remove such a comment, run:
#
#   go test ./internal/privacylint -run TestRepository -update
#
# Then review the change to this file like any other privacy change.
# Columns (separated by tabs): file, function, kind, rule, ID.
`

// FormatExceptions returns the content of exceptions.txt for ex.
func FormatExceptions(ex []Exception) []byte {
	sorted := append([]Exception(nil), ex...)
	sortExceptions(sorted)
	var b bytes.Buffer
	b.WriteString(exceptionsHeader)
	for _, e := range sorted {
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\n", e.File, e.Func, e.Kind, e.Rule, e.ID)
	}
	return b.Bytes()
}
