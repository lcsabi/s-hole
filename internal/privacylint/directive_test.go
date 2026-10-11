package privacylint

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Tests for the //privacy: comments of the privacy lint (CL 119): the forms
// that are not valid, the lines that an allow comment covers, the place of a
// source comment, the comments that allow nothing, and the exceptions.

// key is one expected finding: a line and a rule.
type key struct {
	line int
	rule string
}

// findingSet returns the findings of file as keys, with their counts.
func findingSet(res *Result, file string) map[key]int {
	got := map[key]int{}
	for _, f := range res.Findings {
		if f.File == file {
			got[key{f.Line, f.Rule}]++
		}
	}
	return got
}

// expect checks that src, alone in f.go, gets exactly the findings in want
// (each once) and the exceptions in wantEx.
func expect(t *testing.T, src string, want []key, wantEx []Exception) *Result {
	t.Helper()
	res := check(t, fixturePkg, map[string]string{"f.go": src})
	w := map[key]int{}
	for _, k := range want {
		w[k]++
	}
	if got := findingSet(res, "f.go"); !reflect.DeepEqual(got, w) {
		t.Errorf("findings = %v, want %v\n%s", got, w, dump(res))
	}
	if len(res.Exceptions) != 0 || len(wantEx) != 0 {
		if !reflect.DeepEqual(res.Exceptions, wantEx) {
			t.Errorf("exceptions = %+v, want %+v", res.Exceptions, wantEx)
		}
	}
	return res
}

// dialAfter returns a file whose line 6 is comment and whose line 7 dials
// out.
func dialAfter(comment string) string {
	return `package fixture

import "net"

func f() {
	` + comment + `
	_, _ = net.Dial("tcp", "a:1")
}
`
}

func TestDirective_Malformed(t *testing.T) {
	for _, comment := range []string{
		"//privacy:deny outbound CL 1: unknown verb",
		"//privacy:allowed outbound CL 1: unknown verb",
		"//privacy: outbound CL 1: no verb",
		"//privacy:allow",
		"//privacy:allow nosuchrule CL 1: unknown rule",
		"//privacy:allow directive CL 1: the directive rule cannot be allowed",
		"//privacy:allow Outbound CL 1: rule IDs are lower case",
		"//privacy:allow outbound",
		"//privacy:allow outbound: no ID",
		"//privacy:allow outbound the reason only",
		"//privacy:allow outbound CL 1 no colon",
		"//privacy:allow outbound CL 1:",
		"//privacy:allow outbound CL 1: ",
		"//privacy:allow outbound CL 1:no space",
		"//privacy:allow outbound CL1: no space in the CL ID",
		"//privacy:allow outbound CL x: not a number",
		"//privacy:allow outbound PRIV-: no number",
		"//privacy:allow outbound PRIV-1a: not a number",
		"//privacy:allow outbound priv-1: lower case",
		"//privacy:allow outbound SEC 1: a space, not a dash",
		"//privacy:allow outbound b/: no number",
		"//privacy:allow outbound B/1: upper case",
		"//privacy:allow outbound XYZ-1: unknown ID",
		"//privacy:allow outbound #12: unknown ID",
		"// privacy:allow outbound CL 1: a space after the slashes",
		"//  privacy:allow outbound CL 1: two spaces after the slashes",
		"//\tprivacy:allow outbound CL 1: a tab after the slashes",
		"/* privacy:allow outbound CL 1: a block comment */",
		"/*privacy:allow outbound CL 1: a block comment with no space*/",
	} {
		t.Run(comment, func(t *testing.T) {
			// The comment is a directive finding; it allows nothing, so the
			// dial is still reported.
			expect(t, dialAfter(comment), []key{{6, RuleDirective}, {7, RuleOutbound}}, nil)
		})
	}
}

func TestDirective_ValidIDForms(t *testing.T) {
	for _, id := range []string{"PRIV-12", "SEC-3", "b/104", "CL 5", "CL 119"} {
		t.Run(id, func(t *testing.T) {
			expect(t, dialAfter("//privacy:allow outbound "+id+": a reason"), nil,
				[]Exception{{File: "f.go", Func: "f", Kind: "allow", Rule: RuleOutbound, ID: id}})
		})
	}
}

func TestDirective_SourceWithOtherKind(t *testing.T) {
	for _, kind := range []string{RuleOutbound, RuleDirective, "client", "nosuchkind"} {
		t.Run(kind, func(t *testing.T) {
			src := `package fixture

import (
	"net"

	"github.com/miekg/dns"
)

//privacy:source ` + kind + ` CL 1: a reason
func remote(w dns.ResponseWriter) net.Addr {
	return w.RemoteAddr()
}
`
			expect(t, src, []key{{9, RuleDirective}, {11, RuleClientAddress}}, nil)
		})
	}
}

func TestDirective_SourceNeedsIDAndReason(t *testing.T) {
	src := `package fixture

import (
	"net"

	"github.com/miekg/dns"
)

//privacy:source client-address: no ID
func remote(w dns.ResponseWriter) net.Addr {
	return w.RemoteAddr()
}
`
	expect(t, src, []key{{9, RuleDirective}, {11, RuleClientAddress}}, nil)
}

func TestDirective_UnusedAllow(t *testing.T) {
	src := `package fixture

func f() int {
	//privacy:allow outbound CL 1: nothing to allow
	x := 1
	return x //privacy:allow client-address CL 2: nothing to allow
}
`
	expect(t, src, []key{{4, RuleDirective}, {6, RuleDirective}}, nil)
}

func TestDirective_UnusedSource(t *testing.T) {
	src := `package fixture

import "net"

// local returns an address that is not a client address.
//
//privacy:source client-address CL 1: reads nothing
func local(c net.Conn) net.Addr {
	return c.LocalAddr()
}
`
	expect(t, src, []key{{7, RuleDirective}}, nil)
}

func TestDirective_WrongRuleAllowsNothing(t *testing.T) {
	expect(t, dialAfter("//privacy:allow client-address CL 1: the wrong rule"),
		[]key{{6, RuleDirective}, {7, RuleOutbound}}, nil)
}

// An allow comment allows only its own rule, also on a line with findings of
// two rules.
func TestDirective_AllowsOnlyItsRule(t *testing.T) {
	src := `package fixture

import (
	"net"

	"github.com/miekg/dns"
)

func f(w dns.ResponseWriter) {
	//privacy:allow outbound CL 1: a reason
	_, _ = net.Dial("tcp", w.RemoteAddr().String())
}
`
	expect(t, src, []key{{11, RuleClientAddress}},
		[]Exception{{File: "f.go", Func: "f", Kind: "allow", Rule: RuleOutbound, ID: "CL 1"}})
}

// One comment above a declaration that spans lines covers every finding in
// it.
func TestCoverage_MultiLineDeclaration(t *testing.T) {
	src := `package fixture

import "net/http"

//privacy:allow outbound CL 1: a reason
var client = &http.Client{
	Transport: &http.Transport{},
}
`
	expect(t, src, nil, []Exception{{File: "f.go", Func: "-", Kind: "allow", Rule: RuleOutbound, ID: "CL 1"}})
}

func TestCoverage_VarBlock(t *testing.T) {
	src := `package fixture

import (
	"net"
	"net/http"
)

//privacy:allow outbound CL 1: a reason
var (
	a = &http.Client{}
	b = net.Dialer{}
)

var c = net.Dialer{}
`
	expect(t, src, []key{{14, RuleOutbound}},
		[]Exception{{File: "f.go", Func: "-", Kind: "allow", Rule: RuleOutbound, ID: "CL 1"}})
}

func TestCoverage_ValueSpecInBlock(t *testing.T) {
	src := `package fixture

import (
	"net"
	"net/http"
)

var (
	//privacy:allow outbound CL 1: a reason
	a = &http.Client{
		Transport: &http.Transport{},
	}
	b = net.Dialer{}
)
`
	expect(t, src, []key{{13, RuleOutbound}},
		[]Exception{{File: "f.go", Func: "-", Kind: "allow", Rule: RuleOutbound, ID: "CL 1"}})
}

func TestCoverage_StructField(t *testing.T) {
	src := `package fixture

import (
	"net"
	"net/http"
)

type holder struct {
	//privacy:allow outbound CL 1: a reason
	c http.Client
	d net.Dialer
}
`
	expect(t, src, []key{{11, RuleOutbound}},
		[]Exception{{File: "f.go", Func: "-", Kind: "allow", Rule: RuleOutbound, ID: "CL 1"}})
}

func TestCoverage_MultiLineStatement(t *testing.T) {
	src := `package fixture

import (
	"net"
	"net/http"
)

func f() {
	//privacy:allow outbound CL 1: a reason
	c := &http.Client{
		Transport: &http.Transport{},
	}
	_ = c
	_, _ = net.Dial("tcp", "a:1")
}
`
	expect(t, src, []key{{14, RuleOutbound}},
		[]Exception{{File: "f.go", Func: "f", Kind: "allow", Rule: RuleOutbound, ID: "CL 1"}})
}

// Above a compound statement, an allow comment covers its first line only.
func TestCoverage_CompoundStatementFirstLineOnly(t *testing.T) {
	for name, tc := range map[string]struct {
		src  string
		want []key
	}{
		"if": {src: `package fixture

import "net"

func f() {
	//privacy:allow outbound CL 1: a reason
	if c, err := net.Dial("tcp", "a:1"); err == nil {
		_ = c
		_, _ = net.Dial("tcp", "b:1")
	}
}
`, want: []key{{9, RuleOutbound}}},
		"for": {src: `package fixture

import "net"

func f() {
	//privacy:allow outbound CL 1: a reason
	for _, err := net.Dial("tcp", "a:1"); err != nil; {
		_, _ = net.Dial("tcp", "b:1")
	}
}
`, want: []key{{8, RuleOutbound}}},
		"switch": {src: `package fixture

import "net"

func f() {
	//privacy:allow outbound CL 1: a reason
	switch _, err := net.Dial("tcp", "a:1"); err {
	case nil:
		_, _ = net.Dial("tcp", "b:1")
	}
}
`, want: []key{{9, RuleOutbound}}},
	} {
		t.Run(name, func(t *testing.T) {
			expect(t, tc.src, tc.want, []Exception{{File: "f.go", Func: "f", Kind: "allow", Rule: RuleOutbound, ID: "CL 1"}})
		})
	}
}

// Above a compound statement with no finding on its first line, an allow
// comment allows nothing: the body is not covered.
func TestCoverage_CompoundStatementBodyNotCovered(t *testing.T) {
	const dial = "_, _ = net.Dial(\"tcp\", \"a:1\")"
	for name, tc := range map[string]struct {
		body string
		line int // the line of the dial
	}{
		"if":     {"if true {\n\t\t" + dial + "\n\t}", 8},
		"for":    {"for i := 0; i < 1; i++ {\n\t\t" + dial + "\n\t}", 8},
		"switch": {"switch {\n\tdefault:\n\t\t" + dial + "\n\t}", 9},
		"select": {"select {\n\tdefault:\n\t\t" + dial + "\n\t}", 9},
		"block":  {"{\n\t\t" + dial + "\n\t}", 8},
	} {
		t.Run(name, func(t *testing.T) {
			src := "package fixture\n\nimport \"net\"\n\nfunc f() {\n\t//privacy:allow outbound CL 1: a reason\n\t" + tc.body + "\n}\n"
			expect(t, src, []key{{6, RuleDirective}, {tc.line, RuleOutbound}}, nil)
		})
	}
}

// Above a function declaration, an allow comment covers the func line only.
func TestCoverage_FuncDeclFirstLineOnly(t *testing.T) {
	src := `package fixture

import "net"

//privacy:allow outbound CL 1: a reason
func g() {
	_, _ = net.Dial("tcp", "a:1")
}
`
	expect(t, src, []key{{5, RuleDirective}, {7, RuleOutbound}}, nil)

	oneLine := `package fixture

import "net"

//privacy:allow outbound CL 1: a reason
func g() { _, _ = net.Dial("tcp", "a:1") }
`
	res := check(t, fixturePkg, map[string]string{"f.go": oneLine})
	if got := findingSet(res, "f.go"); len(got) != 0 {
		t.Errorf("one-line func: findings = %v, want none\n%s", got, dump(res))
	}
	if len(res.Exceptions) != 1 || res.Exceptions[0].Kind != "allow" || res.Exceptions[0].ID != "CL 1" {
		t.Errorf("exceptions = %+v, want one allow CL 1", res.Exceptions)
	}
}

// A comment after code covers its own line only.
func TestCoverage_TrailingComment(t *testing.T) {
	src := `package fixture

import (
	"net"
	"net/http"
)

func f() {
	_, _ = net.Dial("tcp", "a:1") //privacy:allow outbound CL 1: a reason
	_, _ = net.Dial("tcp", "b:1")
	c := &http.Client{ //privacy:allow outbound CL 2: a reason
		Transport: &http.Transport{},
	}
	_ = c
}
`
	expect(t, src, []key{{10, RuleOutbound}, {12, RuleOutbound}}, []Exception{
		{File: "f.go", Func: "f", Kind: "allow", Rule: RuleOutbound, ID: "CL 1"},
		{File: "f.go", Func: "f", Kind: "allow", Rule: RuleOutbound, ID: "CL 2"},
	})
}

// A comment covers the line right after it, not a line after a blank line.
func TestCoverage_BlankLineBreaksCover(t *testing.T) {
	src := `package fixture

import "net"

func f() {
	//privacy:allow outbound CL 1: a reason

	_, _ = net.Dial("tcp", "a:1")
}
`
	expect(t, src, []key{{6, RuleDirective}, {8, RuleOutbound}}, nil)
}

// Two findings of the rule on the covered node: one comment allows both.
// A second statement after the node is not covered.
func TestCoverage_StopsAfterNode(t *testing.T) {
	src := `package fixture

import "net"

func f() {
	//privacy:allow outbound CL 1: a reason
	_, _ = net.Dial("tcp", "a:1")
	_, _ = net.Dial("tcp", "b:1")
}
`
	expect(t, src, []key{{8, RuleOutbound}},
		[]Exception{{File: "f.go", Func: "f", Kind: "allow", Rule: RuleOutbound, ID: "CL 1"}})
}

func TestSource_Placement(t *testing.T) {
	for name, tc := range map[string]struct {
		src  string
		want []key
	}{
		"above a var": {src: `package fixture

import "net"

//privacy:source client-address CL 1: a reason
var f = func(c net.Conn) net.Addr { return c.RemoteAddr() }
`, want: []key{{5, RuleDirective}, {6, RuleClientAddress}}},
		"in a function body": {src: `package fixture

import "net"

func f(c net.Conn) net.Addr {
	//privacy:source client-address CL 1: a reason
	return c.RemoteAddr()
}
`, want: []key{{6, RuleDirective}, {7, RuleClientAddress}}},
		"after code": {src: `package fixture

import "net"

func f(c net.Conn) net.Addr {
	return c.RemoteAddr() //privacy:source client-address CL 1: a reason
}
`, want: []key{{6, RuleDirective}, {6, RuleClientAddress}}},
		"separated from the function by a blank line": {src: `package fixture

import "net"

//privacy:source client-address CL 1: a reason

func f(c net.Conn) net.Addr {
	return c.RemoteAddr()
}
`, want: []key{{5, RuleDirective}, {8, RuleClientAddress}}},
		"on a type": {src: `package fixture

import "net"

//privacy:source client-address CL 1: a reason
type conn struct{ net.Conn }

func (c conn) addr() net.Addr { return c.RemoteAddr() }
`, want: []key{{5, RuleDirective}, {8, RuleClientAddress}}},
	} {
		t.Run(name, func(t *testing.T) {
			expect(t, tc.src, tc.want, nil)
		})
	}
}

// A source comment marks the function: its own reads are allowed, and each
// call or reference anywhere in the package is a read, also in another file.
func TestSource_MarksCallers(t *testing.T) {
	a := `package fixture

import (
	"net"

	"github.com/miekg/dns"
)

type srv struct{}

// remote returns the client address.
//
//privacy:source client-address CL 1: the one place that reads it
func remote(w dns.ResponseWriter) net.Addr {
	a := w.RemoteAddr()
	return a
}

// peer returns the client address.
//
//privacy:source client-address PRIV-2: the one place that reads it
func (s srv) peer(w dns.ResponseWriter) net.Addr {
	return w.RemoteAddr()
}
`
	b := `package fixture

import "github.com/miekg/dns"

func use(w dns.ResponseWriter) {
	_ = remote(w)
	_ = srv{}.peer(w)
	f := remote
	_ = f
	g := srv.peer
	_ = g
}
`
	res := check(t, fixturePkg, map[string]string{"a.go": a, "b.go": b})
	if got := findingSet(res, "a.go"); len(got) != 0 {
		t.Errorf("a.go findings = %v, want none\n%s", got, dump(res))
	}
	want := map[key]int{{6, RuleClientAddress}: 1, {7, RuleClientAddress}: 1, {8, RuleClientAddress}: 1, {10, RuleClientAddress}: 1}
	if got := findingSet(res, "b.go"); !reflect.DeepEqual(got, want) {
		t.Errorf("b.go findings = %v, want %v\n%s", got, want, dump(res))
	}
	wantEx := []Exception{
		{File: "a.go", Func: "(srv).peer", Kind: "source", Rule: RuleClientAddress, ID: "PRIV-2"},
		{File: "a.go", Func: "remote", Kind: "source", Rule: RuleClientAddress, ID: "CL 1"},
	}
	if !reflect.DeepEqual(res.Exceptions, wantEx) {
		t.Errorf("exceptions = %+v, want %+v", res.Exceptions, wantEx)
	}
}

// Without the source comment, the same call is not a read: the comment is
// what marks it.
func TestSource_UnmarkedFunctionIsNotASource(t *testing.T) {
	src := `package fixture

import (
	"net"

	"github.com/miekg/dns"
)

func remote(w dns.ResponseWriter) net.Addr {
	//privacy:allow client-address CL 1: a reason
	return w.RemoteAddr()
}

func use(w dns.ResponseWriter) { _ = remote(w) }
`
	expect(t, src, nil, []Exception{{File: "f.go", Func: "remote", Kind: "allow", Rule: RuleClientAddress, ID: "CL 1"}})
}

// Each used comment is one exception, with the function that holds it. Unused
// and malformed comments are not exceptions. The list is sorted.
func TestExceptions_FuncNamesAndOrder(t *testing.T) {
	b := `package fixture

import (
	"net"
	"net/http"
)

type T struct{}

func (t *T) ptr() {
	_, _ = net.Dial("tcp", "a:1") //privacy:allow outbound SEC-2: a reason
}

func (t T) val() {
	//privacy:allow outbound b/9: a reason
	_, _ = net.Dial("tcp", "a:1")
}

func plain() {
	go func() {
		//privacy:allow outbound CL 3: a reason
		_, _ = net.Dial("tcp", "a:1")
	}()
	//privacy:allow outbound CL 4: unused
	_ = 1
	// privacy:allow outbound CL 5: malformed
	_, _ = net.Dial("tcp", "b:1")
}

//privacy:allow outbound PRIV-1: a reason
var c = &http.Client{}
`
	a := `package fixture

import "net"

func first() {
	_, _ = net.LookupHost("a") //privacy:allow outbound CL 9: a reason
}
`
	res := check(t, fixturePkg, map[string]string{"b.go": b, "a.go": a})
	wantEx := []Exception{
		{File: "a.go", Func: "first", Kind: "allow", Rule: RuleOutbound, ID: "CL 9"},
		{File: "b.go", Func: "(*T).ptr", Kind: "allow", Rule: RuleOutbound, ID: "SEC-2"},
		{File: "b.go", Func: "(T).val", Kind: "allow", Rule: RuleOutbound, ID: "b/9"},
		{File: "b.go", Func: "-", Kind: "allow", Rule: RuleOutbound, ID: "PRIV-1"},
		{File: "b.go", Func: "plain", Kind: "allow", Rule: RuleOutbound, ID: "CL 3"},
	}
	sortExceptionsForTest(wantEx)
	if !reflect.DeepEqual(res.Exceptions, wantEx) {
		t.Errorf("exceptions =\n%+v\nwant\n%+v", res.Exceptions, wantEx)
	}
	want := map[key]int{{24, RuleDirective}: 1, {26, RuleDirective}: 1, {27, RuleOutbound}: 1}
	if got := findingSet(res, "b.go"); !reflect.DeepEqual(got, want) {
		t.Errorf("b.go findings = %v, want %v\n%s", got, want, dump(res))
	}
}

// sortExceptionsForTest sorts by every field in the column order of
// exceptions.txt: file, function, kind, rule, ID.
func sortExceptionsForTest(ex []Exception) {
	sort.Slice(ex, func(i, j int) bool {
		x := []string{ex[i].File, ex[i].Func, ex[i].Kind, ex[i].Rule, ex[i].ID}
		y := []string{ex[j].File, ex[j].Func, ex[j].Kind, ex[j].Rule, ex[j].ID}
		for k := range x {
			if x[k] != y[k] {
				return x[k] < y[k]
			}
		}
		return false
	})
}

func TestFormatExceptions(t *testing.T) {
	in := []Exception{
		{File: "internal/z.go", Func: "f", Kind: "allow", Rule: RuleOutbound, ID: "CL 2"},
		{File: "internal/a.go", Func: "(*T).g", Kind: "source", Rule: RuleClientAddress, ID: "PRIV-1"},
		{File: "internal/a.go", Func: "-", Kind: "allow", Rule: RuleOutbound, ID: "CL 1"},
	}
	orig := append([]Exception(nil), in...)
	out := string(FormatExceptions(in))
	if !reflect.DeepEqual(in, orig) {
		t.Errorf("FormatExceptions changed its input: %+v", in)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("output does not end with a newline: %q", out)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	var header, rows []string
	for i, l := range lines {
		if strings.HasPrefix(l, "#") {
			if len(rows) > 0 {
				t.Errorf("line %d: a comment line after the rows: %q", i+1, l)
			}
			header = append(header, l)
			continue
		}
		rows = append(rows, l)
	}
	if len(header) == 0 || !strings.HasPrefix(lines[0], "#") {
		t.Errorf("output does not start with a # comment header:\n%s", out)
	}
	if !strings.Contains(strings.Join(header, "\n"), "-update") {
		t.Errorf("header does not say how to rewrite the file:\n%s", out)
	}
	want := []string{
		"internal/a.go\t(*T).g\tsource\tclient-address\tPRIV-1",
		"internal/a.go\t-\tallow\toutbound\tCL 1",
		"internal/z.go\tf\tallow\toutbound\tCL 2",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows =\n%q\nwant\n%q", rows, want)
	}

	empty := string(FormatExceptions(nil))
	for _, l := range strings.Split(strings.TrimSuffix(empty, "\n"), "\n") {
		if !strings.HasPrefix(l, "#") {
			t.Errorf("FormatExceptions(nil) has a row: %q", l)
		}
	}
	if !strings.HasPrefix(out, empty) {
		t.Errorf("the header changes with the rows:\n%s\n---\n%s", empty, out)
	}
}

// The committed exceptions.txt is in the format that FormatExceptions writes:
// the header, then rows of five tab-separated fields, sorted.
func TestExceptionsFile_Format(t *testing.T) {
	data := readFile(t, "exceptions.txt")
	var ex []Exception
	for _, l := range strings.Split(strings.TrimSuffix(data, "\n"), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) != 5 {
			t.Fatalf("row %q has %d fields, want 5", l, len(f))
		}
		if f[2] != "allow" && f[2] != "source" {
			t.Errorf("row %q: kind %q is not allow or source", l, f[2])
		}
		ex = append(ex, Exception{File: f[0], Func: f[1], Kind: f[2], Rule: f[3], ID: f[4]})
	}
	if got := string(FormatExceptions(ex)); got != data {
		t.Errorf("exceptions.txt is not in the format of FormatExceptions:\n%s", got)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
