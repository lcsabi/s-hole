package privacylint

import (
	"go/ast"
)

var serverErrorLogRule = &Rule{
	ID: RuleServerErrorLog,
	Policy: "every http.Server logs through newErrorLog, which replaces each IP address " +
		"in net/http's own lines with the word \"client\" (CLAUDE.md, Privacy first; b/103)",
	check: checkServerErrorLog,
}

// errorLogFunc is the function whose result an http.Server must use as its
// ErrorLog.
const errorLogFunc = "github.com/lcsabi/s-hole/internal/api.newErrorLog"

// serveFuncs build an http.Server that has no ErrorLog.
var serveFuncs = setOf("net/http.ListenAndServe", "net/http.ListenAndServeTLS", "net/http.Serve", "net/http.ServeTLS")

// checkServerErrorLog reports an http.Server composite literal whose ErrorLog
// is not newErrorLog(), an http.Server made any other way (new, a var
// declaration, a struct field: the lint cannot see its ErrorLog), and a call
// that serves HTTP without an http.Server.
func checkServerErrorLog(p *pass) {
	const fix = "Set ErrorLog: newErrorLog() (internal/api/errorlog.go)."
	ast.Inspect(p.file.ast, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if name := calleeName(p.info, call); serveFuncs[name] {
				p.report(call, "%s serves HTTP with a server that has no ErrorLog. Make an http.Server. %s", name, fix)
			}
		}
		return true
	})
	constructions(p, setOf("net/http.Server"), func(n ast.Node, _, how string) {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			p.report(n, "%s makes an http.Server whose ErrorLog the lint cannot check. Use a composite literal. %s", how, fix)
			return
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "ErrorLog" {
				if call, ok := ast.Unparen(kv.Value).(*ast.CallExpr); ok && calleeName(p.info, call) == errorLogFunc {
					return
				}
				p.report(kv, "the http.Server ErrorLog is not newErrorLog(). %s", fix)
				return
			}
		}
		p.report(lit, "the http.Server sets no ErrorLog, so net/http logs the client address. %s", fix)
	})
}
