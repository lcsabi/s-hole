package privacylint

import (
	"go/ast"
	"go/types"
)

var clientAddressRule = &Rule{
	ID: RuleClientAddress,
	Policy: "s-hole reads the client address in one place and masks it at once with querylog.MaskClientIP; " +
		"no other code reads it to store, show, or log it (CLAUDE.md, Privacy first)",
	check: checkClientAddress,
}

// checkClientAddress reports each read of a client address: a RemoteAddr
// method (dns.ResponseWriter, net.Conn), the RemoteAddr field of an
// http.Request, and a call of a function that a //privacy:source
// client-address comment marks. A type assertion that keeps only the type
// (`_, udp := w.RemoteAddr().(*net.UDPAddr)`, the same with var, or a type
// switch with no variable) reads no address and is not reported.
func checkClientAddress(p *pass) {
	typeOnly := map[ast.Expr]bool{}
	ast.Inspect(p.file.ast, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Rhs) == 1 && len(n.Lhs) >= 1 && isBlank(n.Lhs[0]) {
				if ta, ok := ast.Unparen(n.Rhs[0]).(*ast.TypeAssertExpr); ok && ta.Type != nil {
					markCallee(typeOnly, ta.X)
				}
			}
		case *ast.ValueSpec:
			if len(n.Values) == 1 && len(n.Names) >= 1 && n.Names[0].Name == "_" {
				if ta, ok := ast.Unparen(n.Values[0]).(*ast.TypeAssertExpr); ok && ta.Type != nil {
					markCallee(typeOnly, ta.X)
				}
			}
		case *ast.TypeSwitchStmt:
			if es, ok := n.Assign.(*ast.ExprStmt); ok {
				if ta, ok := ast.Unparen(es.X).(*ast.TypeAssertExpr); ok {
					markCallee(typeOnly, ta.X)
				}
			}
		}
		return true
	})

	selIdents := map[*ast.Ident]bool{}
	ast.Inspect(p.file.ast, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			selIdents[n.Sel] = true
			if typeOnly[n] {
				return true
			}
			if sel, ok := p.info.Selections[n]; ok {
				if v, ok := sel.Obj().(*types.Var); ok && v.Name() == "RemoteAddr" && derefName(sel.Recv()) == "net/http.Request" {
					p.report(n, "%s reads the client address (http.Request.RemoteAddr).", render(n))
					return true
				}
			}
			if fn := funcOf(p.info, n); fn != nil {
				p.reportFunc(n, fn)
			}
		case *ast.Ident:
			if selIdents[n] || typeOnly[n] {
				return true
			}
			if fn, ok := p.info.Uses[n].(*types.Func); ok {
				p.reportFunc(n, fn)
			}
		}
		return true
	})
}

// reportFunc reports a use of fn when fn returns the client address.
func (p *pass) reportFunc(n ast.Expr, fn *types.Func) {
	switch {
	case isRemoteAddr(fn):
		p.report(n, "%s reads the client address (RemoteAddr). Use the masked address from ServeDNS.", render(n))
	case p.u.sources[fn.FullName()]:
		p.report(n, "%s returns the raw client address (//privacy:source client-address). Use the masked address from ServeDNS.", render(n))
	}
}

// isRemoteAddr reports whether fn is a method RemoteAddr() net.Addr, as on
// dns.ResponseWriter, net.Conn, and tls.Conn.
func isRemoteAddr(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	return ok && fn.Name() == "RemoteAddr" && sig.Recv() != nil &&
		sig.Params().Len() == 0 && sig.Results().Len() == 1 &&
		typeName(sig.Results().At(0).Type()) == "net.Addr"
}

// markCallee marks the function expression of the call e (the selector in
// w.RemoteAddr()).
func markCallee(set map[ast.Expr]bool, e ast.Expr) {
	if call, ok := ast.Unparen(e).(*ast.CallExpr); ok {
		set[ast.Unparen(call.Fun)] = true
	}
}

func isBlank(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "_"
}

// render returns a short form of e for a message, such as w.RemoteAddr.
func render(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return render(e.X) + "." + e.Sel.Name
	case *ast.CallExpr:
		return render(e.Fun) + "()"
	case *ast.ParenExpr:
		return render(e.X)
	case *ast.StarExpr:
		return "*" + render(e.X)
	case *ast.IndexExpr:
		return render(e.X) + "[...]"
	}
	return "expression"
}
