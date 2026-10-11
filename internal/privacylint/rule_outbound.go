package privacylint

import (
	"go/ast"
	"go/types"
)

var outboundRule = &Rule{
	ID: RuleOutbound,
	Policy: "s-hole connects only to the configured upstreams and blocklist URLs; " +
		"a new outbound connection needs a ROADMAP decision first (CLAUDE.md, Privacy first)",
	check: checkOutbound,
}

// outboundFuncs are the functions that open a connection, look up a name
// through the system resolver, or start a program that can.
var outboundFuncs = setOf(
	"net.Dial", "net.DialTimeout", "net.DialIP", "net.DialTCP", "net.DialUDP", "net.DialUnix",
	"net.LookupAddr", "net.LookupCNAME", "net.LookupHost", "net.LookupIP", "net.LookupMX",
	"net.LookupNS", "net.LookupPort", "net.LookupSRV", "net.LookupTXT",
	"crypto/tls.Dial", "crypto/tls.DialWithDialer",
	"net/http.Get", "net/http.Head", "net/http.Post", "net/http.PostForm",
	"net/smtp.Dial", "net/smtp.SendMail",
	"github.com/miekg/dns.Exchange", "github.com/miekg/dns.ExchangeContext",
	"github.com/miekg/dns.ExchangeConn", "github.com/miekg/dns.Dial",
	"github.com/miekg/dns.DialTimeout", "github.com/miekg/dns.DialWithTLS",
	"github.com/miekg/dns.DialTimeoutWithTLS",
	"os/exec.Command", "os/exec.CommandContext",
)

// outboundTypes are the types whose value can open a connection.
var outboundTypes = setOf(
	"net/http.Client", "net/http.Transport", "net.Dialer", "net.Resolver",
	"crypto/tls.Dialer", "github.com/miekg/dns.Client",
)

// outboundVars are the package variables that can open a connection.
var outboundVars = setOf("net/http.DefaultClient", "net/http.DefaultTransport", "net.DefaultResolver")

// checkOutbound reports each place that can open a new outbound connection:
// a call in outboundFuncs, a use of a variable in outboundVars, and a value of
// a type in outboundTypes.
func checkOutbound(p *pass) {
	ast.Inspect(p.file.ast, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if name := calleeName(p.info, n); outboundFuncs[name] {
				p.report(n, "%s can open an outbound connection.", name)
			}
		case *ast.Ident:
			if v, ok := p.info.Uses[n].(*types.Var); ok && v.Pkg() != nil && outboundVars[v.Pkg().Path()+"."+v.Name()] {
				p.report(n, "%s.%s can open an outbound connection.", v.Pkg().Path(), v.Name())
			}
		}
		return true
	})
	constructions(p, outboundTypes, func(n ast.Node, name, how string) {
		p.report(n, "%s makes a %s, which can open an outbound connection.", how, name)
	})
}

func setOf(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}
