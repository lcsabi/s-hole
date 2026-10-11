package privacylint

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Rule fixtures for the privacy lint (CL 119). Each fixture is one Go file
// for one rule. A line that the rule must report ends with "// want" (or
// "// want N" for N findings on that line). A fixture with no "// want" line
// must get no finding of its rule. The fixtures check the rules as the
// requirements state them; TestFixtures_EveryRuleHasBoth makes sure that each
// rule has fixtures of both kinds.

type ruleFixture struct {
	name string
	rule string
	pkg  string // the import path; fixturePkg when empty
	src  string
}

var ruleFixtures = []ruleFixture{
	// ---- client-address: must report ----
	{name: "dns ResponseWriter call", rule: RuleClientAddress, src: `package fixture

import (
	"fmt"

	"github.com/miekg/dns"
)

func serve(w dns.ResponseWriter) {
	fmt.Println(w.RemoteAddr()) // want
}
`},
	{name: "net.Conn and tls.Conn calls", rule: RuleClientAddress, src: `package fixture

import (
	"crypto/tls"
	"net"
)

func peer(c net.Conn, t *tls.Conn) (string, string) {
	a := c.RemoteAddr().String() // want
	return a, t.RemoteAddr().String() // want
}
`},
	{name: "method value and method expression", rule: RuleClientAddress, src: `package fixture

import "net"

func value(c net.Conn) func() net.Addr {
	return c.RemoteAddr // want
}

var expr = net.Conn.RemoteAddr // want
`},
	{name: "promoted method and own interface", rule: RuleClientAddress, src: `package fixture

import "net"

type wrapped struct{ net.Conn }

type peer interface{ RemoteAddr() net.Addr }

func promoted(c wrapped) net.Addr {
	return c.RemoteAddr() // want
}

func own(p peer) net.Addr {
	return p.RemoteAddr() // want
}
`},
	{name: "http.Request RemoteAddr field", rule: RuleClientAddress, src: `package fixture

import "net/http"

func handle(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(r.RemoteAddr)) // want
}

func byValue(r http.Request) string {
	return r.RemoteAddr // want
}
`},
	{name: "type assertion that keeps the value", rule: RuleClientAddress, src: `package fixture

import (
	"net"

	"github.com/miekg/dns"
)

func keep(w dns.ResponseWriter) bool {
	a, ok := w.RemoteAddr().(*net.UDPAddr) // want
	b := w.RemoteAddr().(*net.TCPAddr) // want
	return ok && a != nil && b != nil
}
`},
	{name: "type switch that binds a variable", rule: RuleClientAddress, src: `package fixture

import (
	"net"

	"github.com/miekg/dns"
)

func bound(w dns.ResponseWriter) string {
	switch a := w.RemoteAddr().(type) { // want
	case *net.UDPAddr:
		return a.IP.String()
	}
	return ""
}
`},
	{name: "call of and reference to a source function", rule: RuleClientAddress, src: `package fixture

import (
	"net"

	"github.com/miekg/dns"
)

// remote returns the client address.
//
//privacy:source client-address CL 1: the one place that reads the address
func remote(w dns.ResponseWriter) net.Addr {
	return w.RemoteAddr()
}

func caller(w dns.ResponseWriter) string {
	return remote(w).String() // want
}

var ref = remote // want
`},
	{name: "call of a source method", rule: RuleClientAddress, src: `package fixture

import (
	"net"

	"github.com/miekg/dns"
)

type srv struct{}

// peer returns the client address.
//
//privacy:source client-address PRIV-3: the one place that reads the address
func (s *srv) peer(w dns.ResponseWriter) net.Addr {
	return w.RemoteAddr()
}

func (s *srv) log(w dns.ResponseWriter) string {
	return s.peer(w).String() // want
}
`},

	// ---- client-address: must not report ----
	{name: "type assertion that keeps only the type", rule: RuleClientAddress, src: `package fixture

import (
	"net"

	"github.com/miekg/dns"
)

func udp(w dns.ResponseWriter) bool {
	_, udp := w.RemoteAddr().(*net.UDPAddr)
	if _, tcp := w.RemoteAddr().(*net.TCPAddr); tcp {
		return false
	}
	return udp
}
`},
	{name: "type switch with no variable", rule: RuleClientAddress, src: `package fixture

import (
	"net"

	"github.com/miekg/dns"
)

func kind(w dns.ResponseWriter) string {
	switch w.RemoteAddr().(type) {
	case *net.UDPAddr:
		return "udp"
	}
	return "tcp"
}
`},
	{name: "other methods and fields named RemoteAddr", rule: RuleClientAddress, src: `package fixture

import (
	"net"
	"net/http"
)

type info struct{ RemoteAddr string }

type str struct{}

func (str) RemoteAddr() string { return "" }

type arg struct{}

func (arg) RemoteAddr(int) net.Addr { return nil }

func RemoteAddr() net.Addr { return nil }

func others(c net.Conn, r *http.Request, i info, s str, a arg) (net.Addr, string, string, string, net.Addr, net.Addr) {
	return c.LocalAddr(), r.Host, i.RemoteAddr, s.RemoteAddr(), a.RemoteAddr(1), RemoteAddr()
}
`},

	// ---- outbound: must report ----
	{name: "outbound functions", rule: RuleOutbound, src: `package fixture

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os/exec"

	"github.com/miekg/dns"
)

func calls(ctx context.Context, m *dns.Msg) {
	_, _ = net.Dial("tcp", "a:1") // want
	_, _ = net.DialTimeout("tcp", "a:1", 0) // want
	_, _ = net.DialIP("ip4:1", nil, nil) // want
	_, _ = net.DialTCP("tcp", nil, nil) // want
	_, _ = net.DialUDP("udp", nil, nil) // want
	_, _ = net.DialUnix("unix", nil, nil) // want
	_, _ = net.LookupAddr("a") // want
	_, _ = net.LookupCNAME("a") // want
	_, _ = net.LookupHost("a") // want
	_, _ = net.LookupIP("a") // want
	_, _ = net.LookupMX("a") // want
	_, _ = net.LookupNS("a") // want
	_, _ = net.LookupPort("tcp", "a") // want
	_, _, _ = net.LookupSRV("a", "b", "c") // want
	_, _ = net.LookupTXT("a") // want
	_, _ = tls.Dial("tcp", "a:1", nil) // want
	_, _ = tls.DialWithDialer(nil, "tcp", "a:1", nil) // want
	_, _ = http.Get("http://a") // want
	_, _ = http.Head("http://a") // want
	_, _ = http.Post("http://a", "text/plain", nil) // want
	_, _ = http.PostForm("http://a", url.Values{}) // want
	_, _ = smtp.Dial("a:25") // want
	_ = smtp.SendMail("a:25", nil, "f", nil, nil) // want
	_, _ = dns.Exchange(m, "a:53") // want
	_, _ = dns.ExchangeContext(ctx, m, "a:53") // want
	_, _ = dns.ExchangeConn(nil, m) // want
	_, _ = dns.Dial("udp", "a:53") // want
	_, _ = dns.DialTimeout("udp", "a:53", 0) // want
	_, _ = dns.DialWithTLS("tcp", "a:853", nil) // want
	_, _ = dns.DialTimeoutWithTLS("tcp", "a:853", nil, 0) // want
	_ = exec.Command("x") // want
	_ = exec.CommandContext(ctx, "x") // want
}
`},
	{name: "outbound package variables", rule: RuleOutbound, src: `package fixture

import (
	"net"
	"net/http"
)

var tr = http.DefaultTransport // want

func vars(req *http.Request) {
	_, _ = http.DefaultClient.Do(req) // want
	c := http.DefaultClient // want
	_ = c
	_, _ = net.DefaultResolver.LookupHost(req.Context(), "a") // want
	_ = tr
}
`},
	{name: "outbound composite literals and new", rule: RuleOutbound, src: `package fixture

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/miekg/dns"
)

var (
	_ = http.Client{} // want
	_ = &http.Transport{} // want
	_ = net.Dialer{} // want
	_ = &net.Resolver{} // want
	_ = tls.Dialer{} // want
	_ = &dns.Client{} // want
	_ = new(http.Client) // want
	_ = new(http.Transport) // want
	_ = new(net.Dialer) // want
	_ = new(net.Resolver) // want
	_ = new(tls.Dialer) // want
	_ = new(dns.Client) // want
)

func inFunc() *http.Client {
	return &http.Client{} // want
}

var client = &http.Client{ // want
	Transport: &http.Transport{}, // want
}
`},
	{name: "outbound var declarations and struct fields", rule: RuleOutbound, src: `package fixture

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/miekg/dns"
)

var pkgLevel http.Client // want

func vars() {
	var c http.Client // want
	var t http.Transport // want
	var d net.Dialer // want
	var r net.Resolver // want
	var td tls.Dialer // want
	var dc dns.Client // want
	_, _, _, _, _, _ = &c, &t, &d, &r, &td, &dc
}

type holder struct {
	c  http.Client // want
	t  http.Transport // want
	d  net.Dialer // want
	r  net.Resolver // want
	td tls.Dialer // want
	dc dns.Client // want
}

type embeds struct {
	http.Client // want
}
`},

	// ---- outbound: must not report ----
	{name: "pointers and other net code", rule: RuleOutbound, src: `package fixture

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/miekg/dns"
)

var (
	c  *http.Client
	t  *http.Transport
	d  *net.Dialer
	r  *net.Resolver
	td *tls.Dialer
	dc *dns.Client
)

type holder struct {
	c  *http.Client
	t  *http.Transport
	d  *net.Dialer
	r  *net.Resolver
	td *tls.Dialer
	dc *dns.Client
}

func injected(c *http.Client, req *http.Request) (*http.Response, error) {
	return c.Do(req)
}

func other() {
	_ = net.ParseIP("192.0.2.1")
	_, _ = http.NewRequest(http.MethodGet, "http://a", nil)
	_ = new(dns.Msg)
	_ = dns.Msg{}
	_ = &dns.Server{}
	_, _ = net.Listen("tcp", "127.0.0.1:0")
	_ = &tls.Config{}
}

type Client struct{}

func Dial() {}

func Get() {}

func own() {
	Dial()
	Get()
	_ = Client{}
}
`},

	// ---- server-errorlog: must report ----
	{name: "http.Server with no or a wrong ErrorLog", rule: RuleServerErrorLog, pkg: apiPkg, src: `package api

import (
	"log"
	"net"
	"net/http"
	"os"
)

func newErrorLog() *log.Logger { return log.New(os.Stderr, "", 0) }

func servers(l net.Listener, h http.Handler) {
	_ = &http.Server{Addr: ":0"} // want
	_ = http.Server{} // want
	_ = &http.Server{ErrorLog: log.New(os.Stderr, "", 0)} // want
	lg := newErrorLog()
	_ = &http.Server{ErrorLog: lg} // want
	_ = &http.Server{ErrorLog: nil} // want
	_ = new(http.Server) // want
	var s http.Server // want
	_ = &s
	_ = http.ListenAndServe(":0", h) // want
	_ = http.ListenAndServeTLS(":0", "c", "k", h) // want
	_ = http.Serve(l, h) // want
	_ = http.ServeTLS(l, h, "c", "k") // want
}

type wrap struct {
	srv http.Server // want
}
`},
	{name: "newErrorLog of another package", rule: RuleServerErrorLog, src: `package fixture

import (
	"log"
	"net/http"
	"os"
)

func newErrorLog() *log.Logger { return log.New(os.Stderr, "", 0) }

var _ = &http.Server{ErrorLog: newErrorLog()} // want
`},

	// ---- server-errorlog: must not report ----
	{name: "http.Server with newErrorLog", rule: RuleServerErrorLog, pkg: apiPkg, src: `package api

import (
	"log"
	"net/http"
	"os"
)

func newErrorLog() *log.Logger { return log.New(os.Stderr, "", 0) }

var p *http.Server

type holder struct{ srv *http.Server }

func servers() (*http.Server, *http.Server, http.Server) {
	a := &http.Server{Addr: ":0", ErrorLog: newErrorLog()}
	b := &http.Server{
		Addr:     ":0",
		ErrorLog: newErrorLog(),
	}
	return a, b, http.Server{ErrorLog: (newErrorLog())}
}
`},

	// ---- metric-labels: must report ----
	{name: "label keys not on the allowlist", rule: RuleMetricLabels, src: `package fixture

import (
	"fmt"
	"io"

	"github.com/lcsabi/s-hole/internal/redact"
)

const clientLine = "shole_queries_total{client=\"192.0.2.1\"} 1\n" // want

var raw = ` + "`" + `shole_queries_total{domain="example.com"} 1` + "`" + ` // want

func keys(w io.Writer, d string) {
	fmt.Fprintf(w, "shole_x{domain=\"%s\"} 1\n", redact.URL(d)) // want
	fmt.Fprintf(w, "shole_x{upstream=\"a\",client=\"b\"} 1\n") // want
	_ = "# HELP shole_x Queries.\nshole_x{qname=\"a\"} 1\n" // want
}
`},
	{name: "label values that skip redact.URL", rule: RuleMetricLabels, src: `package fixture

import (
	"fmt"
	"io"
	"strings"

	"github.com/lcsabi/s-hole/internal/redact"
)

func URL(s string) string { return s }

func values(w io.Writer, u string, n int) {
	fmt.Fprintf(w, "shole_x{upstream=\"%s\"} %d\n", u, n) // want
	fmt.Fprintf(w, "shole_x{url=\"%s\"} %d\n", strings.ToLower(u), n) // want
	_ = fmt.Sprintf("shole_x{url=\"%s\"}", URL(u)) // want
	fmt.Printf("shole_x{upstream=\"%v\"}\n", u) // want
	_ = fmt.Sprintf("%d shole_x{url=\"%s\"}", redact.URL(u), u) // want
	_ = fmt.Sprintf("%*d shole_x{url=\"%s\"}", n, redact.URL(u), u) // want
	_ = fmt.Sprintf("%s %% shole_x{url=\"%s\"}", redact.URL(u), u) // want
}
`},
	{name: "verb-valued labels that the lint cannot check", rule: RuleMetricLabels, src: `package fixture

import (
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/lcsabi/s-hole/internal/redact"
)

const format = "shole_x{url=\"%s\"} 1\n" // want

func unchecked(w io.Writer, u string) error {
	fmt.Fprintf(w, format, redact.URL(u))
	s := "shole_x{url=\"%s\"}" // want
	_ = s
	_ = fmt.Sprint("shole_x{url=\"%s\"}", redact.URL(u)) // want
	log.Printf("shole_x{url=\"%s\"}", redact.URL(u)) // want
	fmt.Fprintf(w, "shole_x{url=\"%[1]s\"} 1\n", redact.URL(u)) // want
	return errors.New(fmt.Sprintf("%s", "shole_x{upstream=\"%s\"}")) // want
}
`},

	// ---- metric-labels: must not report ----
	{name: "allowed keys with fixed or redacted values", rule: RuleMetricLabels, src: `package fixture

import (
	"fmt"
	"io"
	"strings"

	"github.com/lcsabi/s-hole/internal/redact"
)

func escapeLabel(s string) string { return strings.ReplaceAll(s, "\"", "\\\"") }

func ok(w io.Writer, u string, n int) {
	fmt.Fprintf(w, "shole_x{upstream=\"%s\"} %d\n", redact.URL(u), n)
	fmt.Fprintf(w, "shole_x{url=\"%s\"} %d\n", escapeLabel(redact.URL(u)), n)
	fmt.Fprintf(w, "# HELP shole_x Queries.\n# TYPE shole_x counter\nshole_x{upstream=\"%s\",url=\"%s\"} %d\n", redact.URL(u), redact.URL(u), n)
	_ = fmt.Sprintf("shole_x{url=\"%s\"}", redact.URL(u))
	fmt.Printf("shole_x{url=\"%s\"}\n", redact.URL(u))
	_ = fmt.Sprintf("%d%% shole_x{url=\"%s\"}", n, redact.URL(u))
	_ = fmt.Sprintf("%*d shole_x{url=\"%s\"}", n, n, redact.URL(u))
	_ = fmt.Sprintf("%-*.*f shole_x{url=\"%s\"}", n, n, 1.0, redact.URL(u))
	_ = fmt.Sprintf("%s shole_x{url=\"%s\"}", u, redact.URL(u))
	_ = "shole_x{url=\"https://example.com\"} 1"
	_ = "shole_x{upstream=\"a\",url=\"b\"} 1"
	_ = "# HELP shole_queries_total Queries since start.\n# TYPE shole_queries_total counter\nshole_queries_total 3\n"
	_ = "other_metric{client=\"a\"} 1"
	_ = "client=\"a\""
}
`},
}

var wantRe = regexp.MustCompile(`// want(?: (\d+))?\s*$`)

// wantLines returns the line numbers of src that end with "// want", with the
// number of findings that each line must get.
func wantLines(src string) map[int]int {
	want := map[int]int{}
	for i, line := range strings.Split(src, "\n") {
		m := wantRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n := 1
		if m[1] != "" {
			n, _ = strconv.Atoi(m[1])
		}
		want[i+1] = n
	}
	return want
}

// check runs CheckFiles over the sources and fails the test on an error.
func check(t *testing.T, pkg string, sources map[string]string) *Result {
	t.Helper()
	res, err := CheckFiles(moduleRoot, pkg, sources)
	if err != nil {
		t.Fatalf("CheckFiles: %v", err)
	}
	return res
}

// ruleLines counts the findings of rule in file by line.
func ruleLines(res *Result, file, rule string) map[int]int {
	got := map[int]int{}
	for _, f := range res.Findings {
		if f.File == file && f.Rule == rule {
			got[f.Line]++
		}
	}
	return got
}

func policyOf(t *testing.T, id string) string {
	t.Helper()
	for _, r := range Rules() {
		if r.ID == id {
			return r.Policy
		}
	}
	t.Fatalf("no rule %q", id)
	return ""
}

func TestRuleFixtures(t *testing.T) {
	for _, fx := range ruleFixtures {
		t.Run(fx.rule+"/"+fx.name, func(t *testing.T) {
			pkg := fx.pkg
			if pkg == "" {
				pkg = fixturePkg
			}
			res := check(t, pkg, map[string]string{"f.go": fx.src})
			want := wantLines(fx.src)
			got := ruleLines(res, "f.go", fx.rule)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s findings by line = %v, want %v\n%s", fx.rule, got, want, dump(res))
			}
			suffix := " Policy: " + policyOf(t, fx.rule) + "."
			for _, f := range res.Findings {
				if f.File != "f.go" {
					t.Errorf("finding in file %q, want f.go: %s", f.File, f)
				}
				if f.Rule == RuleDirective {
					t.Errorf("unexpected directive finding: %s", f)
				}
				if f.Rule == fx.rule && !strings.HasSuffix(f.Message, suffix) {
					t.Errorf("message does not end with %q: %s", suffix, f)
				}
			}
		})
	}
}

// TestFixtures_EveryRuleHasBoth fails when a rule has no fixture that must be
// reported or no fixture that must pass, so a new rule needs both.
func TestFixtures_EveryRuleHasBoth(t *testing.T) {
	flagged, passed := map[string]bool{}, map[string]bool{}
	for _, fx := range ruleFixtures {
		if len(wantLines(fx.src)) > 0 {
			flagged[fx.rule] = true
		} else {
			passed[fx.rule] = true
		}
	}
	for _, r := range Rules() {
		if !flagged[r.ID] {
			t.Errorf("rule %q has no fixture that must be reported", r.ID)
		}
		if !passed[r.ID] {
			t.Errorf("rule %q has no fixture that must pass", r.ID)
		}
	}
}

// Every rule finding ends with the policy of its rule. The fixtures check the
// rule that they are for; this checks every rule finding of every fixture.
func TestFindings_EndWithPolicy(t *testing.T) {
	policies := map[string]string{}
	for _, r := range Rules() {
		policies[r.ID] = r.Policy
	}
	for _, fx := range ruleFixtures {
		pkg := fx.pkg
		if pkg == "" {
			pkg = fixturePkg
		}
		res := check(t, pkg, map[string]string{"f.go": fx.src})
		for _, f := range res.Findings {
			p, ok := policies[f.Rule]
			if !ok {
				continue
			}
			if !strings.HasSuffix(f.Message, " Policy: "+p+".") {
				t.Errorf("%s: message does not end with the policy: %s", fx.name, f)
			}
		}
	}
}

// Findings are sorted by file, then line.
func TestFindings_Sorted(t *testing.T) {
	src := `package fixture

import "net"

var _, _ = net.Dial("tcp", "a:1")

var _, _ = net.LookupHost("a")
`
	res := check(t, fixturePkg, map[string]string{"b.go": src, "a.go": src, "c.go": strings.Replace(src, "package fixture\n", "package fixture\n\n\n", 1)})
	if len(res.Findings) != 6 {
		t.Fatalf("got %d findings, want 6:\n%s", len(res.Findings), dump(res))
	}
	sorted := sort.SliceIsSorted(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	if !sorted {
		t.Errorf("findings are not sorted by file and line:\n%s", dump(res))
	}
}

// Edge forms of a type assertion that keeps only the type. The requirement
// is that such an assertion reads no address, whatever the form.
func TestClientAddress_TypeOnlyForms(t *testing.T) {
	const head = `package fixture

import (
	"net"

	"github.com/miekg/dns"
)

// remote returns the client address.
//
//privacy:source client-address CL 1: the one place that reads the address
func remote(w dns.ResponseWriter) net.Addr {
	return w.RemoteAddr()
}

func form(w dns.ResponseWriter) bool {
`
	for name, body := range map[string]string{
		"var declaration":            "\tvar _, udp = w.RemoteAddr().(*net.UDPAddr)\n\treturn udp\n}\n",
		"source function assertion":  "\t_, tcp := remote(w).(*net.TCPAddr)\n\treturn tcp\n}\n",
		"source function typeswitch": "\tswitch remote(w).(type) {\n\tcase *net.UDPAddr:\n\t}\n\treturn true\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			res := check(t, fixturePkg, map[string]string{"f.go": head + body})
			if got := ruleLines(res, "f.go", RuleClientAddress); len(got) != 0 {
				t.Errorf("client-address findings by line = %v, want none\n%s", got, dump(res))
			}
		})
	}
}

// A label value written with %q makes key="value" in the output, so its key
// must be on the allowlist too.
func TestMetricLabels_QuotedVerbValue(t *testing.T) {
	src := `package fixture

import (
	"fmt"
	"io"
)

func quoted(w io.Writer, client string) {
	fmt.Fprintf(w, "shole_x{client=%q} 1\n", client) // want
}
`
	res := check(t, fixturePkg, map[string]string{"f.go": src})
	if got, want := ruleLines(res, "f.go", RuleMetricLabels), wantLines(src); !reflect.DeepEqual(got, want) {
		t.Errorf("metric-labels findings by line = %v, want %v\n%s", got, want, dump(res))
	}
}

// dump formats the result for a failure message.
func dump(res *Result) string {
	var b strings.Builder
	for _, f := range res.Findings {
		fmt.Fprintf(&b, "  finding: %s\n", f)
	}
	for _, e := range res.Exceptions {
		fmt.Fprintf(&b, "  exception: %+v\n", e)
	}
	return b.String()
}
