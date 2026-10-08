package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/dnsserver"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// CL 101 tests for the search-domain note, written from the requirements.

func writeResolv(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSearchDomains(t *testing.T) {
	// CL 101: searchDomains reads the search lines (several domains on one
	// line) and the domain lines of the files that exist. Each domain comes
	// once, lowercase, with no trailing dot. Invalid entries are skipped.
	dir := t.TempDir()
	a := writeResolv(t, dir, "resolv.conf", strings.Join([]string{
		"# search commented.example",
		"nameserver 127.0.0.53",
		"search Lan. home.arpa Example.ORG",
		"options edns0 trust-ad",
		"search",
		"searchx notthis.example",
		"  domain fritz.box",
		"search a..b " + strings.Repeat("x", 64) + ".example .",
	}, "\n")+"\n")
	b := writeResolv(t, dir, "resolved.conf", "search example.org LAN corp.example\ndomain HOME.ARPA.\n")
	got := searchDomains([]string{a, filepath.Join(dir, "missing"), b})
	want := []string{"corp.example", "example.org", "fritz.box", "home.arpa", "lan"}
	sorted := append([]string(nil), got...)
	sort.Strings(sorted)
	if strings.Join(sorted, ",") != strings.Join(want, ",") {
		t.Errorf("searchDomains = %v, want %v (in any order, each once)", got, want)
	}

	if got := searchDomains([]string{filepath.Join(dir, "missing")}); len(got) != 0 {
		t.Errorf("searchDomains(missing file) = %v, want none", got)
	}
}

// searchHandler builds a handler as main does: the dns.local_domains
// entries set, a client on the LAN.
func searchHandler(localDomains []string) *dnsserver.Handler {
	h := dnsserver.NewHandler(blocklist.NewStore(), stats.New(), nil, nopLogger{}, "zero", 60, nil, false, "drop")
	h.SetQueryLogMode("none")
	h.SetLocalDomains(localDomains)
	return h
}

type nopLogger struct{}

func (nopLogger) Log(querylog.Record) {}

func TestLogSearchDomains(t *testing.T) {
	// CL 101: one INFO line for each search domain whose names s-hole sends
	// to every upstream. The line names the domain and suggests
	// dns.local_domains. A domain that s-hole keeps on the LAN (built in, or
	// a dns.local_domains entry) gets no line.
	h := searchHandler([]string{"corp.example"})
	var jl jsonLog
	domains := []string{
		"lan", "fritz.box", "home.arpa", "office.lan", "localdomain",
		"corp.example", "eu.corp.example",
		"example.org", "isp-customer.example.net",
	}
	logSearchDomains(jl.logger(), domains, h.KeepsLocal)
	recs := jl.records(t)
	if len(recs) != 2 {
		t.Fatalf("log lines = %d, want 2: %v", len(recs), recs)
	}
	named := map[string]bool{}
	for _, r := range recs {
		if r["level"] != "INFO" {
			t.Errorf("line %v: level %v, want INFO", r, r["level"])
		}
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(line), "dns.local_domains") {
			t.Errorf("line %v does not suggest dns.local_domains", r)
		}
		for _, d := range domains {
			for _, v := range r {
				if s, ok := v.(string); ok && s == d {
					named[d] = true
				}
			}
		}
	}
	if !named["example.org"] || !named["isp-customer.example.net"] || len(named) != 2 {
		t.Errorf("domains named in the log = %v, want example.org and isp-customer.example.net", named)
	}

	var none jsonLog
	logSearchDomains(none.logger(), nil, h.KeepsLocal)
	if recs := none.records(t); len(recs) != 0 {
		t.Errorf("no search domains: log lines %v, want none", recs)
	}
}

// answerWriter is a dns.ResponseWriter for a client on the LAN that keeps
// the reply.
type answerWriter struct{ reply *dns.Msg }

func (w *answerWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (w *answerWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 40000}
}
func (w *answerWriter) WriteMsg(m *dns.Msg) error { w.reply = m; return nil }
func (w *answerWriter) Write([]byte) (int, error) { return 0, nil }
func (w *answerWriter) Close() error              { return nil }
func (w *answerWriter) TsigStatus() error         { return nil }
func (w *answerWriter) TsigTimersOnly(bool)       {}
func (w *answerWriter) Hijack()                   {}

func TestLogSearchDomains_DoesNotAddTheDomain(t *testing.T) {
	// CL 101: s-hole does not add an uncovered search domain on its own (it
	// can be a public domain). After the startup check, names under it are
	// still public names. With no upstream, a public name is forwarded and
	// fails (SERVFAIL), while a LAN-only name gets a local NXDOMAIN.
	dir := t.TempDir()
	conf := writeResolv(t, dir, "resolv.conf", "search myisp.example\nnameserver 192.168.1.1\n")
	h := searchHandler(nil)
	var jl jsonLog
	logSearchDomains(jl.logger(), searchDomains([]string{conf}), h.KeepsLocal)
	if recs := jl.records(t); len(recs) != 1 || recs[0]["level"] != "INFO" {
		t.Fatalf("log lines = %v, want one INFO line", recs)
	}
	if h.KeepsLocal("myisp.example") {
		t.Error("KeepsLocal(myisp.example) = true after the startup check, want false")
	}
	w := &answerWriter{}
	h.ServeDNS(w, &dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: true}, Question: []dns.Question{{Name: "laptop.myisp.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})
	if w.reply == nil || w.reply.Rcode != dns.RcodeServerFailure {
		t.Errorf("laptop.myisp.example: reply %v, want SERVFAIL (forwarded as a public name)", w.reply)
	}
	w = &answerWriter{}
	h.ServeDNS(w, &dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: true}, Question: []dns.Question{{Name: "laptop.lan.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})
	if w.reply == nil || w.reply.Rcode != dns.RcodeNameError || !w.reply.Authoritative {
		t.Errorf("laptop.lan (control): reply %v, want a local NXDOMAIN", w.reply)
	}
}
