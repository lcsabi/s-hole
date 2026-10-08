package dnsserver

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// trustTestCert makes the production dohClient trust the httptest
// certificate by swapping only its Transport. Every httptest TLS server uses
// the same certificate, so the client then trusts all of them. The client
// keeps its own redirect policy, so the tests below exercise the production
// policy (b/102), not the policy of a client that a helper built. The swap is
// safe because the package runs its tests sequentially (no t.Parallel).
func trustTestCert(t *testing.T, ts *httptest.Server) {
	t.Helper()
	old := dohClient.Transport
	dohClient.Transport = ts.Client().Transport
	t.Cleanup(func() {
		dohClient.CloseIdleConnections()
		dohClient.Transport = old
	})
}

// dnsAnswerBody returns the wire-format reply to the DNS query in body, with
// an A record for ip, or nil when body is not a DNS query.
func dnsAnswerBody(body []byte, ip net.IP) []byte {
	var req dns.Msg
	if req.Unpack(body) != nil || len(req.Question) != 1 {
		return nil
	}
	resp := new(dns.Msg)
	resp.SetReply(&req)
	q := req.Question[0]
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   ip,
	}}
	packed, err := resp.Pack()
	if err != nil {
		return nil
	}
	return packed
}

// startRedirectTarget runs the server that a redirect points to: plain HTTP,
// or HTTPS with the shared httptest certificate. It counts every request it
// gets and answers a DNS query with 5.5.5.5.
func startRedirectTarget(t *testing.T, useTLS bool) (base string, hits *atomic.Int64) {
	t.Helper()
	hits = new(atomic.Int64)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		packed := dnsAnswerBody(body, net.IPv4(5, 5, 5, 5))
		if packed == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", dohMediaType)
		_, _ = w.Write(packed)
	})
	var ts *httptest.Server
	if useTLS {
		ts = httptest.NewTLSServer(h)
	} else {
		ts = httptest.NewServer(h)
	}
	t.Cleanup(ts.Close)
	return ts.URL, hits
}

// startRedirectingDoH runs a DoH upstream that answers every request with
// status code and a Location that points to target. The 3xx reply carries a
// valid DNS answer with 6.6.6.6 in its body, so a client that read the body
// as the answer would show 6.6.6.6. It swaps dohClient's Transport to trust
// the httptest certificate (see trustTestCert).
func startRedirectingDoH(t *testing.T, code int, target string) (endpoint string, hits *atomic.Int64) {
	t.Helper()
	hits = new(atomic.Int64)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Location", target)
		if packed := dnsAnswerBody(body, net.IPv4(6, 6, 6, 6)); packed != nil {
			w.Header().Set("Content-Type", dohMediaType)
			w.WriteHeader(code)
			_, _ = w.Write(packed)
			return
		}
		w.WriteHeader(code)
	}))
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	trustTestCert(t, ts)
	return ts.URL + "/dns-query", hits
}

// redirectCodes are the redirect statuses that Go's default client policy
// follows: 307 and 308 send the POST body (the query) again, and 301, 302,
// and 303 change to GET but still connect to the new host.
var redirectCodes = []int{
	http.StatusMovedPermanently,
	http.StatusFound,
	http.StatusSeeOther,
	http.StatusTemporaryRedirect,
	http.StatusPermanentRedirect,
}

func TestForward_DoHRedirectIsAFailedAttempt(t *testing.T) {
	// SEC-21 (b/102): a DoH upstream that answers with a redirect is a failed
	// attempt. The client does not follow the redirect: no request reaches
	// the redirect target, a plain HTTP server or another HTTPS server that
	// the client trusts. The forwarder uses the next upstream and returns its
	// answer, not the DNS message in the 3xx body. The tracker counts a
	// transport failure for the redirecting upstream and puts it in cooldown.
	for _, code := range redirectCodes {
		for _, useTLS := range []bool{false, true} {
			kind := "http"
			if useTLS {
				kind = "https"
			}
			t.Run(fmt.Sprintf("%d to %s", code, kind), func(t *testing.T) {
				targetBase, targetHits := startRedirectTarget(t, useTLS)
				target := targetBase + "/dns-query"
				redirector, redirHits := startRedirectingDoH(t, code, target)
				next, nextHits := startMockUpstream(t, net.IPv4(7, 7, 7, 7))
				tracker := newUpstreamTracker()

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				resp, err := forwardWith(ctx, buildReq("redirected.zqxv-doh.example"), []string{redirector, next}, tracker)
				if err != nil {
					t.Fatalf("forward: %v, want the answer of the next upstream", err)
				}
				if ip := firstA(resp); !ip.Equal(net.IPv4(7, 7, 7, 7)) {
					t.Errorf("answer = %v, want 7.7.7.7 from the next upstream", ip)
				}
				if redirHits.Load() != 1 || nextHits.Load() != 1 {
					t.Errorf("redirecting upstream hits = %d, next upstream hits = %d, want 1 and 1", redirHits.Load(), nextHits.Load())
				}
				if n := targetHits.Load(); n != 0 {
					t.Errorf("the redirect target got %d requests, want 0", n)
				}
				if n := tracker.TransportFailureCounts()[redirector]; n != 1 {
					t.Errorf("transport failures for the redirecting upstream = %d, want 1", n)
				}
				if !tracker.shouldSkip(redirector, time.Now()) {
					t.Error("the redirecting upstream is not in cooldown")
				}

				// Control: the client trusts the target, so its zero hits
				// come from the redirect policy and not from a TLS failure.
				if !useTLS {
					return
				}
				if _, err := exchange(ctx, buildReq("control.zqxv-doh.example"), target); err != nil {
					t.Fatalf("direct exchange with the HTTPS target failed: %v", err)
				}
				if n := targetHits.Load(); n != 1 {
					t.Errorf("direct exchange: target hits = %d, want 1", n)
				}
			})
		}
	}
}

func TestExchangeDoH_RedirectIsAnError(t *testing.T) {
	// SEC-21 (b/102): exchangeDoH returns an error for every redirect status
	// and never the DNS message in the 3xx body. The error names no query.
	for _, code := range redirectCodes {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			targetBase, targetHits := startRedirectTarget(t, true)
			redirector, _ := startRedirectingDoH(t, code, targetBase+"/dns-query")
			resp, err := exchangeDoH(context.Background(), buildReq("redirected.zqxv-doh.example"), redirector)
			if err == nil {
				t.Fatalf("exchangeDoH = %v, nil error; want a failure", resp)
			}
			if resp != nil {
				t.Errorf("exchangeDoH returned a reply %v with the error", resp)
			}
			if strings.Contains(strings.ToLower(err.Error()), "zqxv") {
				t.Errorf("error %q names the query", err)
			}
			if n := targetHits.Load(); n != 0 {
				t.Errorf("the redirect target got %d requests, want 0", n)
			}
		})
	}
}

func TestServeDNS_DoHRedirectFailsOverAndIsCounted(t *testing.T) {
	// SEC-21 (b/102): through ServeDNS, a redirecting DoH upstream fails the
	// attempt, the next upstream answers, the redirect target gets nothing,
	// and the shared tracker counts one transport failure for the
	// redirecting upstream (shole_upstream_transport_failures_total).
	targetBase, targetHits := startRedirectTarget(t, false)
	redirector, _ := startRedirectingDoH(t, http.StatusTemporaryRedirect, targetBase+"/dns-query")
	next, _ := startMockUpstream(t, net.IPv4(7, 7, 7, 7))
	before := UpstreamTransportFailures()[redirector]

	h := NewHandler(blocklist.NewStore(), stats.New(), []string{redirector, next}, nullLogger{}, "zero", 60, nil, false, "full")
	h.SetQueryLogMode("all")
	w := fakeClient()
	h.ServeDNS(w, buildReq("redirected.zqxv-doh.example"))
	if ip := firstA(w.written); w.written == nil || !ip.Equal(net.IPv4(7, 7, 7, 7)) {
		t.Fatalf("reply = %v, want 7.7.7.7 from the next upstream", w.written)
	}
	if n := targetHits.Load(); n != 0 {
		t.Errorf("the redirect target got %d requests, want 0", n)
	}
	if got := UpstreamTransportFailures()[redirector] - before; got != 1 {
		t.Errorf("transport failures for the redirecting upstream rose by %d, want 1", got)
	}
}

func TestServeDNS_DoHRedirectSummaryNamesNoQuery(t *testing.T) {
	// SEC-21 (b/102): when the only upstream redirects, the query is
	// unresolved. The failure summary names the configured upstream through
	// redact.URL (no user info, no query string), and neither it nor any
	// other log line names the query, the client, or the redirect target,
	// even under query_log.mode "all". The redirect target gets nothing.
	app := captureAppLog(t)
	targetBase, targetHits := startRedirectTarget(t, false)
	target := targetBase + "/zqxv-location"
	redirector, _ := startRedirectingDoH(t, http.StatusPermanentRedirect, target)
	configured := strings.Replace(redirector, "https://", "https://u53r:p455@", 1) + "?token=t0k3n"

	h := NewHandler(blocklist.NewStore(), stats.New(), []string{configured}, nullLogger{}, "zero", 60, nil, false, "full")
	h.SetQueryLogMode("all")
	w := fakeClient()
	h.ServeDNS(w, buildReq("Redirected.ZQXV-doh.example"))
	if w.written == nil || w.written.Rcode != dns.RcodeServerFailure {
		t.Fatalf("reply = %v, want SERVFAIL", w.written)
	}
	if n := targetHits.Load(); n != 0 {
		t.Errorf("the redirect target got %d requests, want 0", n)
	}
	if recs := app.records(t); len(recs) != 0 {
		t.Fatalf("the query wrote %d log lines before the summary, want 0:\n%s", len(recs), app.text())
	}

	reportNow(h)
	sums := app.withMsg(t, "queries could not be resolved")
	if len(sums) != 1 || sums[0]["queries"] != float64(1) {
		t.Fatalf("summary = %v, want one line with queries=1:\n%s", sums, app.text())
	}
	causes, _ := sums[0]["causes"].(string)
	hostPort := strings.TrimPrefix(strings.TrimSuffix(redirector, "/dns-query"), "https://")
	if !strings.Contains(causes, hostPort) || !strings.Contains(causes, "redacted") {
		t.Errorf("causes = %q, want the upstream %s shown through redact.URL", causes, hostPort)
	}
	text := strings.ToLower(app.text())
	targetHost := strings.TrimPrefix(targetBase, "http://")
	for _, leak := range []string{"zqxv", "redirected.", "u53r", "p455", "t0k3n", targetHost, "192.168.1.100", "33333"} {
		if strings.Contains(text, leak) {
			t.Errorf("application log holds %q:\n%s", leak, app.text())
		}
	}
}
