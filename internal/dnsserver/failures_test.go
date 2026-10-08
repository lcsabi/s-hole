package dnsserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

func TestForward_ErrorListsEachUpstreamNotTheQuery(t *testing.T) {
	// D4 (b/078): when every upstream fails, the error is a *ForwardError
	// that lists each upstream and its error, and never the query name.
	a, _ := startFailingUpstream(t)
	b, _ := startFailingUpstream(t)
	_, err := forwardWith(context.Background(), buildReq("privatename.example.com"), []string{a, b}, newUpstreamTracker())
	var fe *ForwardError
	if !errors.As(err, &fe) {
		t.Fatalf("forward error = %T %v, want *ForwardError", err, err)
	}
	if len(fe.Causes) != 2 || fe.Causes[0].Upstream != a || fe.Causes[1].Upstream != b {
		t.Fatalf("causes = %+v, want one for %s and one for %s", fe.Causes, a, b)
	}
	for _, c := range fe.Causes {
		if c.Err == nil {
			t.Errorf("cause for %s has no error", c.Upstream)
		}
	}
	text := err.Error()
	if strings.Contains(strings.ToLower(text), "privatename") {
		t.Errorf("error %q names the query", text)
	}
	for _, u := range []string{a, b} {
		if !strings.Contains(text, u) {
			t.Errorf("error %q does not name upstream %s", text, u)
		}
	}
	if (&ForwardError{}).Error() == "" {
		t.Error("an empty ForwardError has no text")
	}
}

// failingHandler returns a handler whose two upstreams both fail fast.
func failingHandler(t *testing.T, mode string) (*Handler, []string) {
	t.Helper()
	a, _ := startFailingUpstream(t)
	b, _ := startFailingUpstream(t)
	h := NewHandler(blocklist.NewStore(), stats.New(), []string{a, b}, nullLogger{}, "zero", 60, nil, false, "full")
	h.SetQueryLogMode(mode)
	return h, []string{a, b}
}

func reportNow(h *Handler) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.RunFailureReport(ctx) // logs once at ctx end and returns
}

func TestRunFailureReport_OncePerMinute(t *testing.T) {
	// D4: the summary is logged once per minute while failures happen, and
	// not in a minute without failures. The fake clock of synctest drives
	// the ticker.
	app := captureAppLog(t)
	synctest.Test(t, func(t *testing.T) {
		h := NewHandler(blocklist.NewStore(), stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "drop")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			h.RunFailureReport(ctx)
			close(done)
		}()
		synctest.Wait()
		cause := &ForwardError{Causes: []UpstreamCause{{Upstream: "9.9.9.9:53", Err: errors.New("i/o timeout")}}}

		summaries := func() int { return len(app.withMsg(t, "queries could not be resolved")) }

		h.failures.record(cause)
		h.failures.record(cause)
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if n := summaries(); n != 0 {
			t.Errorf("summary after 30 s = %d lines, want 0", n)
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if n := summaries(); n != 1 {
			t.Fatalf("summary after 1 min = %d lines, want 1", n)
		}
		if got := app.withMsg(t, "queries could not be resolved")[0]["queries"]; got != float64(2) {
			t.Errorf("queries = %v, want 2", got)
		}

		time.Sleep(time.Minute) // a minute without failures
		synctest.Wait()
		if n := summaries(); n != 1 {
			t.Errorf("summary after an empty minute = %d lines, want still 1", n)
		}

		h.failures.record(cause)
		time.Sleep(time.Minute)
		synctest.Wait()
		if n := summaries(); n != 2 {
			t.Errorf("summary after the third minute = %d lines, want 2", n)
		}

		h.failures.record(cause)
		cancel()
		<-done
		if n := summaries(); n != 3 {
			t.Errorf("summary at ctx end = %d lines, want 3", n)
		}
	})
}

func TestRunFailureReport_PlaintextFallbacks(t *testing.T) {
	// D4: the report also logs "queries were sent unencrypted" with the
	// count when PlaintextFallbacks grew in the interval, and nothing when it
	// did not.
	app := captureAppLog(t)
	synctest.Test(t, func(t *testing.T) {
		h := NewHandler(blocklist.NewStore(), stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "drop")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			h.RunFailureReport(ctx)
			close(done)
		}()
		synctest.Wait()
		mixed := []string{"https://9.9.9.9/dns-query", "9.9.9.9:53"}

		lines := func() []map[string]any { return app.withMsg(t, "queries were sent unencrypted") }

		for i := 0; i < 3; i++ {
			countPlaintextFallback("9.9.9.9:53", mixed)
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		got := lines()
		if len(got) != 1 || got[0]["queries"] != float64(3) || got[0]["level"] != "WARN" {
			t.Fatalf("after 3 fallbacks: lines = %v, want one WARN with queries=3", got)
		}

		time.Sleep(time.Minute)
		synctest.Wait()
		if n := len(lines()); n != 1 {
			t.Errorf("after a minute without fallbacks: %d lines, want still 1", n)
		}

		countPlaintextFallback("9.9.9.9:53", mixed)
		cancel()
		<-done
		got = lines()
		if len(got) != 2 || got[1]["queries"] != float64(1) {
			t.Errorf("at ctx end: lines = %v, want a second line with queries=1", got)
		}
		if n := len(app.withMsg(t, "queries could not be resolved")); n != 0 {
			t.Errorf("unresolved summary logged %d times without a failure", n)
		}
	})
}

func TestForward_PlaintextFallbackCount(t *testing.T) {
	// D5: a query answered by a plain upstream counts when the list also has
	// a DoH entry (every DoH entry had failed). A plain-only list, and a
	// query answered over DoH, do not count.
	dohDown, _ := startDoHUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	plain, _ := startMockUpstream(t, net.IPv4(4, 4, 4, 4))

	before := PlaintextFallbacks()
	if _, err := forwardWith(context.Background(), buildReq("example.com"), []string{dohDown, plain}, newUpstreamTracker()); err != nil {
		t.Fatalf("forward = %v", err)
	}
	if got := PlaintextFallbacks() - before; got != 1 {
		t.Errorf("fallbacks after DoH failed and plain answered = %d, want 1", got)
	}

	before = PlaintextFallbacks()
	if _, err := forwardWith(context.Background(), buildReq("example.com"), []string{plain}, newUpstreamTracker()); err != nil {
		t.Fatalf("forward = %v", err)
	}
	if got := PlaintextFallbacks() - before; got != 0 {
		t.Errorf("fallbacks with a plain-only list = %d, want 0", got)
	}

	dohUp, _ := startMockDoHUpstream(t, net.IPv4(5, 5, 5, 5))
	before = PlaintextFallbacks()
	if _, err := forwardWith(context.Background(), buildReq("example.com"), []string{dohUp, plain}, newUpstreamTracker()); err != nil {
		t.Fatalf("forward = %v", err)
	}
	if got := PlaintextFallbacks() - before; got != 0 {
		t.Errorf("fallbacks when DoH answered = %d, want 0", got)
	}
}

// clockTLSUpstream serves DoH with a certificate that is valid only between
// notBefore and notAfter, and points dohClient at a pool that trusts it.
func clockTLSUpstream(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}}}
	ts.StartTLS()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	old := dohClient
	dohClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, CheckRedirect: old.CheckRedirect}
	t.Cleanup(func() {
		dohClient.CloseIdleConnections()
		dohClient = old
		ts.Close()
	})
	return ts.URL + "/dns-query"
}

func TestFailureReport_ClockHint(t *testing.T) {
	// D4: when an upstream error is an x509 certificate that is expired or
	// not yet valid, the hint names the system clock. The error comes from a
	// real TLS handshake, so the whole error chain is checked.
	now := time.Now()
	cases := map[string][2]time.Time{
		"expired":       {now.Add(-48 * time.Hour), now.Add(-24 * time.Hour)},
		"not yet valid": {now.Add(24 * time.Hour), now.Add(48 * time.Hour)},
	}
	for name, validity := range cases {
		t.Run(name, func(t *testing.T) {
			endpoint := clockTLSUpstream(t, validity[0], validity[1])
			h := NewHandler(blocklist.NewStore(), stats.New(), []string{endpoint}, nullLogger{}, "zero", 60, nil, false, "drop")
			app := captureAppLog(t)
			w := fakeClient()
			h.ServeDNS(w, buildReq("example.com"))
			if w.written == nil || w.written.Rcode != dns.RcodeServerFailure {
				t.Fatalf("reply = %v, want SERVFAIL", w.written)
			}
			reportNow(h)
			sums := app.withMsg(t, "queries could not be resolved")
			if len(sums) != 1 {
				t.Fatalf("got %d summary lines, want 1:\n%s", len(sums), app.text())
			}
			if hint, _ := sums[0]["hint"].(string); !strings.Contains(hint, "clock") {
				t.Errorf("hint = %q, want it to name the system clock", hint)
			}
		})
	}
}

func TestClockSuspect(t *testing.T) {
	// The clock hint needs an x509 validity error; another certificate error
	// or a network error does not point at the clock.
	expired := x509.CertificateInvalidError{Reason: x509.Expired}
	if !clockSuspect(expired) {
		t.Error("clockSuspect(Expired) = false")
	}
	if !clockSuspect(errors.Join(errors.New("tls: handshake"), expired)) {
		t.Error("clockSuspect(wrapped Expired) = false")
	}
	if clockSuspect(x509.CertificateInvalidError{Reason: x509.NameMismatch}) {
		t.Error("clockSuspect(NameMismatch) = true")
	}
	if clockSuspect(x509.UnknownAuthorityError{}) {
		t.Error("clockSuspect(UnknownAuthority) = true")
	}
	if clockSuspect(errors.New("connection refused")) {
		t.Error("clockSuspect(network error) = true")
	}
}

func TestFailureReport_HidesDoHSecrets(t *testing.T) {
	// D4 with D8: the summary names a DoH upstream with its secrets redacted.
	app := captureAppLog(t)
	h := NewHandler(blocklist.NewStore(), stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "drop")
	h.failures.record(&ForwardError{Causes: []UpstreamCause{{
		Upstream: "https://u53r:p455@9.9.9.9/dns-query?token=t0k3n",
		Err:      errors.New("status 403"),
	}}})
	h.failures.record(context.DeadlineExceeded)
	reportNow(h)
	text := app.text()
	for _, secret := range []string{"u53r", "p455", "t0k3n"} {
		if strings.Contains(text, secret) {
			t.Errorf("summary holds %q:\n%s", secret, text)
		}
	}
	if sums := app.withMsg(t, "queries could not be resolved"); len(sums) != 1 || sums[0]["queries"] != float64(2) {
		t.Errorf("summary = %v, want one line with queries=2", sums)
	}
}

func TestServeDNS_UnresolvedSummaryNamesNoQuery(t *testing.T) {
	// PRIV-03 (b/078): an unresolved query writes no line of its own. The
	// summary that RunFailureReport logs has the count, each upstream's last
	// error, and a hint that does not blame the clock. Under every mode, "all"
	// included, it has no last_domain and names no query (in any case) and no
	// client address or port. An interval without failures logs nothing.
	for _, mode := range []string{"all", "blocked", "none"} {
		t.Run(mode, func(t *testing.T) {
			h, ups := failingHandler(t, mode)
			app := captureAppLog(t)
			for _, name := range []string{"first.zqxv-example.com", "Second.ZQXV-Example.com"} {
				w := fakeClient()
				h.ServeDNS(w, buildReq(name))
				if w.written == nil || w.written.Rcode != dns.RcodeServerFailure {
					t.Fatalf("reply = %v, want SERVFAIL", w.written)
				}
			}
			if recs := app.records(t); len(recs) != 0 {
				t.Fatalf("failed queries wrote %d log lines before the summary, want 0:\n%s", len(recs), app.text())
			}

			reportNow(h)
			sums := app.withMsg(t, "queries could not be resolved")
			if len(sums) != 1 {
				t.Fatalf("got %d summary lines, want 1:\n%s", len(sums), app.text())
			}
			s := sums[0]
			if s["level"] != "WARN" || s["queries"] != float64(2) {
				t.Errorf("summary = %v, want a WARN with queries=2", s)
			}
			causes, _ := s["causes"].(string)
			for _, u := range ups {
				if !strings.Contains(causes, u+": ") {
					t.Errorf("causes %q do not name %s with its error", causes, u)
				}
			}
			if hint, _ := s["hint"].(string); hint == "" || strings.Contains(hint, "clock") {
				t.Errorf("hint = %q, want a hint that does not blame the clock", hint)
			}
			if _, has := s["last_domain"]; has {
				t.Errorf("summary has last_domain under mode %q: %v", mode, s)
			}
			text := strings.ToLower(app.text())
			for _, leak := range []string{"zqxv-example", "first.", "second.", "192.168.1.100", "33333"} {
				if strings.Contains(text, leak) {
					t.Errorf("application log holds %q under mode %q:\n%s", leak, mode, app.text())
				}
			}
			if n := len(app.withMsg(t, "replies could not be sent")); n != 0 {
				t.Errorf("got %d failed-reply summaries, but every reply was sent", n)
			}

			// The interval starts again: a report without new failures logs
			// nothing.
			reportNow(h)
			if n := len(app.records(t)); n != 1 {
				t.Errorf("got %d log lines after an empty interval, want still 1:\n%s", n, app.text())
			}
		})
	}
}

func TestRunFailureReport_ReplySummaryOncePerMinute(t *testing.T) {
	// PRIV-03: a failed reply write is counted into a summary that
	// RunFailureReport logs once per minute, with the count for the minute,
	// and nothing in a minute without failures. The fake clock of synctest
	// drives the ticker.
	app := captureAppLog(t)
	synctest.Test(t, func(t *testing.T) {
		store := blocklist.NewStore()
		store.Replace([]string{"ads.zqxv-tracker.com"})
		h := NewHandler(store, stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "full")
		h.SetQueryLogMode("all")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			h.RunFailureReport(ctx)
			close(done)
		}()
		// Stop the report goroutine also when a check below ends the test
		// early, so the bubble can exit.
		defer func() {
			cancel()
			<-done
		}()
		synctest.Wait()

		fail := func(n int) {
			for i := 0; i < n; i++ {
				w := fakeClient()
				w.writeError = replyWriteError()
				h.ServeDNS(w, buildReq("Ads.Zqxv-Tracker.com"))
			}
		}
		summaries := func() []map[string]any { return app.withMsg(t, "replies could not be sent") }

		fail(3)
		if n := len(app.records(t)); n != 0 {
			t.Errorf("failed writes logged %d lines at once, want 0", n)
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if n := len(summaries()); n != 0 {
			t.Errorf("summary after 30 s = %d lines, want 0", n)
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		got := summaries()
		if len(got) != 1 || got[0]["replies"] != float64(3) || got[0]["level"] != "WARN" {
			t.Fatalf("after 1 min: summaries = %v, want one WARN with replies=3", got)
		}

		time.Sleep(time.Minute) // a minute without failures
		synctest.Wait()
		if n := len(summaries()); n != 1 {
			t.Errorf("summary after an empty minute = %d lines, want still 1", n)
		}

		fail(1)
		time.Sleep(time.Minute)
		synctest.Wait()
		got = summaries()
		if len(got) != 2 || got[1]["replies"] != float64(1) {
			t.Errorf("after the third minute: summaries = %v, want a second one with replies=1", got)
		}

		fail(2)
		cancel()
		<-done
		got = summaries()
		if len(got) != 3 || got[2]["replies"] != float64(2) {
			t.Errorf("at ctx end: summaries = %v, want a third one with replies=2", got)
		}
		if n := len(app.withMsg(t, "queries could not be resolved")); n != 0 {
			t.Errorf("unresolved summary logged %d times without an unresolved query", n)
		}
		if text := strings.ToLower(app.text()); strings.Contains(text, "zqxv-tracker") || strings.Contains(text, "192.168.1.100") {
			t.Errorf("application log holds query data:\n%s", app.text())
		}
	})
}
