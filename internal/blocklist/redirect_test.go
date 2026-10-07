package blocklist

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/redact"
)

// The b/097 tests: a blocklist download that starts on HTTPS must not follow
// a redirect to plain HTTP. The refused redirect is a download failure, so
// the stale-cache fallback applies, and a WARN names both URLs in redacted
// form. A redirect to HTTPS on another host still works.

// otherHost is a second host name for HTTPS test servers. The httptest
// certificate is valid for it, and trustTLS dials it on 127.0.0.1, so a
// redirect to it goes to a different host name than the configured URL.
const otherHost = "example.com"

// trustTLS points httpClient at a transport that trusts the certificates of
// srvs and dials otherHost on 127.0.0.1. It keeps httpClient itself, so the
// production redirect policy and timeout stay in place. Only tests write
// httpClient.Transport, and blocklist tests run sequentially (no t.Parallel),
// so the write never races a download.
func trustTLS(t *testing.T, srvs ...*httptest.Server) {
	t.Helper()
	pool := x509.NewCertPool()
	for _, s := range srvs {
		pool.AddCert(s.Certificate())
	}
	tr := srvs[0].Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.RootCAs = pool
	var d net.Dialer
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, port, err := net.SplitHostPort(addr); err == nil && host == otherHost {
			addr = net.JoinHostPort("127.0.0.1", port)
		}
		return d.DialContext(ctx, network, addr)
	}
	prev := httpClient.Transport
	httpClient.Transport = tr
	t.Cleanup(func() {
		tr.CloseIdleConnections()
		httpClient.Transport = prev
	})
}

// redirectServer is a TLS server that answers every request with a 302 to
// target(), and counts the requests.
func redirectServer(t *testing.T, target func() string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, target(), http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// tlsListServer is a TLS server that serves body and counts the requests.
func tlsListServer(t *testing.T, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// onOtherHost returns the URL of srv with otherHost as the host name.
func onOtherHost(srv *httptest.Server) string {
	return strings.Replace(srv.URL, "127.0.0.1", otherHost, 1)
}

// withTLSSecrets adds user info and a query string to an https URL. It uses
// the same secrets as withSecrets, so assertNoSecrets finds them.
func withTLSSecrets(u string) string {
	return strings.Replace(u, "https://", "https://listuser:listpass@", 1) + "/hosts.txt?token=listtoken"
}

// withTargetSecrets adds other user info and another query string to a
// redirect target, so a test can tell the target's secrets from the
// configured URL's secrets.
func withTargetSecrets(u string) string {
	u = strings.Replace(u, "http://", "http://targetuser:targetpass@", 1)
	u = strings.Replace(u, "https://", "https://targetuser:targetpass@", 1)
	return u + "/next.txt?token=targettoken"
}

func assertNoTargetSecrets(t *testing.T, where, text string) {
	t.Helper()
	for _, s := range []string{"targetuser", "targetpass", "targettoken"} {
		if strings.Contains(text, s) {
			t.Errorf("%s holds the redirect target's %q:\n%s", where, s, text)
		}
	}
}

// refusedRedirectWarns returns the WARN records that hold both the
// configured URL and the redirect target as attribute values.
func refusedRedirectWarns(recs []map[string]any, configured, target string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["level"] != "WARN" {
			continue
		}
		var hasConfigured, hasTarget bool
		for _, v := range r {
			switch v {
			case configured:
				hasConfigured = true
			case target:
				hasTarget = true
			}
		}
		if hasConfigured && hasTarget {
			out = append(out, r)
		}
	}
	return out
}

func TestUpdate_HTTPSToHTTPRedirectUsesStaleCache(t *testing.T) {
	// b/097: an https list that redirects to http is not downloaded. The plain
	// HTTP server gets no request, the list comes from the cached copy, and
	// the source is stale. One WARN names the configured URL and the redirect
	// target, both redacted; no log line and no error holds a secret of
	// either URL.
	for _, m := range downloadModes {
		t.Run(m.name, func(t *testing.T) {
			plain, plainHits := countingServer(t, "0.0.0.0 plain.example.com\n")
			target := withTargetSecrets(plain.URL)
			tls, tlsHits := redirectServer(t, func() string { return target })
			trustTLS(t, tls)
			url := withTLSSecrets(tls.URL)

			dir := t.TempDir()
			seedCache(t, dir, url, cachedList, m.age)
			mtime := ageCopy(t, dir, url, m.age)
			records := captureLogs(t)

			store := NewStore()
			if err := Update(store, []string{url}, dir, m.mode); err != nil {
				t.Fatalf("Update = %v, want nil: the cached copy serves the list", err)
			}
			recs := records()

			if n := plainHits.Load(); n != 0 {
				t.Errorf("plain HTTP server got %d requests, want 0", n)
			}
			if n := tlsHits.Load(); n != 1 {
				t.Errorf("HTTPS server got %d requests, want 1", n)
			}
			if store.IsBlocked("plain.example.com") {
				t.Error("a domain from the plain HTTP list is in the block set")
			}
			if !store.IsBlocked("cached.example.com") || store.Len() != 1 {
				t.Errorf("store has %d domains, want only the cached copy's cached.example.com", store.Len())
			}
			src := sourceByURL(store)[url]
			if !src.Stale || src.Count != 1 || !src.LastRefresh.Equal(mtime) {
				t.Errorf("source status = %+v, want stale with 1 domain and LastRefresh %v", src, mtime)
			}
			if got := loadedFrom(t, recs)[redact.URL(url)]; got != "stale_cache" {
				t.Errorf("from = %q, want stale_cache", got)
			}
			if n := len(staleWarns(recs)); n != 1 {
				t.Errorf("got %d stale-cache records, want 1: %v", n, recs)
			}

			warns := refusedRedirectWarns(recs, redact.URL(url), redact.URL(target))
			if len(warns) != 1 {
				t.Errorf("got %d WARN records with both redacted URLs, want 1: %v", len(warns), recs)
			}
			text := logText(t, recs)
			assertNoSecrets(t, "the log", text)
			assertNoTargetSecrets(t, "the log", text)
		})
	}
}

func TestUpdate_HTTPSToHTTPRedirectNoCacheFailsList(t *testing.T) {
	// b/097: with no cached copy, the refused redirect fails the list. As the
	// only list, it fails Update, and the existing block set is kept. The
	// plain HTTP server gets no request, and the error holds no secret of
	// either URL.
	plain, plainHits := countingServer(t, "0.0.0.0 plain.example.com\n")
	target := withTargetSecrets(plain.URL)
	tls, _ := redirectServer(t, func() string { return target })
	trustTLS(t, tls)
	url := withTLSSecrets(tls.URL)
	records := captureLogs(t)

	store := NewStore()
	store.Replace([]string{"old.example.com"})
	err := Update(store, []string{url}, t.TempDir(), DownloadFirst)
	if err == nil {
		t.Fatal("Update = nil, want an error: the only list was refused")
	}
	recs := records()

	if n := plainHits.Load(); n != 0 {
		t.Errorf("plain HTTP server got %d requests, want 0", n)
	}
	if !store.IsBlocked("old.example.com") || store.Len() != 1 {
		t.Errorf("store has %d domains, want only the existing old.example.com", store.Len())
	}
	if src := sourceByURL(store)[url]; !src.Stale || src.Count != 0 || !src.LastRefresh.IsZero() {
		t.Errorf("source status = %+v, want failed (stale, no domains, never refreshed)", src)
	}
	if n := len(staleWarns(recs)); n != 0 {
		t.Errorf("got %d stale-cache records with no cached copy, want 0", n)
	}
	if n := len(refusedRedirectWarns(recs, redact.URL(url), redact.URL(target))); n != 1 {
		t.Errorf("got %d WARN records with both redacted URLs, want 1: %v", n, recs)
	}
	assertNoSecrets(t, "the returned error", err.Error())
	assertNoTargetSecrets(t, "the returned error", err.Error())
	text := logText(t, recs)
	assertNoSecrets(t, "the log", text)
	assertNoTargetSecrets(t, "the log", text)
}

func TestUpdate_HTTPSToHTTPRedirectOtherListStillLoads(t *testing.T) {
	// b/097: a refused redirect fails only its own list. A second list loads,
	// and the plain HTTP server gets no request.
	plain, plainHits := countingServer(t, "0.0.0.0 plain.example.com\n")
	tls, _ := redirectServer(t, func() string { return plain.URL + "/hosts.txt" })
	good, _ := tlsListServer(t, goodList)
	trustTLS(t, tls, good)
	captureLogs(t)

	store := NewStore()
	if err := Update(store, []string{tls.URL, good.URL}, t.TempDir(), DownloadFirst); err != nil {
		t.Fatalf("Update = %v, want nil: one list works", err)
	}
	if n := plainHits.Load(); n != 0 {
		t.Errorf("plain HTTP server got %d requests, want 0", n)
	}
	if !store.IsBlocked("good.example.com") || store.Len() != 1 {
		t.Errorf("store has %d domains, want only good.example.com", store.Len())
	}
	if src := sourceByURL(store)[tls.URL]; !src.Stale || src.Count != 0 {
		t.Errorf("redirected source status = %+v, want failed", src)
	}
}

func TestUpdate_HTTPSRedirectChainToHTTPRefused(t *testing.T) {
	// b/097: the check applies at every hop. HTTPS, then HTTPS on another
	// host, then HTTP: the HTTP request is not sent. The WARN names the
	// configured URL (the first one) and the HTTP target, both redacted.
	plain, plainHits := countingServer(t, "0.0.0.0 plain.example.com\n")
	target := withTargetSecrets(plain.URL)
	hop, hopHits := redirectServer(t, func() string { return target })
	first, _ := redirectServer(t, func() string { return onOtherHost(hop) + "/hop" })
	trustTLS(t, first, hop)
	url := withTLSSecrets(first.URL)

	dir := t.TempDir()
	seedCache(t, dir, url, cachedList, 10*time.Second)
	records := captureLogs(t)

	store := NewStore()
	if err := Update(store, []string{url}, dir, DownloadFirst); err != nil {
		t.Fatalf("Update = %v, want nil: the cached copy serves the list", err)
	}
	recs := records()

	if n := hopHits.Load(); n != 1 {
		t.Errorf("second HTTPS server got %d requests, want 1: the HTTPS hop is followed", n)
	}
	if n := plainHits.Load(); n != 0 {
		t.Errorf("plain HTTP server got %d requests, want 0", n)
	}
	if store.IsBlocked("plain.example.com") || !store.IsBlocked("cached.example.com") {
		t.Errorf("block set is wrong: want the cached copy only, have %d domains", store.Len())
	}
	if src := sourceByURL(store)[url]; !src.Stale {
		t.Errorf("source status = %+v, want stale", src)
	}
	if n := len(refusedRedirectWarns(recs, redact.URL(url), redact.URL(target))); n != 1 {
		t.Errorf("got %d WARN records with the configured URL and the HTTP target, want 1: %v", n, recs)
	}
	text := logText(t, recs)
	assertNoSecrets(t, "the log", text)
	assertNoTargetSecrets(t, "the log", text)
}

func TestUpdate_HTTPSRedirectToOtherHostFollowed(t *testing.T) {
	// b/097 negative: a redirect from HTTPS to HTTPS on another host name is
	// followed, as for a GitHub release download. The list comes from the
	// target, fresh, and no WARN is logged.
	dst, dstHits := tlsListServer(t, "0.0.0.0 target.example.com\n")
	src, srcHits := redirectServer(t, func() string { return onOtherHost(dst) + "/hosts.txt" })
	trustTLS(t, src, dst)

	dir := t.TempDir()
	seedCache(t, dir, src.URL, cachedList, 10*time.Second)
	records := captureLogs(t)

	store := NewStore()
	if err := Update(store, []string{src.URL}, dir, DownloadFirst); err != nil {
		t.Fatalf("Update = %v, want nil", err)
	}
	recs := records()

	if srcHits.Load() != 1 || dstHits.Load() != 1 {
		t.Errorf("requests: first server %d, target %d, want 1 and 1", srcHits.Load(), dstHits.Load())
	}
	if !store.IsBlocked("target.example.com") || store.Len() != 1 {
		t.Errorf("store has %d domains, want only the target's target.example.com", store.Len())
	}
	if s := sourceByURL(store)[src.URL]; s.Stale || s.Count != 1 {
		t.Errorf("source status = %+v, want fresh with 1 domain", s)
	}
	if got := loadedFrom(t, recs)[src.URL]; got != "download" {
		t.Errorf("from = %q, want download", got)
	}
	for _, r := range recs {
		if r["level"] == "WARN" || r["level"] == "ERROR" {
			t.Errorf("unexpected %v record: %v", r["level"], r)
		}
	}
}

func TestUpdate_HTTPToHTTPRedirectStillFollowed(t *testing.T) {
	// b/097 negative: the check applies only to a download that starts on
	// HTTPS. A list configured as http:// (which already has a config
	// warning) can still redirect to another http:// URL.
	dst, dstHits := countingServer(t, "0.0.0.0 target.example.com\n")
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dst.URL+"/hosts.txt", http.StatusFound)
	}))
	t.Cleanup(src.Close)
	records := captureLogs(t)

	store := NewStore()
	if err := Update(store, []string{src.URL}, t.TempDir(), DownloadFirst); err != nil {
		t.Fatalf("Update = %v, want nil", err)
	}
	if n := dstHits.Load(); n != 1 {
		t.Errorf("target got %d requests, want 1", n)
	}
	if !store.IsBlocked("target.example.com") {
		t.Error("the list from the redirect target is not in use")
	}
	for _, r := range records() {
		if r["level"] == "WARN" || r["level"] == "ERROR" {
			t.Errorf("unexpected %v record: %v", r["level"], r)
		}
	}
}

// countdownServer is a TLS server where /r/N redirects to /r/N-1 and /r/0
// serves a list. It counts the requests.
func countdownServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/r/%d", &n); err != nil {
			http.NotFound(w, r)
			return
		}
		if n == 0 {
			w.Write([]byte("0.0.0.0 end.example.com\n"))
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/r/%d", n-1), http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestUpdate_HTTPSRedirectLimitKept(t *testing.T) {
	// b/097: the new redirect policy keeps the limit of Go's default policy.
	// The client sends at most 10 requests: 9 redirects are followed, and a
	// 10th redirect fails the download.
	captureLogs(t)
	t.Run("9 redirects", func(t *testing.T) {
		srv, hits := countdownServer(t)
		trustTLS(t, srv)
		store := NewStore()
		if err := Update(store, []string{srv.URL + "/r/9"}, t.TempDir(), DownloadFirst); err != nil {
			t.Fatalf("Update = %v, want nil: 9 redirects are in the limit", err)
		}
		if n := hits.Load(); n != 10 {
			t.Errorf("server got %d requests, want 10", n)
		}
		if !store.IsBlocked("end.example.com") {
			t.Error("the list at the end of the chain is not in use")
		}
	})
	t.Run("10 redirects", func(t *testing.T) {
		srv, hits := countdownServer(t)
		trustTLS(t, srv)
		store := NewStore()
		if err := Update(store, []string{srv.URL + "/r/10"}, t.TempDir(), DownloadFirst); err == nil {
			t.Fatal("Update = nil, want an error: 10 redirects are over the limit")
		}
		if n := hits.Load(); n != 10 {
			t.Errorf("server got %d requests, want 10", n)
		}
		if store.IsBlocked("end.example.com") {
			t.Error("the list past the redirect limit is in use")
		}
	})
	t.Run("loop", func(t *testing.T) {
		var srv *httptest.Server
		srv, hits := redirectServer(t, func() string { return srv.URL + "/again" })
		trustTLS(t, srv)
		if err := Update(NewStore(), []string{srv.URL}, t.TempDir(), DownloadFirst); err == nil {
			t.Fatal("Update = nil, want an error: a redirect loop never ends")
		}
		if n := hits.Load(); n != 10 {
			t.Errorf("server got %d requests, want 10", n)
		}
	})
}
