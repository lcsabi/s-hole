package dnsserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/stats"
)

// testCertName is the SAN the test certificates carry; clients verify it.
const testCertName = "dns.test"

// writeTestCert writes a self-signed ECDSA certificate for testCertName and
// 127.0.0.1, with the given serial and expiry, plus its private key, to
// cert.pem and key.pem in dir. It returns the two paths and a pool that
// trusts the certificate, so a test client can verify the handshake.
func writeTestCert(t *testing.T, dir string, serial int64, notAfter time.Time) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: testCertName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		DNSNames:              []string{testCertName},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	writePEM(t, certFile, "CERTIFICATE", der)
	writePEM(t, keyFile, "PRIVATE KEY", keyDER)

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(leaf)
	return certFile, keyFile, pool
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// startDoTServer runs a full Server (UDP, TCP, and DoT) whose handler blocks
// ads.example.com, with the DoT listener on a free loopback port. It returns
// the DoT address and the stats counter. Cleanup shuts the server down and
// checks that Start returned cleanly.
func startDoTServer(t *testing.T, certs *CertReloader) (dotAddr string, counter *stats.Counter) {
	t.Helper()
	addr, err := pickFreePort(t)
	if err != nil {
		t.Fatalf("pickFreePort: %v", err)
	}
	dotLn, err := ListenDoT("127.0.0.1:0", certs)
	if err != nil {
		t.Fatalf("ListenDoT: %v", err)
	}

	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})
	counter = stats.New()
	h := NewHandler(store, counter, nil, nullLogger{}, "zero", 60, nil, false, "raw")

	srv := NewServer(addr, h)
	srv.EnableDoT(dotLn)
	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start() }()
	if err := waitForUDP(addr, 3*time.Second); err != nil {
		t.Fatalf("server did not come up on %s", addr)
	}

	t.Cleanup(func() {
		srv.Shutdown()
		select {
		case err := <-startErr:
			if err != nil {
				t.Errorf("Start returned %v after Shutdown, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Start did not return after Shutdown")
		}
	})
	return dotLn.Addr().String(), counter
}

func dotClient(pool *x509.CertPool) *dns.Client {
	return &dns.Client{
		Net:       "tcp-tls",
		Timeout:   3 * time.Second,
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: testCertName, MinVersion: tls.VersionTLS12},
	}
}

func TestDoT_ServesQueryThroughSharedHandler(t *testing.T) {
	// A blocked query over DoT gets the same sinkhole answer as plain DNS,
	// and stats record the loopback client, which proves clientAddr and the
	// query_privacy mask read the right address under tls.Conn.
	certFile, keyFile, pool := writeTestCert(t, t.TempDir(), 1, time.Now().Add(90*24*time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	dotAddr, counter := startDoTServer(t, certs)

	resp, _, err := dotClient(pool).Exchange(buildReq("ads.example.com"), dotAddr)
	if err != nil {
		t.Fatalf("DoT exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || !a.A.Equal(net.IPv4zero) {
		t.Errorf("answer = %v, want the 0.0.0.0 sinkhole", resp.Answer[0])
	}
	clients := counter.Snapshot(10).TopClients
	if len(clients) != 1 || clients[0].Name != "127.0.0.1" {
		t.Errorf("top clients = %+v, want one entry for 127.0.0.1", clients)
	}
}

func TestDoT_UntrustedClientFailsHandshake(t *testing.T) {
	// A client that does not trust the issuer must not get an answer: this is
	// the property that makes DoT safe against an impostor resolver.
	certFile, keyFile, _ := writeTestCert(t, t.TempDir(), 1, time.Now().Add(90*24*time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	dotAddr, _ := startDoTServer(t, certs)

	_, _, err = dotClient(x509.NewCertPool()).Exchange(buildReq("ads.example.com"), dotAddr)
	if err == nil {
		t.Fatal("exchange succeeded with an untrusted certificate, want a handshake error")
	}
}

// peerSerial completes a TLS handshake with the DoT listener and returns the
// serial number of the certificate the server presented.
func peerSerial(t *testing.T, addr string, pool *x509.CertPool) int64 {
	t.Helper()
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{RootCAs: pool, ServerName: testCertName, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

func TestCertReloader_ReloadServesNewCertificate(t *testing.T) {
	// After Reload, a new connection gets the replacement certificate without
	// a restart. This is how an operator renews: replace the files, reload.
	dir := t.TempDir()
	certFile, keyFile, pool1 := writeTestCert(t, dir, 1, time.Now().Add(90*24*time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	dotAddr, _ := startDoTServer(t, certs)

	if got := peerSerial(t, dotAddr, pool1); got != 1 {
		t.Fatalf("serial before reload = %d, want 1", got)
	}

	// Overwrite the same two paths with a new pair, as a renewal would.
	_, _, pool2 := writeTestCert(t, dir, 2, time.Now().Add(90*24*time.Hour))
	if err := certs.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := peerSerial(t, dotAddr, pool2); got != 2 {
		t.Errorf("serial after reload = %d, want 2", got)
	}
}

func TestCertReloader_FailedReloadKeepsCurrent(t *testing.T) {
	// A half-copied or garbage file must not take the listener down: Reload
	// reports the error and the current certificate stays in place.
	certFile, keyFile, _ := writeTestCert(t, t.TempDir(), 7, time.Now().Add(90*24*time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := certs.Reload(); err == nil {
		t.Fatal("Reload of a garbage file returned nil, want an error")
	}
	cur, _ := certs.GetCertificate(nil)
	if cur == nil || cur.Leaf.SerialNumber.Int64() != 7 {
		t.Errorf("current certificate after failed reload = %v, want serial 7", cur)
	}
}

func TestNewCertReloader_RejectsBadPairs(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	certA, _, _ := writeTestCert(t, dirA, 1, time.Now().Add(time.Hour))
	_, keyB, _ := writeTestCert(t, dirB, 2, time.Now().Add(time.Hour))

	cases := map[string][2]string{
		"missing files":  {filepath.Join(dirA, "nope.pem"), filepath.Join(dirA, "nope.key")},
		"mismatched key": {certA, keyB},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewCertReloader(files[0], files[1]); err == nil {
				t.Error("NewCertReloader returned nil error, want a failure")
			}
		})
	}
}

func TestExpiryWarning(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		notAfter time.Time
		want     string // substring; "" means no warning
	}{
		{"valid for months", now.Add(60 * 24 * time.Hour), ""},
		{"inside 14 days", now.Add(3 * 24 * time.Hour), "expires within 14 days"},
		{"expired", now.Add(-time.Minute), "has expired"},
		{"expires exactly now", now, "has expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := expiryWarning(tc.notAfter, now)
			if tc.want == "" {
				if got != "" {
					t.Errorf("warning = %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("warning = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

func TestCertReloader_ExpiryWarningUsesLeaf(t *testing.T) {
	certFile, keyFile, _ := writeTestCert(t, t.TempDir(), 1, time.Now().Add(2*24*time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	if msg := certs.ExpiryWarning(time.Now()); msg == "" {
		t.Error("certificate expiring in 2 days produced no warning")
	}
}

func TestListenDoT_BindErrorIsReturned(t *testing.T) {
	// ListenDoT binds synchronously, so a port conflict surfaces to main as
	// an error (which main treats as fatal) instead of inside a goroutine.
	certFile, keyFile, _ := writeTestCert(t, t.TempDir(), 1, time.Now().Add(time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if _, err := ListenDoT(busy.Addr().String(), certs); err == nil {
		t.Error("ListenDoT on a busy port returned nil error")
	}
}

func TestServer_DoTShutdownBeforeStartClosesListener(t *testing.T) {
	// The DoT listener is bound before Start. If Shutdown runs first, the
	// port must still be released; dns.Server.Shutdown alone closes the
	// listener only of a started server.
	certFile, keyFile, _ := writeTestCert(t, t.TempDir(), 1, time.Now().Add(time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	ln, err := ListenDoT("127.0.0.1:0", certs)
	if err != nil {
		t.Fatalf("ListenDoT: %v", err)
	}
	addr := ln.Addr().String()

	h := dns.HandlerFunc(func(w dns.ResponseWriter, _ *dns.Msg) {})
	s := NewServer("127.0.0.1:5302", h)
	s.EnableDoT(ln)
	s.Shutdown()

	rebind, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("DoT port still bound after Shutdown: %v", err)
	}
	rebind.Close()
}

func TestServer_EnableDoTSharesHandler(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// A pointer handler, because a dns.HandlerFunc is not comparable.
	h := &Handler{}
	s := NewServer("127.0.0.1:5303", h)
	s.EnableDoT(ln)
	if s.dot == nil || s.dot.Net != "tcp-tls" || s.dot.Listener != ln {
		t.Fatalf("dot server = %+v, want tcp-tls on the given listener", s.dot)
	}
	if s.dot.Handler != dns.Handler(h) || s.dot.Handler != s.udp.Handler {
		t.Error("DoT server does not share the plain listeners' handler")
	}
	if len(s.servers()) != 3 {
		t.Errorf("servers() = %d entries, want 3", len(s.servers()))
	}
}

func TestServer_StartDrainsEveryListenerOnError(t *testing.T) {
	// With the UDP port taken, Start fails fast. The TCP and DoT goroutines
	// are still running; Start must drain all of their slots once Shutdown
	// stops them, or goleak (TestMain) fails the package.
	addr, err := pickFreePort(t)
	if err != nil {
		t.Fatalf("pickFreePort: %v", err)
	}
	busy, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	certFile, keyFile, _ := writeTestCert(t, t.TempDir(), 1, time.Now().Add(time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	ln, err := ListenDoT("127.0.0.1:0", certs)
	if err != nil {
		t.Fatalf("ListenDoT: %v", err)
	}

	h := dns.HandlerFunc(func(w dns.ResponseWriter, _ *dns.Msg) {})
	s := NewServer(addr, h)
	s.EnableDoT(ln)

	startErr := make(chan error, 1)
	go func() { startErr <- s.Start() }()
	select {
	case err := <-startErr:
		if err == nil || !strings.Contains(err.Error(), "dns:") {
			t.Errorf("Start = %v, want a dns: bind error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after the UDP bind failed")
	}
	// Give the TCP listener a moment to bind before stopping it, so Shutdown
	// finds it started; either way every goroutine must exit.
	time.Sleep(50 * time.Millisecond)
	s.Shutdown()
}

func TestLimitListener_CapsAndReleases(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newLimitListener(inner, 1)
	defer l.Close()

	dial := func() net.Conn {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	dial()
	dial()

	first, err := l.Accept()
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()

	select {
	case <-accepted:
		t.Fatal("second Accept returned while the only slot was held")
	case <-time.After(100 * time.Millisecond):
	}

	// Closing twice must free exactly one slot.
	first.Close()
	first.Close()

	select {
	case c, ok := <-accepted:
		if !ok {
			t.Fatal("second Accept failed after a slot was freed")
		}
		defer c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("second Accept did not proceed after the first conn closed")
	}
	if n := len(l.slots); n != 1 {
		t.Errorf("slots in use = %d, want 1 (double Close released twice?)", n)
	}
}

func TestLimitListener_CloseUnblocksWaitingAccept(t *testing.T) {
	// With the cap full, Accept waits for a slot. Close must wake it with
	// net.ErrClosed, or Shutdown would hang on a saturated DoT listener.
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newLimitListener(inner, 1)
	c, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	held, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	result := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		result <- err
	}()
	time.Sleep(50 * time.Millisecond)
	l.Close()

	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("waiting Accept returned %v, want net.ErrClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock the waiting Accept")
	}
}

func TestCertReloader_ConcurrentReloadAndHandshakes(t *testing.T) {
	// Reload swaps the certificate pointer while handshakes read it. Under
	// -race this pins the lock-free GetCertificate path.
	certFile, keyFile, pool := writeTestCert(t, t.TempDir(), 1, time.Now().Add(90*24*time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	dotAddr, _ := startDoTServer(t, certs)

	done := make(chan error, 1)
	go func() {
		cfg := &tls.Config{RootCAs: pool, ServerName: testCertName, MinVersion: tls.VersionTLS12}
		d := &net.Dialer{Timeout: 3 * time.Second}
		for range 20 {
			conn, err := tls.DialWithDialer(d, "tcp", dotAddr, cfg)
			if err != nil {
				done <- err
				return
			}
			conn.Close()
		}
		done <- nil
	}()
	for range 20 {
		if err := certs.Reload(); err != nil {
			t.Fatalf("Reload: %v", err)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("handshake during reloads: %v", err)
	}
}

func TestCertReloader_StatusTracksReloads(t *testing.T) {
	// Status is what the dashboard badge and /metrics report: the names, the
	// state, and the last reload result. A failed reload shows reload_failed
	// and counts once; the next good reload clears the error but keeps the
	// cumulative count.
	certFile, keyFile, _ := writeTestCert(t, t.TempDir(), 1, time.Now().Add(90*24*time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	st := certs.Status(time.Now())
	if st.State != CertOK || st.ReloadFailures != 0 || st.LastReloadError != "" || st.LastReload.IsZero() {
		t.Fatalf("initial status = %+v, want ok with a recorded load and no failures", st)
	}
	if strings.Join(st.Names, ",") != testCertName+",127.0.0.1" {
		t.Errorf("names = %v, want [%s 127.0.0.1]", st.Names, testCertName)
	}

	good, _ := os.ReadFile(certFile)
	if err := os.WriteFile(certFile, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = certs.Reload()
	st = certs.Status(time.Now())
	if st.State != CertReloadFailed || st.ReloadFailures != 1 || st.LastReloadError == "" {
		t.Errorf("after a failed reload: %+v, want reload_failed, 1 failure, an error", st)
	}

	if err := os.WriteFile(certFile, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := certs.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	st = certs.Status(time.Now())
	if st.State != CertOK || st.ReloadFailures != 1 || st.LastReloadError != "" {
		t.Errorf("after a good reload: %+v, want ok, the count kept at 1, no error", st)
	}
}

func TestCertState_Precedence(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		notAfter time.Time
		failed   bool
		want     string
	}{
		{"healthy", now.Add(60 * 24 * time.Hour), false, CertOK},
		{"expiring", now.Add(5 * 24 * time.Hour), false, CertExpiring},
		{"failed reload outranks expiring", now.Add(5 * 24 * time.Hour), true, CertReloadFailed},
		{"failed reload on a healthy cert", now.Add(60 * 24 * time.Hour), true, CertReloadFailed},
		{"expired outranks failed reload", now.Add(-time.Hour), true, CertExpired},
		{"expired", now.Add(-time.Hour), false, CertExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := certState(tc.notAfter, tc.failed, now); got != tc.want {
				t.Errorf("certState = %q, want %q", got, tc.want)
			}
		})
	}
}
