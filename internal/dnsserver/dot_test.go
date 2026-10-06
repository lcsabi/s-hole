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
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
	addr, pc, ln := pickFreePort(t)
	dotLn, err := ListenDoT("127.0.0.1:0", certs)
	if err != nil {
		t.Fatalf("ListenDoT: %v", err)
	}

	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})
	counter = stats.New()
	h := NewHandler(store, counter, nil, nullLogger{}, "zero", 60, nil, false, "full")

	srv := NewServer(pc, ln, h)
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
	// the property that makes DoT safe against an impostor resolver for a
	// client that verifies the certificate.
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
	// The failure must be the certificate check. Any other error (a listener
	// that does not speak TLS, a closed port) would also fail the exchange,
	// but it would not prove the client rejected the issuer.
	var unknown x509.UnknownAuthorityError
	var verify *tls.CertificateVerificationError
	if !errors.As(err, &unknown) && !errors.As(err, &verify) {
		t.Errorf("exchange error = %v (%T), want a certificate verification failure", err, err)
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
	// The messages are exact: TROUBLESHOOTING.md and log searches quote them.
	// The expiring hint states the window in days from certExpiryWarnWindow.
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	windowDays := fmt.Sprintf("%d days", int(certExpiryWarnWindow/(24*time.Hour)))
	cases := []struct {
		name     string
		notAfter time.Time
		wantMsg  string // "" means no warning
		wantHint string // substring of the hint
	}{
		{"valid for months", now.Add(60 * 24 * time.Hour), "", ""},
		{"exactly the window away", now.Add(certExpiryWarnWindow), "", ""},
		{"just inside the window", now.Add(certExpiryWarnWindow - time.Second), "DoT certificate expires soon", windowDays},
		{"inside the window", now.Add(3 * 24 * time.Hour), "DoT certificate expires soon", windowDays},
		{"one second left", now.Add(time.Second), "DoT certificate expires soon", windowDays},
		{"expires exactly now", now, "DoT certificate expired", ""},
		{"expired", now.Add(-time.Minute), "DoT certificate expired", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, hint := expiryWarning(tc.notAfter, now)
			if msg != tc.wantMsg {
				t.Errorf("msg = %q, want %q", msg, tc.wantMsg)
			}
			if tc.wantMsg == "" {
				if hint != "" {
					t.Errorf("hint = %q, want empty", hint)
				}
				return
			}
			if hint == "" {
				t.Error("hint is empty")
			}
			if !strings.Contains(hint, tc.wantHint) {
				t.Errorf("hint = %q, want it to contain %q", hint, tc.wantHint)
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
	if msg, _ := certs.ExpiryWarning(time.Now()); msg == "" {
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
	// b/063: every listener is bound before Start. If Shutdown runs first,
	// every port must still be released; dns.Server.Shutdown alone closes a
	// socket only when the server has started. A later Start returns nil.
	certFile, keyFile, _ := writeTestCert(t, t.TempDir(), 1, time.Now().Add(time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	dotLn, err := ListenDoT("127.0.0.1:0", certs)
	if err != nil {
		t.Fatalf("ListenDoT: %v", err)
	}
	dotAddr := dotLn.Addr().String()
	addr, pc, ln := pickFreePort(t)

	h := dns.HandlerFunc(func(w dns.ResponseWriter, _ *dns.Msg) {})
	s := NewServer(pc, ln, h)
	s.EnableDoT(dotLn)
	s.Shutdown()

	assertTCPFree(t, dotAddr)
	assertPortsFree(t, addr)

	startErr := make(chan error, 1)
	go func() { startErr <- s.Start() }()
	if err := waitStart(t, startErr); err != nil {
		t.Errorf("Start after Shutdown = %v, want nil", err)
	}
}

func TestServer_EnableDoTSharesHandler(t *testing.T) {
	dotLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dotLn.Close()
	_, pc, ln := pickFreePort(t)
	// A pointer handler, because a dns.HandlerFunc is not comparable.
	h := &Handler{}
	s := NewServer(pc, ln, h)
	s.EnableDoT(dotLn)
	if s.dot == nil || s.dot.Net != "tcp-tls" || s.dot.Listener != dotLn {
		t.Fatalf("dot server = %+v, want tcp-tls on the given listener", s.dot)
	}
	if s.dot.Handler != dns.Handler(h) || s.dot.Handler != s.udp.Handler {
		t.Error("DoT server does not share the plain listeners' handler")
	}
	if len(s.servers()) != 3 {
		t.Errorf("servers() = %d entries, want 3", len(s.servers()))
	}
}

// startDoTOnly runs a Server with a DoT listener and returns the DoT address
// and a trusting pool. It is startDoTServer with a plain answer handler.
func startDoTOnly(t *testing.T) (string, *x509.CertPool) {
	t.Helper()
	certFile, keyFile, pool := writeTestCert(t, t.TempDir(), 1, time.Now().Add(90*24*time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	dotAddr, _ := startDoTServer(t, certs)
	return dotAddr, pool
}

// serverClosesWithin reads from conn until the server closes it or limit
// passes. It returns how long the close took, or fails the test when the
// connection is still open at limit.
func serverClosesWithin(t *testing.T, conn net.Conn, limit time.Duration) time.Duration {
	t.Helper()
	begin := time.Now()
	if err := conn.SetReadDeadline(begin.Add(limit)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	for {
		_, err := conn.Read(buf)
		if err == nil {
			continue // data (a TLS session ticket, for example); keep reading
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("server did not close the connection within %v", limit)
		}
		return time.Since(begin)
	}
}

func TestDoT_SilentTCPClientIsDisconnected(t *testing.T) {
	// A client that opens TCP and sends nothing (no TLS ClientHello) must not
	// hold one of the maxDoTConns slots. dotReadTimeout (2 s) covers the
	// handshake, so the server closes the connection well within 5 s.
	dotAddr, _ := startDoTOnly(t)
	conn, err := net.DialTimeout("tcp", dotAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	serverClosesWithin(t, conn, 5*time.Second)
}

func TestDoT_SilentAfterHandshakeIsDisconnected(t *testing.T) {
	// A client that completes the TLS handshake and then sends no query is
	// closed after the first-read bound (dotReadTimeout, 2 s).
	dotAddr, pool := startDoTOnly(t)
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", dotAddr, &tls.Config{RootCAs: pool, ServerName: testCertName, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	serverClosesWithin(t, conn, 5*time.Second)
}

func TestDoT_IdleConnectionClosedAfterIdleTimeout(t *testing.T) {
	// After one query, the connection stays open for later queries and is
	// closed after dotIdleTimeout (8 s). The lower bound shows the idle
	// timeout, not the 2 s first-read timeout, applies after a query.
	if testing.Short() {
		t.Skip("waits for the 8 s idle timeout")
	}
	dotAddr, pool := startDoTOnly(t)
	c := dotClient(pool)
	conn, err := c.Dial(dotAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, _, err := c.ExchangeWithConn(buildReq("example.com"), conn); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	took := serverClosesWithin(t, conn.Conn, 12*time.Second)
	if took < 4*time.Second {
		t.Errorf("idle connection closed after %v, want about %v", took, dotIdleTimeout)
	}
}

func TestDoT_RejectsTLS11(t *testing.T) {
	// The DoT listener accepts TLS 1.2 or later. The client allows TLS 1.0 and
	// 1.1 only, so the handshake must fail on the server's version check.
	dotAddr, pool := startDoTOnly(t)
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", dotAddr, &tls.Config{
		RootCAs:    pool,
		ServerName: testCertName,
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS11,
	})
	if err == nil {
		v := conn.ConnectionState().Version
		conn.Close()
		t.Fatalf("TLS 1.1 client completed a handshake (version %#x), want a failure", v)
	}
	if !strings.Contains(err.Error(), "protocol version") {
		t.Errorf("handshake error = %v, want a protocol version failure", err)
	}
}

func TestDoT_AcceptsTLS12(t *testing.T) {
	dotAddr, pool := startDoTOnly(t)
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", dotAddr, &tls.Config{
		RootCAs:    pool,
		ServerName: testCertName,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("TLS 1.2 handshake: %v", err)
	}
	defer conn.Close()
	if v := conn.ConnectionState().Version; v != tls.VersionTLS12 {
		t.Errorf("negotiated version %#x, want TLS 1.2", v)
	}
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
	// net.ErrClosed, or Shutdown would hang on a saturated DoT listener. The
	// test waits until the goroutine dump shows Accept blocked in its select,
	// and a counting inner listener proves the wait was for a slot: the inner
	// Accept is called only for the held connection.
	inner := newCountingListener()
	l := newLimitListener(inner, 1)
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
	waitForBlockedSlotWait(t)
	l.Close()

	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("waiting Accept returned %v, want net.ErrClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock the waiting Accept")
	}
	if n := inner.accepts.Load(); n != 1 {
		t.Errorf("inner Accept called %d times, want 1 (the second Accept must wait for a slot)", n)
	}
}

// countingListener hands out one end of a net.Pipe per Accept and counts the
// calls. After Close, Accept returns net.ErrClosed.
type countingListener struct {
	accepts atomic.Int32
	closed  chan struct{}
	once    sync.Once
}

func newCountingListener() *countingListener {
	return &countingListener{closed: make(chan struct{})}
}

func (c *countingListener) Accept() (net.Conn, error) {
	c.accepts.Add(1)
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	default:
	}
	a, b := net.Pipe()
	b.Close()
	return a, nil
}

func (c *countingListener) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *countingListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// waitForBlockedSlotWait polls the goroutine dump until a goroutine is
// blocked in the select inside (*limitListener).Accept. The poll is bounded.
func waitForBlockedSlotWait(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "[select") && strings.Contains(g, "(*limitListener).Accept") {
				return
			}
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Accept never blocked waiting for a slot")
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
