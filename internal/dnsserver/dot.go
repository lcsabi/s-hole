package dnsserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// maxDoTConns caps concurrent DNS-over-TLS connections. A DoT client (an
// Android phone in Private DNS mode, for example) holds its connection open
// between queries, so without a cap a flood of idle TLS connections could
// exhaust file descriptors. A home LAN needs one or two connections per
// device, so 256 leaves wide headroom. It is a constant, not a config knob:
// there is no evidence yet that anyone needs to tune it.
const maxDoTConns = 256

// certExpiryWarnWindow is how far ahead of NotAfter the DoT certificate
// starts to log an expiry warning. ACME certificates renew about 30 days
// before they expire, so a certificate inside 14 days usually means renewal
// failed or the new files were not reloaded.
const certExpiryWarnWindow = 14 * 24 * time.Hour

// CertReloader holds the certificate the DoT listener presents and swaps it
// on Reload. The TLS handshake reads it through GetCertificate from an atomic
// pointer, so a reload takes no lock on the handshake path. New connections
// get the new certificate; connections already open keep the certificate
// they negotiated until the client reconnects.
type CertReloader struct {
	certFile string
	keyFile  string
	current  atomic.Pointer[tls.Certificate]

	// failures counts reloads that did not load (the listener kept the
	// previous certificate). It feeds /metrics.
	failures atomic.Uint64

	// mu guards the last-reload record that Status reports. It is off the
	// handshake path, which reads only current.
	mu         sync.Mutex
	lastReload time.Time
	lastErr    string
}

// Certificate states that Status reports, most severe first.
const (
	CertExpired      = "expired"       // NotAfter has passed; clients reject the certificate
	CertReloadFailed = "reload_failed" // the last reload did not load; the old certificate is still served
	CertExpiring     = "expiring"      // expires within certExpiryWarnWindow
	CertOK           = "ok"
)

// CertStatus is a point-in-time view of the DoT certificate for the admin API
// and /metrics.
type CertStatus struct {
	Names           []string  // DNS names and IP addresses in the certificate SAN
	NotAfter        time.Time // expiry of the certificate being served
	State           string    // one of the Cert* constants
	LastReload      time.Time // time of the last load attempt, startup included
	LastReloadError string    // "" when the last attempt succeeded
	ReloadFailures  uint64    // cumulative failed reloads
}

// NewCertReloader loads the PEM certificate and private key once. It fails if
// either file is unreadable or the key does not match the certificate.
func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	r := &CertReloader{certFile: certFile, keyFile: keyFile}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload reads the certificate and key files again and swaps them in. On
// failure it returns the error and keeps the current certificate, so a
// half-copied or mistyped file never takes the listener down.
func (r *CertReloader) Reload() error {
	err := r.load()
	r.mu.Lock()
	r.lastReload = time.Now()
	r.lastErr = ""
	if err != nil {
		r.lastErr = err.Error()
	}
	r.mu.Unlock()
	if err != nil && r.current.Load() != nil {
		// Count only failures that left an old certificate in service; a
		// failure in NewCertReloader stops startup instead.
		r.failures.Add(1)
	}
	return err
}

func (r *CertReloader) load() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("loading DoT certificate: %w", err)
	}
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("parsing DoT certificate: %w", err)
		}
		cert.Leaf = leaf
	}
	r.current.Store(&cert)
	return nil
}

// Status reports the certificate being served and the result of the last
// reload, with the state evaluated at now.
func (r *CertReloader) Status(now time.Time) CertStatus {
	leaf := r.current.Load().Leaf
	names := append([]string(nil), leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	r.mu.Lock()
	st := CertStatus{
		Names:           names,
		NotAfter:        leaf.NotAfter,
		LastReload:      r.lastReload,
		LastReloadError: r.lastErr,
		ReloadFailures:  r.failures.Load(),
	}
	r.mu.Unlock()
	st.State = certState(st.NotAfter, st.LastReloadError != "", now)
	return st
}

// certState picks the most severe state: an expired certificate outranks a
// failed reload (clients already reject it), and a failed reload outranks an
// upcoming expiry (the renewal the operator attempted did not take).
func certState(notAfter time.Time, reloadFailed bool, now time.Time) string {
	switch {
	case !now.Before(notAfter):
		return CertExpired
	case reloadFailed:
		return CertReloadFailed
	case notAfter.Sub(now) < certExpiryWarnWindow:
		return CertExpiring
	default:
		return CertOK
	}
}

// GetCertificate returns the current certificate. It is the tls.Config
// callback for the DoT listener.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.current.Load(), nil
}

// NotAfter returns the expiry time of the current certificate.
func (r *CertReloader) NotAfter() time.Time {
	return r.current.Load().Leaf.NotAfter
}

// ExpiryWarning returns a warning message when the current certificate has
// expired or expires within certExpiryWarnWindow of now, and "" otherwise.
func (r *CertReloader) ExpiryWarning(now time.Time) string {
	return expiryWarning(r.NotAfter(), now)
}

func expiryWarning(notAfter, now time.Time) string {
	switch certState(notAfter, false, now) {
	case CertExpired:
		return "the DoT certificate has expired; clients will reject it"
	case CertExpiring:
		return "the DoT certificate expires within 14 days; renew it and reload"
	default:
		return ""
	}
}

// ListenDoT binds addr for DNS over TLS (RFC 7858) and returns a listener that
// completes the TLS handshake with the certificate from certs. It binds
// synchronously, so a port conflict or a bad address surfaces at startup
// instead of inside a serving goroutine. The listener caps concurrent
// connections at maxDoTConns and accepts TLS 1.2 or later.
func ListenDoT(addr string, certs *CertReloader) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dot: listen on %s: %w", addr, err)
	}
	tlsCfg := &tls.Config{
		GetCertificate: certs.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
	return tls.NewListener(newLimitListener(ln, maxDoTConns), tlsCfg), nil
}

// limitListener caps the number of open connections. Accept waits for a
// free slot, and each connection frees its slot when it closes. Close also
// wakes an Accept that is waiting for a slot, so shutdown cannot hang on a
// full listener.
type limitListener struct {
	net.Listener
	slots     chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newLimitListener(l net.Listener, n int) *limitListener {
	return &limitListener{
		Listener: l,
		slots:    make(chan struct{}, n),
		done:     make(chan struct{}),
	}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.slots }}, nil
}

func (l *limitListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// limitConn frees its listener slot exactly once, however many times Close is
// called. It embeds net.Conn, so RemoteAddr still returns the *net.TCPAddr
// that clientAddr expects, including under the tls.Conn that wraps it.
type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// isClosedListener reports whether err means the listener was closed, which
// the DoT serve loop treats as a clean stop.
func isClosedListener(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
