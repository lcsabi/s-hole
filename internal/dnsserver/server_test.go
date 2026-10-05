package dnsserver

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// answerHandler replies to every A query with 9.9.9.9, so a test can tell a
// real answer from an error.
var answerHandler = dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.IPv4(9, 9, 9, 9),
		},
	}
	_ = w.WriteMsg(resp)
})

// pickFreePort binds UDP and TCP on the same random loopback port through
// Listen and returns the address with both sockets still open. The sockets
// are never released and rebound, so no other process can take the port in
// between.
//
// The port is probed at random rather than taken from the OS allocator
// (b/029): Windows reserves large contiguous port ranges per protocol
// (Hyper-V/WSL dynamic exclusions; `netsh int ipv4 show
// excludedportrange`), and the sequential ephemeral allocator of one
// protocol routinely parks inside a block excluded for the other; a port
// that `:0` hands out for TCP can be UDP-forbidden and vice versa, and
// sequential retries stay stuck in the same block. Random probes in a range
// below the dynamic-reservation area (49152+) escape immediately.
//
// Cleanup closes both sockets. A second Close after Shutdown is harmless.
func pickFreePort(t *testing.T) (addr string, pc net.PacketConn, ln net.Listener) {
	t.Helper()
	var lastErr error
	for range 20 {
		addr = fmt.Sprintf("127.0.0.1:%d", 20000+rand.IntN(28000))
		pc, ln, err := Listen(addr)
		if err != nil {
			lastErr = err // in use or excluded for one transport; probe again
			continue
		}
		t.Cleanup(func() {
			_ = pc.Close()
			_ = ln.Close()
		})
		return addr, pc, ln
	}
	t.Fatalf("no port bindable for both UDP and TCP: %v", lastErr)
	return "", nil, nil
}

// waitForUDP polls a UDP DNS query against addr until we get any reply
// or the deadline expires. Used to confirm the listener is up before
// the real test query runs.
func waitForUDP(addr string, dl time.Duration) error {
	c := &dns.Client{Timeout: 100 * time.Millisecond}
	req := new(dns.Msg)
	req.SetQuestion("probe.", dns.TypeA)
	deadline := time.Now().Add(dl)
	for time.Now().Before(deadline) {
		if _, _, err := c.Exchange(req, addr); err == nil {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return &timeoutErr{}
}

type timeoutErr struct{}

func (timeoutErr) Error() string { return "udp probe timed out" }

// assertPortsFree fails the test when UDP or TCP on addr cannot be bound
// again, which means a socket is still open.
func assertPortsFree(t *testing.T, addr string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Errorf("UDP %s still bound: %v", addr, err)
	} else {
		_ = pc.Close()
	}
	assertTCPFree(t, addr)
}

func assertTCPFree(t *testing.T, addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Errorf("TCP %s still bound: %v", addr, err)
		return
	}
	_ = ln.Close()
}

// waitStart waits for the Start result and fails the test when Start does
// not return in time.
func waitStart(t *testing.T, startErr <-chan error) error {
	t.Helper()
	select {
	case err := <-startErr:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Shutdown")
		return nil
	}
}

func TestListen_BindsUDPAndTCPOnSamePort(t *testing.T) {
	addr, pc, ln := pickFreePort(t)
	if got := pc.LocalAddr().String(); got != addr {
		t.Errorf("UDP bound on %s, want %s", got, addr)
	}
	if got := ln.Addr().String(); got != addr {
		t.Errorf("TCP bound on %s, want %s", got, addr)
	}
	// Both sockets are live: a second bind on either transport fails.
	if other, err := net.ListenPacket("udp", addr); err == nil {
		_ = other.Close()
		t.Error("second UDP bind succeeded, want Listen to hold the UDP port")
	}
	if other, err := net.Listen("tcp", addr); err == nil {
		_ = other.Close()
		t.Error("second TCP bind succeeded, want Listen to hold the TCP port")
	}
}

func TestListen_UDPBindFailureReturnsError(t *testing.T) {
	busy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	addr := busy.LocalAddr().String()

	pc, ln, err := Listen(addr)
	if err == nil {
		_ = pc.Close()
		_ = ln.Close()
		t.Fatal("Listen on a busy UDP port returned nil error")
	}
	if !strings.Contains(err.Error(), "udp") || !strings.Contains(err.Error(), addr) {
		t.Errorf("error = %q, want it to name udp and %s", err, addr)
	}
	if pc != nil || ln != nil {
		t.Errorf("Listen returned sockets with an error: pc=%v ln=%v", pc, ln)
	}
}

// TestListen_TCPBindFailureReleasesUDP verifies that when the TCP bind fails,
// Listen closes the UDP socket it already opened, so the port is free again.
func TestListen_TCPBindFailureReleasesUDP(t *testing.T) {
	for range 20 {
		addr := fmt.Sprintf("127.0.0.1:%d", 20000+rand.IntN(28000))
		busy, err := net.Listen("tcp", addr)
		if err != nil {
			continue // in use or excluded for TCP; probe again
		}
		pc, ln, err := Listen(addr)
		if err == nil {
			_ = pc.Close()
			_ = ln.Close()
			_ = busy.Close()
			t.Fatal("Listen on a busy TCP port returned nil error")
		}
		if strings.Contains(err.Error(), "udp") {
			_ = busy.Close()
			continue // UDP is in use or excluded on this port; probe again (b/029)
		}
		if !strings.Contains(err.Error(), "tcp") || !strings.Contains(err.Error(), addr) {
			t.Errorf("error = %q, want it to name tcp and %s", err, addr)
		}
		udp, err := net.ListenPacket("udp", addr)
		if err != nil {
			t.Errorf("UDP port still bound after the TCP bind failed: %v", err)
		} else {
			_ = udp.Close()
		}
		_ = busy.Close()
		return
	}
	t.Skip("found no port with TCP free and UDP free")
}

func TestNewServer_UsesGivenSockets(t *testing.T) {
	_, pc, ln := pickFreePort(t)
	h := &Handler{}
	s := NewServer(pc, ln, h)
	if s.udp == nil || s.tcp == nil {
		t.Fatal("NewServer left a nil transport")
	}
	if s.udp.PacketConn != pc || s.udp.Net != "udp" {
		t.Errorf("udp server = %+v, want udp on the given PacketConn", s.udp)
	}
	if s.tcp.Listener != ln || s.tcp.Net != "tcp" {
		t.Errorf("tcp server = %+v, want tcp on the given Listener", s.tcp)
	}
	if s.udp.Handler != dns.Handler(h) || s.tcp.Handler != dns.Handler(h) {
		t.Error("UDP and TCP servers do not use the given handler")
	}
	if s.dot != nil || len(s.servers()) != 2 {
		t.Errorf("servers() = %d entries with dot=%v, want 2 and no DoT", len(s.servers()), s.dot)
	}
}

// TestServer_ShutdownBeforeStartReleasesPorts pins b/063: a Shutdown that
// runs before Start closes both sockets, and a later Start returns nil at
// once instead of serving forever.
func TestServer_ShutdownBeforeStartReleasesPorts(t *testing.T) {
	addr, pc, ln := pickFreePort(t)
	s := NewServer(pc, ln, answerHandler)
	s.Shutdown()
	assertPortsFree(t, addr)

	startErr := make(chan error, 1)
	go func() { startErr <- s.Start() }()
	if err := waitStart(t, startErr); err != nil {
		t.Errorf("Start after Shutdown = %v, want nil", err)
	}
}

// TestServer_ShutdownRacesStart pins b/063: Shutdown runs at the same time as
// Start, many times over. Every round must end with Start returning nil and
// every port released. Before the fix, a server that had not started when
// Shutdown ran bound its socket later and served until the process exited.
// goleak (TestMain) catches a listener goroutine that stays alive.
func TestServer_ShutdownRacesStart(t *testing.T) {
	certFile, keyFile, _ := writeTestCert(t, t.TempDir(), 1, time.Now().Add(time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	for i := range 30 {
		addr, pc, ln := pickFreePort(t)
		dotLn, err := ListenDoT("127.0.0.1:0", certs)
		if err != nil {
			t.Fatalf("ListenDoT: %v", err)
		}
		dotAddr := dotLn.Addr().String()
		s := NewServer(pc, ln, answerHandler)
		s.EnableDoT(dotLn)

		startErr := make(chan error, 1)
		go func() { startErr <- s.Start() }()
		s.Shutdown()

		if err := waitStart(t, startErr); err != nil {
			t.Errorf("round %d: Start = %v, want nil after Shutdown", i, err)
		}
		assertPortsFree(t, addr)
		assertTCPFree(t, dotAddr)
		if t.Failed() {
			return
		}
	}
}

// TestServer_StartShutdownLifecycle runs the real Start/Shutdown path on
// pre-bound sockets: it sends a real query over UDP and over TCP to confirm
// the handler is wired on both, then checks that Shutdown makes Start return
// nil and releases both ports.
func TestServer_StartShutdownLifecycle(t *testing.T) {
	addr, pc, ln := pickFreePort(t)
	srv := NewServer(pc, ln, answerHandler)
	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start() }()

	// On failure, surface what Start returned; a serve error looks identical
	// to a probe timeout otherwise (this masked b/029).
	if err := waitForUDP(addr, 2*time.Second); err != nil {
		srv.Shutdown()
		t.Fatalf("server never accepted a query: %v (Start returned: %v)", err, waitStart(t, startErr))
	}

	for _, network := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: network, Timeout: 2 * time.Second}
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		resp, _, err := c.Exchange(req, addr)
		if err != nil {
			t.Errorf("%s exchange: %v", network, err)
			continue
		}
		if len(resp.Answer) != 1 {
			t.Errorf("%s answer = %v, want one A record", network, resp.Answer)
		}
	}

	srv.Shutdown()
	if err := waitStart(t, startErr); err != nil {
		t.Errorf("Start = %v after Shutdown, want nil", err)
	}
	assertPortsFree(t, addr)
}

// errListenerBroken is a runtime failure that is neither temporary nor
// net.ErrClosed, so the dns.Server stops and reports it.
var errListenerBroken = errors.New("listener broken")

// failingPacketConn fails every read with errListenerBroken. Close still
// closes the real socket, so Shutdown can release the port.
type failingPacketConn struct {
	net.PacketConn
}

func (failingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errListenerBroken
}

// TestServer_StartReturnsRuntimeListenerError verifies that when one
// listener fails at runtime, Start returns that error with the "dns: "
// prefix, the TCP and DoT listeners keep serving, and Shutdown then stops
// them with no goroutine left behind (goleak in TestMain).
func TestServer_StartReturnsRuntimeListenerError(t *testing.T) {
	addr, pc, ln := pickFreePort(t)
	certFile, keyFile, pool := writeTestCert(t, t.TempDir(), 1, time.Now().Add(time.Hour))
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	dotLn, err := ListenDoT("127.0.0.1:0", certs)
	if err != nil {
		t.Fatalf("ListenDoT: %v", err)
	}
	dotAddr := dotLn.Addr().String()

	s := NewServer(failingPacketConn{pc}, ln, answerHandler)
	s.EnableDoT(dotLn)

	startErr := make(chan error, 1)
	go func() { startErr <- s.Start() }()
	select {
	case err := <-startErr:
		if !errors.Is(err, errListenerBroken) || !strings.HasPrefix(err.Error(), "dns: ") {
			t.Errorf("Start = %v, want the listener error with a \"dns: \" prefix", err)
		}
	case <-time.After(5 * time.Second):
		s.Shutdown()
		t.Fatal("Start did not return after the UDP listener failed")
	}

	// The other listeners still answer until Shutdown.
	c := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	if _, _, err := c.Exchange(buildReq("example.com"), addr); err != nil {
		t.Errorf("TCP exchange after the UDP failure: %v", err)
	}
	if _, _, err := dotClient(pool).Exchange(buildReq("example.com"), dotAddr); err != nil {
		t.Errorf("DoT exchange after the UDP failure: %v", err)
	}

	s.Shutdown()
	assertPortsFree(t, addr)
	assertTCPFree(t, dotAddr)
}
