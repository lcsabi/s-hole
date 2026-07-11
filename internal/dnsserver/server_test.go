package dnsserver

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNewServer_FieldsSet(t *testing.T) {
	h := dns.HandlerFunc(func(w dns.ResponseWriter, _ *dns.Msg) {})
	s := NewServer("127.0.0.1:5300", h)
	if s.udp == nil || s.tcp == nil {
		t.Fatal("NewServer left a nil transport")
	}
	if s.udp.Addr != "127.0.0.1:5300" || s.udp.Net != "udp" {
		t.Errorf("udp config wrong: %+v", s.udp)
	}
	if s.tcp.Addr != "127.0.0.1:5300" || s.tcp.Net != "tcp" {
		t.Errorf("tcp config wrong: %+v", s.tcp)
	}
}

// TestServer_ShutdownBeforeStartIsSafe pins the never-started path:
// Shutdown must not panic when the listeners were never bound. miekg/dns
// returns "server not started" errors there, which Shutdown logs and
// swallows (CL 24) — this also covers those error-logging branches.
func TestServer_ShutdownBeforeStartIsSafe(t *testing.T) {
	h := dns.HandlerFunc(func(w dns.ResponseWriter, _ *dns.Msg) {})
	s := NewServer("127.0.0.1:5301", h)
	s.Shutdown() // reaching the next line without panicking is the assertion
}

// TestServer_StartShutdownLifecycle exercises the real Start/Shutdown
// code path: binds UDP and TCP on a free port, sends a real query to
// confirm the handler is wired, then triggers Shutdown and verifies the
// Start goroutine returns. This is the only test that runs an actual
// dns.Server (the upstream tests use a PacketConn-backed Server directly).
func TestServer_StartShutdownLifecycle(t *testing.T) {
	// Grab a free UDP port and a free TCP port; close the listeners so
	// dns.Server can bind them. Race window is tiny on a quiet test host;
	// retry once on EADDRINUSE if it bites in CI.
	addr, err := pickFreePort(t)
	if err != nil {
		t.Fatalf("pickFreePort: %v", err)
	}

	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
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
		w.WriteMsg(resp)
	})

	srv := NewServer(addr, h)
	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start() }()

	// Give the listeners a beat to come up.
	if err := waitForUDP(addr, 2*time.Second); err != nil {
		srv.Shutdown()
		t.Fatalf("server never accepted a query: %v", err)
	}

	// Send a real query through the wrapped Server.
	c := new(dns.Client)
	c.Timeout = 1 * time.Second
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	resp, _, err := c.Exchange(req, addr)
	if err != nil {
		srv.Shutdown()
		t.Fatalf("Exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Errorf("response Answer = %v, want one A record", resp.Answer)
	}

	srv.Shutdown()
	select {
	case err := <-startErr:
		// Start may return nil (clean shutdown) or a "use of closed network
		// connection"-style error depending on platform — both indicate the
		// listener actually stopped.
		_ = err
	case <-time.After(3 * time.Second):
		t.Fatal("Server.Start did not return after Shutdown")
	}
}

// pickFreePort returns "127.0.0.1:N" where N is a port that was free
// at call time. It binds and immediately releases. miekg/dns will
// rebind for both UDP and TCP at the same port; collisions across
// transports are rare on a loopback test host.
func pickFreePort(t *testing.T) (string, error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := l.Addr().String()
	l.Close()
	return addr, nil
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
