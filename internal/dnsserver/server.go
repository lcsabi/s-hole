package dnsserver

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// The DoT server's read deadlines. The first read on a connection, which also
// covers the TLS handshake, gets dotReadTimeout; each later read gets
// dotIdleTimeout. They bound how long a silent or idle client holds one of the
// maxDoTConns slots. These match the miekg/dns defaults, set here so that a
// change of those defaults cannot remove the bound.
const (
	dotReadTimeout = 2 * time.Second
	dotIdleTimeout = 8 * time.Second
)

// Server wraps the miekg/dns servers: UDP and TCP on the plain listen
// address, plus an optional DNS-over-TLS server. Every listener dispatches to
// the same handler, so blocking, caching, stats, the query log, and the
// query_privacy mask apply the same way on every transport.
type Server struct {
	udp     *dns.Server
	tcp     *dns.Server
	dot     *dns.Server // nil unless EnableDoT was called
	handler dns.Handler
}

// Listen binds UDP and TCP on addr (host:port) for plain DNS. main calls it
// right after config validation, like ListenDoT, so a port conflict (often the
// systemd-resolved stub on port 53) stops startup at once with a clear error.
// If the TCP bind fails, the UDP socket is closed again.
func Listen(addr string) (net.PacketConn, net.Listener, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dns: %w", err) // err names udp and addr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		return nil, nil, fmt.Errorf("dns: %w", err) // err names tcp and addr
	}
	return pc, ln, nil
}

// NewServer constructs the UDP and TCP servers on the sockets from Listen.
// Every query goes through handler.
//
// The sockets are bound before Start, so Shutdown can always close them.
// Before, each server bound its own socket inside Start; a Shutdown that ran
// before a server had started found it "not started", and that server then
// bound and served until the process exited (b/063).
func NewServer(pc net.PacketConn, ln net.Listener, handler dns.Handler) *Server {
	return &Server{
		udp:     &dns.Server{Addr: pc.LocalAddr().String(), Net: "udp", PacketConn: pc, Handler: handler},
		tcp:     &dns.Server{Addr: ln.Addr().String(), Net: "tcp", Listener: ln, Handler: handler},
		handler: handler,
	}
}

// EnableDoT adds a DNS-over-TLS listener that serves the same handler. ln is
// the pre-bound TLS listener from ListenDoT; miekg/dns serves a pre-set
// Listener through ActivateAndServe, so the TLS config lives on ln and not on
// the dns.Server. Call it before Start.
func (s *Server) EnableDoT(ln net.Listener) {
	s.dot = &dns.Server{
		Addr:        ln.Addr().String(),
		Net:         "tcp-tls",
		Listener:    ln,
		Handler:     s.handler,
		ReadTimeout: dotReadTimeout,
		IdleTimeout: func() time.Duration { return dotIdleTimeout },
	}
}

// servers returns every configured listener, in start order.
func (s *Server) servers() []*dns.Server {
	list := []*dns.Server{s.udp, s.tcp}
	if s.dot != nil {
		list = append(list, s.dot)
	}
	return list
}

// Start runs every listener and blocks until all of them stop, or returns
// the first error. Each goroutine always sends exactly one value (nil or
// error) and the channel holds one slot per listener, so the caller can drain
// every slot and no goroutine ever leaks.
func (s *Server) Start() error {
	servers := s.servers()
	errs := make(chan error, len(servers))

	for _, srv := range servers {
		go func(srv *dns.Server) {
			logger.Info("dns listener started", "addr", srv.Addr, "net", srv.Net)
			errs <- serve(srv)
		}(srv)
	}

	for remaining := len(servers); remaining > 0; remaining-- {
		if err := <-errs; err != nil {
			// Drain the other slots so their goroutines can exit; log any
			// further failure so it is not silently lost.
			go func(n int) {
				for range n {
					if err2 := <-errs; err2 != nil {
						logger.Error("secondary dns server failed", "err", err2)
					}
				}
			}(remaining - 1)
			return fmt.Errorf("dns: %w", err)
		}
	}
	return nil
}

// serve runs one listener on its pre-bound socket until it stops. If Shutdown
// closed the socket before the server started, the first read or Accept
// reports net.ErrClosed, which is a clean stop and not a failure.
func serve(srv *dns.Server) error {
	if err := srv.ActivateAndServe(); err != nil && !isClosedListener(err) {
		return err
	}
	return nil
}

// isClosedListener reports whether err means the socket was closed. serve
// treats that as a clean stop on every transport (UDP, TCP, and DoT).
func isClosedListener(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// Shutdown stops every listener. After Shutdown returns, any goroutine
// blocked in Start will observe all servers as cleanly stopped.
// Errors are logged rather than returned: by the time Shutdown runs the
// process is exiting, and "server not started" (the main failure mode)
// is not actionable, but it should not vanish silently either.
func (s *Server) Shutdown() {
	for _, srv := range s.servers() {
		if err := srv.Shutdown(); err != nil {
			logger.Warn("dns listener shutdown failed", "net", srv.Net, "err", err)
		}
		// dns.Server.Shutdown closes the socket only when the server has
		// started. Every socket is bound before Start, so close it here too;
		// otherwise a Shutdown that wins the race against Start would leave
		// the port bound and the server serving (b/063). A second Close is
		// harmless.
		if srv.PacketConn != nil {
			_ = srv.PacketConn.Close()
		}
		if srv.Listener != nil {
			_ = srv.Listener.Close()
		}
	}
}
