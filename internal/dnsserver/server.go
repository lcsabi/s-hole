package dnsserver

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
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

// NewServer constructs UDP and TCP servers bound to addr (host:port) that
// dispatch every query through handler.
func NewServer(addr string, handler dns.Handler) *Server {
	return &Server{
		udp:     &dns.Server{Addr: addr, Net: "udp", Handler: handler},
		tcp:     &dns.Server{Addr: addr, Net: "tcp", Handler: handler},
		handler: handler,
	}
}

// EnableDoT adds a DNS-over-TLS listener that serves the same handler. ln is
// the pre-bound TLS listener from ListenDoT; miekg/dns serves a pre-set
// Listener through ActivateAndServe, so the TLS config lives on ln and not on
// the dns.Server. Call it before Start.
func (s *Server) EnableDoT(ln net.Listener) {
	s.dot = &dns.Server{Addr: ln.Addr().String(), Net: "tcp-tls", Listener: ln, Handler: s.handler}
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

// serve runs one listener until it stops. A server with a pre-bound Listener
// (DoT) runs through ActivateAndServe; if Shutdown closed that listener before
// the server started, Accept reports net.ErrClosed, which is a clean stop and
// not a failure.
func serve(srv *dns.Server) error {
	if srv.Listener == nil {
		return srv.ListenAndServe()
	}
	if err := srv.ActivateAndServe(); err != nil && !isClosedListener(err) {
		return err
	}
	return nil
}

// Shutdown stops every listener. After Shutdown returns, any goroutine
// blocked in Start will observe all servers as cleanly stopped.
// Errors are logged rather than returned: by the time Shutdown runs the
// process is exiting, and "server not started" (the main failure mode)
// is not actionable, but it should not vanish silently either.
func (s *Server) Shutdown() {
	if err := s.udp.Shutdown(); err != nil {
		logger.Warn("udp listener shutdown", "err", err)
	}
	if err := s.tcp.Shutdown(); err != nil {
		logger.Warn("tcp listener shutdown", "err", err)
	}
	if s.dot != nil {
		if err := s.dot.Shutdown(); err != nil {
			logger.Warn("dot listener shutdown", "err", err)
		}
		// dns.Server.Shutdown closes the listener only of a server that has
		// started. The DoT listener is bound before Start, so close it here
		// too; otherwise a Shutdown that wins the race against Start would
		// leave the port bound. A second Close is harmless.
		_ = s.dot.Listener.Close()
	}
}
