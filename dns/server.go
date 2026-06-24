package dns

import (
	"fmt"

	"github.com/miekg/dns"
)

// Server wraps miekg/dns servers for both UDP and TCP.
type Server struct {
	udp *dns.Server
	tcp *dns.Server
}

// NewServer constructs UDP and TCP servers bound to addr (host:port) that
// dispatch every query through handler.
func NewServer(addr string, handler dns.Handler) *Server {
	return &Server{
		udp: &dns.Server{Addr: addr, Net: "udp", Handler: handler},
		tcp: &dns.Server{Addr: addr, Net: "tcp", Handler: handler},
	}
}

// Start runs both UDP and TCP listeners and blocks until one exits.
// Each goroutine always sends exactly one value (nil or error), so the
// caller can drain both slots and neither goroutine ever leaks.
func (s *Server) Start() error {
	errs := make(chan error, 2)

	for _, srv := range []*dns.Server{s.udp, s.tcp} {
		go func(srv *dns.Server) {
			fmt.Printf("[dns] listening on %s (%s)\n", srv.Addr, srv.Net)
			errs <- srv.ListenAndServe()
		}(srv)
	}

	// Block on the first result.
	if err := <-errs; err != nil {
		// Drain the second slot so the other goroutine can exit;
		// log it if it also failed so the error is not silently lost.
		go func() {
			if err2 := <-errs; err2 != nil {
				fmt.Printf("[dns] secondary server error: %v\n", err2)
			}
		}()
		return fmt.Errorf("dns: %w", err)
	}

	// First server stopped cleanly (shutdown); wait for the second.
	return <-errs
}

// Shutdown stops both listeners. After Shutdown returns, any goroutine
// blocked in Start will observe both servers as cleanly stopped.
func (s *Server) Shutdown() {
	s.udp.Shutdown()
	s.tcp.Shutdown()
}
