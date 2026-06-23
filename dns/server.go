package dns

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

// Server wraps miekg/dns servers for both UDP and TCP.
type Server struct {
	udp *dns.Server
	tcp *dns.Server
}

func NewServer(addr string, handler dns.Handler) *Server {
	return &Server{
		udp: &dns.Server{Addr: addr, Net: "udp", Handler: handler},
		tcp: &dns.Server{Addr: addr, Net: "tcp", Handler: handler},
	}
}

// Start runs both UDP and TCP listeners. It blocks until both have started
// or one returns an error.
func (s *Server) Start() error {
	errs := make(chan error, 2)
	var wg sync.WaitGroup

	for _, srv := range []*dns.Server{s.udp, s.tcp} {
		wg.Add(1)
		go func(srv *dns.Server) {
			defer wg.Done()
			fmt.Printf("[dns] listening on %s (%s)\n", srv.Addr, srv.Net)
			if err := srv.ListenAndServe(); err != nil {
				errs <- fmt.Errorf("%s: %w", srv.Net, err)
			}
		}(srv)
	}

	// Return the first error, if any.
	go func() {
		wg.Wait()
		close(errs)
	}()

	return <-errs
}

func (s *Server) Shutdown() {
	s.udp.Shutdown()
	s.tcp.Shutdown()
}
