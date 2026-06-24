package dns

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// forward tries each upstream in order and returns the first successful
// reply. Each Exchange has its own 3-second timeout; if every upstream
// errors, the caller surfaces SERVFAIL to the client via dns.HandleFailed.
func forward(req *dns.Msg, upstreams []string) (*dns.Msg, error) {
	client := &dns.Client{Timeout: 3 * time.Second}
	for _, upstream := range upstreams {
		resp, _, err := client.Exchange(req, upstream)
		if err == nil {
			return resp, nil
		}
	}
	return nil, fmt.Errorf("all upstreams failed for %s", req.Question[0].Name)
}
