package dnsserver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startMockUpstream spins up a miekg/dns UDP server on 127.0.0.1:0 that
// answers every A query with the supplied IP. Returns the address (so it
// can be passed to forward) and a counter of how many queries it
// received. The server is shut down via t.Cleanup.
func startMockUpstream(t *testing.T, ip net.IP) (addr string, hits *atomic.Int64) {
	t.Helper()
	hits = new(atomic.Int64)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			hits.Add(1)
			resp := new(dns.Msg)
			resp.SetReply(req)
			if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
				resp.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   req.Question[0].Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						A: ip,
					},
				}
			}
			w.WriteMsg(resp)
		}),
	}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })

	return pc.LocalAddr().String(), hits
}

func TestForward_HappyPath(t *testing.T) {
	addr, hits := startMockUpstream(t, net.IPv4(1, 2, 3, 4))

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := forwardWith(ctx, req, []string{addr}, newUpstreamTracker())
	if err != nil {
		t.Fatalf("forwardWith: %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("mock received %d queries, want 1", hits.Load())
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("response has %d answers, want 1", len(resp.Answer))
	}
	a := resp.Answer[0].(*dns.A)
	if !a.A.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Errorf("answer A = %v, want 1.2.3.4", a.A)
	}
}

func TestForward_FailoverToHealthy(t *testing.T) {
	// 127.0.0.1:1 is the canonical "nothing listening here" address.
	dead := "127.0.0.1:1"
	live, hits := startMockUpstream(t, net.IPv4(8, 8, 8, 8))

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tracker := newUpstreamTracker()
	resp, err := forwardWith(ctx, req, []string{dead, live}, tracker)
	if err != nil {
		t.Fatalf("forwardWith: %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("live mock got %d queries, want 1", hits.Load())
	}
	a := resp.Answer[0].(*dns.A)
	if !a.A.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Errorf("answer A = %v, want 8.8.8.8", a.A)
	}

	// The dead upstream should now be in the cooldown set.
	if !tracker.shouldSkip(dead, time.Now()) {
		t.Error("dead upstream was not recorded as failed")
	}
}

func TestForward_SkipsCooldownOnSecondCall(t *testing.T) {
	// R6: once an upstream has failed recently, forwardWith should skip it
	// on the first sweep. We verify by counting that the live upstream
	// gets exactly two queries (one per call) while the dead one gets at
	// most one (the first sweep on call 1; skipped on call 2).
	dead := "127.0.0.1:1"
	live, liveHits := startMockUpstream(t, net.IPv4(8, 8, 8, 8))

	tracker := newUpstreamTracker()
	for range 2 {
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := forwardWith(ctx, req, []string{dead, live}, tracker)
		cancel()
		if err != nil {
			t.Fatalf("forwardWith: %v", err)
		}
	}
	if liveHits.Load() != 2 {
		t.Errorf("live mock got %d queries across two calls, want 2", liveHits.Load())
	}
}

func TestForward_AllFailReturnsError(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := forwardWith(ctx, req, []string{"127.0.0.1:1", "127.0.0.1:2"}, newUpstreamTracker())
	if err == nil {
		t.Error("expected error when every upstream fails")
	}
}

func TestUpstreamTracker_CooldownExpires(t *testing.T) {
	tr := newUpstreamTracker()
	now := time.Now()
	tr.recordFailure("up:53", now)

	if !tr.shouldSkip("up:53", now) {
		t.Error("just-recorded failure not in cooldown")
	}
	if tr.shouldSkip("up:53", now.Add(upstreamCooldown+time.Second)) {
		t.Error("cooldown should have expired")
	}
}

func TestUpstreamTracker_SuccessClearsCooldown(t *testing.T) {
	tr := newUpstreamTracker()
	now := time.Now()
	tr.recordFailure("up:53", now)
	tr.recordSuccess("up:53")
	if tr.shouldSkip("up:53", now) {
		t.Error("recordSuccess did not clear the cooldown")
	}
}
