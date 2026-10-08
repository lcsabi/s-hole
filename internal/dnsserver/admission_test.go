package dnsserver

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// holdingUpstream is a UDP upstream that receives queries and holds each one
// without an answer until release is called. After release, it answers every
// held query and every later query at once, with an A record for ip. A test
// uses it to keep forwards in flight for as long as it needs.
type holdingUpstream struct {
	pc   net.PacketConn
	ip   net.IP
	hits atomic.Int64
	done chan struct{}

	mu       sync.Mutex
	released bool
	pending  []heldQuery
}

type heldQuery struct {
	addr net.Addr
	req  *dns.Msg
}

func startHoldingUpstream(t *testing.T, ip net.IP) *holdingUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	u := &holdingUpstream{pc: pc, ip: ip, done: make(chan struct{})}
	go u.serve()
	t.Cleanup(func() {
		_ = pc.Close()
		<-u.done
	})
	return u
}

func (u *holdingUpstream) addr() string { return u.pc.LocalAddr().String() }

func (u *holdingUpstream) serve() {
	defer close(u.done)
	buf := make([]byte, dns.MaxMsgSize)
	for {
		n, addr, err := u.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req := new(dns.Msg)
		if req.Unpack(buf[:n]) != nil {
			continue
		}
		u.hits.Add(1)
		u.mu.Lock()
		if !u.released {
			u.pending = append(u.pending, heldQuery{addr: addr, req: req})
			u.mu.Unlock()
			continue
		}
		u.mu.Unlock()
		u.answer(addr, req)
	}
}

func (u *holdingUpstream) answer(addr net.Addr, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	q := req.Question[0]
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   u.ip,
	}}
	packed, err := resp.Pack()
	if err != nil {
		return
	}
	_, _ = u.pc.WriteTo(packed, addr)
}

// release answers every held query and makes the upstream answer later
// queries at once.
func (u *holdingUpstream) release() {
	u.mu.Lock()
	u.released = true
	held := u.pending
	u.pending = nil
	u.mu.Unlock()
	for _, h := range held {
		u.answer(h.addr, h.req)
	}
}

// syncLogger is a query-log sink that is safe for concurrent ServeDNS calls.
type syncLogger struct {
	mu   sync.Mutex
	recs []querylog.Record
}

func (l *syncLogger) Log(rec querylog.Record) {
	l.mu.Lock()
	l.recs = append(l.recs, rec)
	l.mu.Unlock()
}

func (l *syncLogger) find(domain string) []querylog.Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []querylog.Record
	for _, r := range l.recs {
		if r.Domain == domain {
			out = append(out, r)
		}
	}
	return out
}

func waitForHits(t *testing.T, hits *atomic.Int64, want int64, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for hits.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("upstream got %d queries within %v, want %d", hits.Load(), limit, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func firstA(m *dns.Msg) net.IP {
	if m == nil {
		return nil
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A
		}
	}
	return nil
}

func TestServeDNS_ForwardLimit(t *testing.T) {
	// SEC-12: at most 512 queries wait for an upstream at the same time.
	// With 512 forwards held by a slow upstream, the next query that needs a
	// forward gets SERVFAIL at once, is not sent upstream, and raises
	// ForwardLimited (shole_forward_limited_total). It is an unresolved query:
	// the forward-failure counter rises, and the query log gets a synthesized
	// SERVFAIL row. A query answered without a forward (blocked, cache hit,
	// local PTR, local name) is not affected by the cap. After the held
	// forwards complete, their slots are free and a new query forwards
	// normally. The failure summary says that the forward limit was reached,
	// and, like the rest of the application log, names no query and no
	// client, even under query_log.mode "all".
	app := captureAppLog(t)
	up := startHoldingUpstream(t, net.IPv4(7, 7, 7, 7))

	store := blocklist.NewStore()
	store.Replace([]string{"ads.zqxv-blocked.example"})
	c := cache.New(100)
	t.Cleanup(c.Close)
	counter := stats.New()
	qlog := &syncLogger{}
	h := NewHandler(store, counter, []string{up.addr()}, qlog, "zero", 60, c, true, "full")
	h.SetQueryLogMode("all")

	cachedReq := buildReq("cached.zqxv-flood.example")
	c.Set(cachedReq, buildResp(cachedReq.Question[0], net.IPv4(8, 8, 4, 4), 300))

	limitedBefore := ForwardLimited()

	const held = 512
	writers := make([]*fakeWriter, held)
	var wg sync.WaitGroup
	// Release the held forwards on every exit path, so no goroutine is left
	// waiting for the per-upstream timeout when the test fails early.
	t.Cleanup(func() {
		up.release()
		wg.Wait()
	})
	// Start the held queries in batches and wait until the upstream has each
	// batch: a burst of 512 datagrams can overflow the upstream's socket
	// buffer. The upstream timeout is 3 s, so the checks below run while all
	// 512 forwards are still held.
	const batch = 32
	for i := range held {
		writers[i] = fakeClient()
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h.ServeDNS(writers[i], buildReq(fmt.Sprintf("q%d.zqxv-flood.example", i)))
		}(i)
		if (i+1)%batch == 0 {
			waitForHits(t, &up.hits, int64(i+1), time.Second)
		}
	}
	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()

	if n := ForwardLimited() - limitedBefore; n != 0 {
		t.Fatalf("ForwardLimited rose by %d while filling the %d slots, want 0", n, held)
	}

	// Query 513 needs a forward: SERVFAIL at once.
	w := fakeClient()
	start := time.Now()
	h.ServeDNS(w, buildReq("limited.zqxv-flood.example"))
	took := time.Since(start)
	if w.written == nil || w.written.Rcode != dns.RcodeServerFailure {
		t.Fatalf("query over the cap got %v, want SERVFAIL", w.written)
	}
	if took > time.Second {
		t.Errorf("SERVFAIL over the cap took %v, want an answer at once", took)
	}
	if n := ForwardLimited() - limitedBefore; n != 1 {
		t.Errorf("ForwardLimited rose by %d, want 1", n)
	}
	if got := up.hits.Load(); got != held {
		t.Errorf("upstream got %d queries, want %d: the query over the cap was forwarded", got, held)
	}
	if got := counter.Snapshot(10).ForwardFailures; got != 1 {
		t.Errorf("ForwardFailures = %d, want 1 for the query over the cap", got)
	}
	recs := qlog.find("limited.zqxv-flood.example.")
	if len(recs) != 1 {
		t.Fatalf("query log has %d rows for the query over the cap, want 1", len(recs))
	}
	if r := recs[0]; r.Rcode != dns.RcodeServerFailure || !r.Synthesized || r.Blocked || r.CacheHit {
		t.Errorf("query log row = %+v, want a synthesized SERVFAIL", r)
	}

	// Answers that need no forward still work while the cap is full.
	t.Run("blocked", func(t *testing.T) {
		w := fakeClient()
		h.ServeDNS(w, buildReq("ads.zqxv-blocked.example"))
		if ip := firstA(w.written); w.written == nil || w.written.Rcode != dns.RcodeSuccess || !ip.Equal(net.IPv4zero) {
			t.Errorf("blocked query got %v, want 0.0.0.0", w.written)
		}
	})
	t.Run("cache hit", func(t *testing.T) {
		w := fakeClient()
		h.ServeDNS(w, buildReq("cached.zqxv-flood.example"))
		if ip := firstA(w.written); w.written == nil || w.written.Rcode != dns.RcodeSuccess || !ip.Equal(net.IPv4(8, 8, 4, 4)) {
			t.Errorf("cached query got %v, want the cached 8.8.4.4", w.written)
		}
	})
	t.Run("local PTR", func(t *testing.T) {
		w := fakeClient()
		h.ServeDNS(w, ptrQuery("100.1.168.192.in-addr.arpa."))
		if w.written == nil || w.written.Rcode != dns.RcodeNameError || !w.written.Authoritative {
			t.Errorf("local PTR got %v, want an authoritative NXDOMAIN", w.written)
		}
	})
	t.Run("localhost", func(t *testing.T) {
		w := fakeClient()
		h.ServeDNS(w, buildReq("localhost"))
		if ip := firstA(w.written); w.written == nil || w.written.Rcode != dns.RcodeSuccess || !ip.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("localhost got %v, want 127.0.0.1", w.written)
		}
	})
	t.Run("never resolved", func(t *testing.T) {
		w := fakeClient()
		h.ServeDNS(w, buildReq("zqxv.onion"))
		if w.written == nil || w.written.Rcode != dns.RcodeNameError {
			t.Errorf(".onion got %v, want NXDOMAIN", w.written)
		}
	})
	if n := ForwardLimited() - limitedBefore; n != 1 {
		t.Errorf("ForwardLimited rose by %d after the local answers, want still 1", n)
	}
	if got := counter.Snapshot(10).ForwardFailures; got != 1 {
		t.Errorf("ForwardFailures = %d after the local answers, want still 1", got)
	}

	// The held forwards complete with answers and free their slots.
	up.release()
	select {
	case <-allDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the held forwards did not complete after release")
	}
	for i, w := range writers {
		if ip := firstA(w.written); w.written == nil || w.written.Rcode != dns.RcodeSuccess || !ip.Equal(net.IPv4(7, 7, 7, 7)) {
			t.Fatalf("held query %d got %v, want the upstream answer 7.7.7.7", i, w.written)
		}
	}
	w = fakeClient()
	h.ServeDNS(w, buildReq("after.zqxv-flood.example"))
	if ip := firstA(w.written); w.written == nil || !ip.Equal(net.IPv4(7, 7, 7, 7)) {
		t.Errorf("query after the release got %v, want a forwarded answer", w.written)
	}
	if got := up.hits.Load(); got != held+1 {
		t.Errorf("upstream got %d queries, want %d", got, held+1)
	}
	if n := ForwardLimited() - limitedBefore; n != 1 {
		t.Errorf("ForwardLimited rose by %d, want 1", n)
	}

	// No query wrote a log line of its own; the summary is the only line.
	if recs := app.records(t); len(recs) != 0 {
		t.Fatalf("queries wrote %d log lines before the summary, want 0:\n%s", len(recs), app.text())
	}
	reportNow(h)
	sums := app.withMsg(t, "queries could not be resolved")
	if len(sums) != 1 {
		t.Fatalf("got %d summary lines, want 1:\n%s", len(sums), app.text())
	}
	if sums[0]["queries"] != float64(1) {
		t.Errorf("summary queries = %v, want 1", sums[0]["queries"])
	}
	causes, _ := sums[0]["causes"].(string)
	hint, _ := sums[0]["hint"].(string)
	if !strings.Contains(strings.ToLower(causes), "limit") {
		t.Errorf("causes = %q, want the forward limit", causes)
	}
	if !strings.Contains(hint, "512") {
		t.Errorf("hint = %q, want the forward limit of 512", hint)
	}
	// No upstream failed in this interval, so the hint does not say so.
	if strings.Contains(hint, "every upstream failed") {
		t.Errorf("hint = %q blames the upstreams, but only the forward limit was reached", hint)
	}
	text := strings.ToLower(app.text())
	for _, leak := range []string{"zqxv", "limited.", "192.168.1.100", "33333"} {
		if strings.Contains(text, leak) {
			t.Errorf("application log holds %q:\n%s", leak, app.text())
		}
	}
}

func TestFailureReport_ForwardLimitWithUpstreamFailure(t *testing.T) {
	// SEC-12: in an interval with a query over the forward cap and a query
	// that every upstream failed, the summary keeps both causes, and the hint
	// still says that the forward limit was reached.
	app := captureAppLog(t)
	h := NewHandler(blocklist.NewStore(), stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "drop")
	h.failures.record(errForwardLimit)
	h.failures.record(&ForwardError{Causes: []UpstreamCause{{Upstream: "9.9.9.9:53", Err: fmt.Errorf("i/o timeout")}}})
	reportNow(h)
	sums := app.withMsg(t, "queries could not be resolved")
	if len(sums) != 1 || sums[0]["queries"] != float64(2) {
		t.Fatalf("summary = %v, want one line with queries=2", sums)
	}
	causes, _ := sums[0]["causes"].(string)
	hint, _ := sums[0]["hint"].(string)
	if !strings.Contains(causes, "9.9.9.9:53") || !strings.Contains(strings.ToLower(causes), "limit") {
		t.Errorf("causes = %q, want the upstream and the forward limit", causes)
	}
	if !strings.Contains(hint, "512") {
		t.Errorf("hint = %q, want the forward limit of 512", hint)
	}

	// The next interval starts clean: an upstream failure alone gets the
	// upstream hint, not the forward-limit hint.
	h.failures.record(&ForwardError{Causes: []UpstreamCause{{Upstream: "9.9.9.9:53", Err: fmt.Errorf("i/o timeout")}}})
	reportNow(h)
	sums = app.withMsg(t, "queries could not be resolved")
	if len(sums) != 2 {
		t.Fatalf("got %d summary lines, want 2", len(sums))
	}
	causes, _ = sums[1]["causes"].(string)
	hint, _ = sums[1]["hint"].(string)
	if strings.Contains(strings.ToLower(causes), "limit") || strings.Contains(hint, "512") {
		t.Errorf("second summary = causes %q, hint %q; want no forward limit", causes, hint)
	}
}

func TestServeDNS_ForwardSlotFreedAfterFailure(t *testing.T) {
	// SEC-12: a failed forward frees its slot. Far more than 512 failed
	// forwards in a row never reach the cap: each one fails at the upstream,
	// and none gets the forward-limit SERVFAIL.
	h, _ := failingHandler(t, "none")
	limitedBefore := ForwardLimited()
	const n = maxForwards + 40
	for i := range n {
		w := fakeClient()
		h.ServeDNS(w, buildReq(fmt.Sprintf("f%d.zqxv-fail.example", i)))
		if w.written == nil || w.written.Rcode != dns.RcodeServerFailure {
			t.Fatalf("query %d got %v, want SERVFAIL", i, w.written)
		}
	}
	if d := ForwardLimited() - limitedBefore; d != 0 {
		t.Errorf("ForwardLimited rose by %d after %d sequential failed forwards, want 0 (a slot is not freed after a failure)", d, n)
	}
	if got := h.counter.Snapshot(10).ForwardFailures; got != n {
		t.Errorf("ForwardFailures = %d, want %d", got, n)
	}
}

func TestServeDNS_ForwardSlotFreedAfterSuccess(t *testing.T) {
	// SEC-12: a successful forward frees its slot. Far more than 512
	// successful forwards in a row (no cache, so each one goes upstream) all
	// get the upstream answer.
	up, hits := startMockUpstream(t, net.IPv4(7, 7, 7, 7))
	h := NewHandler(blocklist.NewStore(), stats.New(), []string{up}, nullLogger{}, "zero", 60, nil, false, "drop")
	limitedBefore := ForwardLimited()
	const n = maxForwards + 40
	for i := range n {
		w := fakeClient()
		h.ServeDNS(w, buildReq(fmt.Sprintf("s%d.zqxv-ok.example", i)))
		if ip := firstA(w.written); w.written == nil || !ip.Equal(net.IPv4(7, 7, 7, 7)) {
			t.Fatalf("query %d got %v, want the upstream answer", i, w.written)
		}
	}
	if d := ForwardLimited() - limitedBefore; d != 0 {
		t.Errorf("ForwardLimited rose by %d, want 0", d)
	}
	if got := hits.Load(); got != n {
		t.Errorf("upstream got %d queries, want %d", got, n)
	}
}

func TestListen_TCPConnectionCap(t *testing.T) {
	// SEC-12: the plain-TCP listener serves at most 256 connections at the
	// same time. With 256 connections open, connection 257 is not served: it
	// waits or is closed. When one of the 256 closes, a slot is free again.
	addr, pc, ln := pickFreePort(t)
	h := NewHandler(blocklist.NewStore(), stats.New(), nil, nullLogger{}, "zero", 60, nil, false, "drop")
	srv := NewServer(pc, ln, h)
	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start() }()
	t.Cleanup(func() {
		srv.Shutdown()
		if err := waitStart(t, startErr); err != nil {
			t.Errorf("Start returned %v after Shutdown, want nil", err)
		}
	})
	if err := waitForUDP(addr, 3*time.Second); err != nil {
		t.Fatalf("server did not come up on %s", addr)
	}

	query := func(c *dns.Conn, limit time.Duration) (*dns.Msg, error) {
		if err := c.WriteMsg(buildReq("localhost")); err != nil {
			return nil, err
		}
		_ = c.SetReadDeadline(time.Now().Add(limit))
		return c.ReadMsg()
	}
	dial := func() *dns.Conn {
		nc, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		c := &dns.Conn{Conn: nc}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	// Each held connection answers one query, which proves the server
	// accepted it. After a query, the server keeps an idle connection open
	// for 8 s, longer than the rest of this test.
	const tcpCap = 256
	held := make([]*dns.Conn, tcpCap)
	for i := range held {
		held[i] = dial()
		if m, err := query(held[i], 2*time.Second); err != nil || m.Rcode != dns.RcodeSuccess {
			t.Fatalf("connection %d: reply %v, err %v; want an answer", i+1, m, err)
		}
	}

	extra := dial()
	m, err := query(extra, 500*time.Millisecond)
	if err == nil {
		t.Fatalf("connection %d got an answer (%v) while %d connections were open, want it to wait or be closed", tcpCap+1, m.Rcode, tcpCap)
	}
	var ne net.Error
	waiting := errors.As(err, &ne) && ne.Timeout()

	// Free one slot. A waiting connection 257 is served now; a closed one
	// is replaced by a new connection, which is served.
	_ = held[0].Close()
	if waiting {
		_ = extra.SetReadDeadline(time.Now().Add(3 * time.Second))
		if m, err := extra.ReadMsg(); err != nil || m.Rcode != dns.RcodeSuccess {
			t.Errorf("connection %d after a slot was freed: reply %v, err %v; want an answer", tcpCap+1, m, err)
		}
		return
	}
	if m, err := query(dial(), 3*time.Second); err != nil || m.Rcode != dns.RcodeSuccess {
		t.Errorf("new connection after a slot was freed: reply %v, err %v; want an answer", m, err)
	}
}
