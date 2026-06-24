package dnsserver

import (
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// TestIntegration_FullPipeline wires the whole production stack — store +
// cache + querylog (real SQLite) + handler + DNS server + mock upstream
// — and runs three real DNS queries against it:
//
//  1. a blocked domain (expects 0.0.0.0)
//  2. an allowed domain (expects the upstream's answer, cached)
//  3. the same allowed domain again (expects cache hit)
//
// Then it asserts the SQLite log captured all three queries with the
// right blocked flags. This catches wiring bugs unit tests miss — a
// constructor arg in the wrong order, a nil store, an unused upstream
// list, an incorrect logger fan-out — without standing up the full
// `cmd/s-hole` binary.
func TestIntegration_FullPipeline(t *testing.T) {
	// --- Mock upstream that answers any A query with 9.9.9.9 ---
	upstreamAddr, upstreamHits := startMockUpstream(t, net.IPv4(9, 9, 9, 9))

	// --- Real DBLogger backed by a temp SQLite file ---
	dbPath := filepath.Join(t.TempDir(), "queries.db")
	db, err := querylog.NewDBLogger(dbPath, "all", 30*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// --- Real blocklist store with one blocked domain ---
	store := blocklist.NewStore()
	store.Replace([]string{"ads.example.com"})

	// --- Real response cache ---
	c := cache.New(100)
	t.Cleanup(c.Close)

	counter := stats.New()
	h := NewHandler(store, counter, []string{upstreamAddr}, db,
		"zero", 60, c)

	// --- Real DNS server on a free port ---
	addr, err := pickFreePort(t)
	if err != nil {
		t.Fatalf("pickFreePort: %v", err)
	}
	srv := NewServer(addr, h)
	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start() }()
	if err := waitForUDP(addr, 2*time.Second); err != nil {
		srv.Shutdown()
		t.Fatalf("server never accepted a query: %v", err)
	}
	t.Cleanup(func() {
		srv.Shutdown()
		<-startErr
	})

	// waitForUDP sent one probe query through the handler — it hits the
	// upstream and gets counted. Reset the counters here so the
	// per-query assertions below speak about the queries the test
	// actually issues, not the probe.
	probeUpstream := upstreamHits.Load()
	probeQueries := counter.Snapshot(0).TotalQueries

	client := &dns.Client{Timeout: 1 * time.Second}

	// --- Query 1: blocked domain → 0.0.0.0 ---
	req1 := new(dns.Msg)
	req1.SetQuestion("ads.example.com.", dns.TypeA)
	resp1, _, err := client.Exchange(req1, addr)
	if err != nil {
		t.Fatalf("blocked query: %v", err)
	}
	if len(resp1.Answer) != 1 {
		t.Fatalf("blocked answer count = %d, want 1", len(resp1.Answer))
	}
	if a := resp1.Answer[0].(*dns.A); !a.A.Equal(net.IPv4zero) {
		t.Errorf("blocked answer = %v, want 0.0.0.0", a.A)
	}
	if got := upstreamHits.Load() - probeUpstream; got != 0 {
		t.Errorf("upstream hit on blocked query: %d", got)
	}

	// --- Query 2: allowed domain → forwarded, cached ---
	req2 := new(dns.Msg)
	req2.SetQuestion("good.example.com.", dns.TypeA)
	resp2, _, err := client.Exchange(req2, addr)
	if err != nil {
		t.Fatalf("allowed query: %v", err)
	}
	if a := resp2.Answer[0].(*dns.A); !a.A.Equal(net.IPv4(9, 9, 9, 9)) {
		t.Errorf("forwarded answer = %v, want 9.9.9.9", a.A)
	}
	if got := upstreamHits.Load() - probeUpstream; got != 1 {
		t.Errorf("upstream hits after query 2 = %d, want 1", got)
	}

	// --- Query 3: same allowed domain → cache hit, no upstream call ---
	req3 := new(dns.Msg)
	req3.SetQuestion("good.example.com.", dns.TypeA)
	_, _, err = client.Exchange(req3, addr)
	if err != nil {
		t.Fatalf("cached query: %v", err)
	}
	if got := upstreamHits.Load() - probeUpstream; got != 1 {
		t.Errorf("upstream hits after query 3 = %d, want still 1", got)
	}

	// --- Stats reflect three queries, one block, one cache hit ---
	snap := counter.Snapshot(0)
	if snap.TotalQueries-probeQueries != 3 {
		t.Errorf("TotalQueries delta = %d, want 3", snap.TotalQueries-probeQueries)
	}
	if snap.BlockedCount != 1 {
		t.Errorf("BlockedCount = %d, want 1", snap.BlockedCount)
	}
	if snap.CacheHits != 1 {
		t.Errorf("CacheHits = %d, want 1", snap.CacheHits)
	}

	// --- Querylog flush + reload, then assert all three rows landed ---
	// We can't query the live DBLogger reads across goroutines, so we
	// wait long enough for the 30 ms flush tick to fire.
	time.Sleep(150 * time.Millisecond)

	rows, err := db.Recent(t.Context(), 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	// 1 probe + 3 test queries = 4 rows expected.
	if len(rows) != 4 {
		t.Fatalf("got %d query log rows, want 4 (3 test + 1 probe)", len(rows))
	}

	// Sort-check by scanning: count test domain occurrences.
	var blocked, goodCount int
	for _, r := range rows {
		switch r.Domain {
		case "ads.example.com.":
			if !r.Blocked {
				t.Errorf("ads.example.com row had blocked=false")
			}
			blocked++
		case "good.example.com.":
			if r.Blocked {
				t.Errorf("good.example.com row had blocked=true")
			}
			goodCount++
		}
	}
	if blocked != 1 {
		t.Errorf("blocked row count = %d, want 1", blocked)
	}
	if goodCount != 2 {
		t.Errorf("good.example.com row count = %d, want 2 (forwarded + cached)", goodCount)
	}
	_ = atomic.LoadInt64 // keep atomic import alive even if test changes
}
