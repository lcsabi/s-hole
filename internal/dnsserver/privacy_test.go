package dnsserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/cache"
	"github.com/lcsabi/s-hole/internal/stats"
	"github.com/miekg/dns"
)

// appLog collects the application log (slog) as JSON lines. The package
// logger looks up slog.Default for each record, so swapping the default
// captures it. The tests in this package run one at a time, so the swap of
// the process-wide default is safe.
type appLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *appLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *appLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *appLog) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.text()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// withMsg returns the records whose msg is msg.
func (l *appLog) withMsg(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range l.records(t) {
		if r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

func captureAppLog(t *testing.T) *appLog {
	t.Helper()
	l := &appLog{}
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(orig) })
	return l
}

func TestServeDNS_QueryLogModeGovernsTallies(t *testing.T) {
	// D2: the Top Clients and Top Domains tallies get the client and domain
	// only for a query the mode records. The counters count every query in
	// every mode.
	cases := []struct {
		mode        string
		set         bool
		wantClients []stats.Entry
		wantDomains []stats.Entry
	}{
		{"all", true, []stats.Entry{{Name: "192.168.1.100", Count: 3}}, []stats.Entry{{Name: "ads.example.com.", Count: 1}}},
		{"blocked", true, []stats.Entry{{Name: "192.168.1.100", Count: 1}}, []stats.Entry{{Name: "ads.example.com.", Count: 1}}},
		{"none", true, nil, nil},
		{"unset", false, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			store := blocklist.NewStore()
			store.Replace([]string{"ads.example.com"})
			c := cache.New(10)
			defer c.Close()
			q := dns.Question{Name: "cached.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
			c.Set(q, buildResp(q, net.IPv4(1, 2, 3, 4), 300))
			counter := stats.New()
			h := NewHandler(store, counter, nil, nullLogger{}, "zero", 60, c, true, "full")
			if tc.set {
				h.SetQueryLogMode(tc.mode)
			}

			h.ServeDNS(fakeClient(), buildReq("ads.example.com"))
			h.ServeDNS(fakeClient(), buildReq("cached.example.com"))
			ptr := new(dns.Msg)
			ptr.SetQuestion("5.1.168.192.in-addr.arpa.", dns.TypePTR)
			h.ServeDNS(fakeClient(), ptr)

			s := counter.Snapshot(10)
			if s.TotalQueries != 3 || s.BlockedCount != 1 || s.CacheHits != 1 || s.LocalPTRCount != 1 {
				t.Errorf("counters = {total %d, blocked %d, cache %d, ptr %d}, want {3, 1, 1, 1}",
					s.TotalQueries, s.BlockedCount, s.CacheHits, s.LocalPTRCount)
			}
			if !sameEntries(s.TopClients, tc.wantClients) {
				t.Errorf("top clients = %v, want %v", s.TopClients, tc.wantClients)
			}
			if !sameEntries(s.TopDomains, tc.wantDomains) {
				t.Errorf("top domains = %v, want %v", s.TopDomains, tc.wantDomains)
			}
		})
	}
}

func sameEntries(a, b []stats.Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// writeFailure is the error a reply write to a gone client returns: its
// text holds both socket addresses.
func writeFailure() error {
	return &net.OpError{
		Op:     "write",
		Net:    "udp",
		Source: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 53},
		Addr:   &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 33333},
		Err:    errors.New("sendto: broken pipe"),
	}
}

func TestServeDNS_WriteFailureWarnings(t *testing.T) {
	// D3: a WARN about one query carries the domain only under mode "all",
	// never the client address. The error is shown as the operation and the
	// underlying error, without the socket addresses.
	upstream, _ := startMockUpstream(t, net.IPv4(4, 4, 4, 4))
	paths := []struct {
		name  string
		query func() *dns.Msg
		qname string
	}{
		{"sinkhole", func() *dns.Msg { return buildReq("Ads.Example.com") }, "ads.example.com."},
		{"cache", func() *dns.Msg { return buildReq("cached.example.com") }, "cached.example.com."},
		{"forward", func() *dns.Msg { return buildReq("fresh.example.com") }, "fresh.example.com."},
		{"local PTR", func() *dns.Msg {
			m := new(dns.Msg)
			m.SetQuestion("5.1.168.192.in-addr.arpa.", dns.TypePTR)
			return m
		}, "5.1.168.192.in-addr.arpa."},
	}
	for _, mode := range []string{"all", "blocked", "none"} {
		for _, p := range paths {
			t.Run(mode+"/"+p.name, func(t *testing.T) {
				store := blocklist.NewStore()
				store.Replace([]string{"ads.example.com"})
				c := cache.New(10)
				defer c.Close()
				q := dns.Question{Name: "cached.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
				c.Set(q, buildResp(q, net.IPv4(1, 2, 3, 4), 300))
				h := NewHandler(store, stats.New(), []string{upstream}, nullLogger{}, "zero", 60, c, true, "full")
				h.SetQueryLogMode(mode)
				app := captureAppLog(t)

				w := fakeClient()
				w.writeError = writeFailure()
				h.ServeDNS(w, p.query())

				var warns []map[string]any
				for _, r := range app.records(t) {
					if r["level"] == "WARN" {
						warns = append(warns, r)
					}
				}
				if len(warns) != 1 {
					t.Fatalf("got %d WARN lines, want 1:\n%s", len(warns), app.text())
				}
				if got := warns[0]["err"]; got != "write: sendto: broken pipe" {
					t.Errorf("err = %v, want \"write: sendto: broken pipe\"", got)
				}
				domain, hasDomain := warns[0]["domain"].(string)
				if mode == "all" {
					if !hasDomain || !strings.EqualFold(domain, p.qname) {
						t.Errorf("domain = %v, want %s under mode all", warns[0]["domain"], p.qname)
					}
				} else if _, ok := warns[0]["domain"]; ok {
					t.Errorf("WARN carries the domain under mode %q: %v", mode, warns[0])
				}
				text := strings.ToLower(app.text())
				for _, leak := range []string{"192.168.1.100", "33333", "192.168.1.2:53"} {
					if strings.Contains(text, leak) {
						t.Errorf("application log holds %q:\n%s", leak, app.text())
					}
				}
				if mode != "all" && strings.Contains(text, strings.TrimSuffix(p.qname, ".")) {
					t.Errorf("application log names the query under mode %q:\n%s", mode, app.text())
				}
			})
		}
	}
}

func TestWriteErr(t *testing.T) {
	// D3: only the operation and the underlying error of a *net.OpError are
	// kept; other errors are shown as they are.
	if got := writeErr(writeFailure()); got != "write: sendto: broken pipe" {
		t.Errorf("writeErr(OpError) = %q", got)
	}
	wrapped := fmt.Errorf("reply: %w", writeFailure())
	if got := writeErr(wrapped); strings.Contains(got, "192.168.1.100") {
		t.Errorf("writeErr(wrapped OpError) = %q, holds the client address", got)
	}
	if got := writeErr(errors.New("plain")); got != "plain" {
		t.Errorf("writeErr(plain) = %q, want plain", got)
	}
}

// bigAnswerDoH starts a DoH upstream that answers every A query with n
// records, more than 512 bytes for n = 40.
func bigAnswerDoH(t *testing.T, n int) (endpoint string, hits interface{ Load() int64 }) {
	t.Helper()
	ep, h := startDoHUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req dns.Msg
		if err := req.Unpack(body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(&req)
		for i := 0; i < n; i++ {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(10, 0, byte(i/256), byte(i%256)),
			})
		}
		packed, _ := resp.Pack()
		w.Header().Set("Content-Type", dohMediaType)
		w.Write(packed)
	})
	return ep, h
}

func packedLen(t *testing.T, m *dns.Msg) int {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("pack reply: %v", err)
	}
	return len(b)
}

func TestServeDNS_UDPReplyFitsTheClient(t *testing.T) {
	// D6 (b/081): over UDP a relayed reply is cut to 512 bytes without EDNS0,
	// or to the size the client advertised, with TC set when it was larger.
	// TCP replies are not changed, and the cache keeps the full reply.
	const records = 40
	endpoint, hits := bigAnswerDoH(t, records)
	c := cache.New(10)
	defer c.Close()
	h := NewHandler(blocklist.NewStore(), stats.New(), []string{endpoint}, nullLogger{}, "zero", 60, c, false, "drop")

	udp := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 40000}
	tcp := &net.TCPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 40000}

	// 1. UDP without EDNS0, from the upstream.
	w := &fakeWriter{remote: udp}
	h.ServeDNS(w, buildReq("big.example.com"))
	if w.written == nil {
		t.Fatal("no reply")
	}
	if n := packedLen(t, w.written); n > 512 || !w.written.Truncated || len(w.written.Answer) >= records {
		t.Errorf("UDP reply without EDNS0: %d bytes, TC=%v, %d answers; want <= 512 bytes, TC set, fewer than %d answers",
			n, w.written.Truncated, len(w.written.Answer), records)
	}

	// 2. TCP, from the cache: the full reply.
	w = &fakeWriter{remote: tcp}
	h.ServeDNS(w, buildReq("big.example.com"))
	if w.written == nil || w.written.Truncated || len(w.written.Answer) != records {
		t.Errorf("TCP reply from the cache: TC=%v, %d answers; want the full %d answers", w.written.Truncated, len(w.written.Answer), records)
	}

	// 3. UDP with a 1232-byte EDNS0 buffer, from the cache: it fits.
	w = &fakeWriter{remote: udp}
	req := buildReq("big.example.com")
	req.SetEdns0(1232, false)
	h.ServeDNS(w, req)
	if w.written == nil || w.written.Truncated || len(w.written.Answer) != records || packedLen(t, w.written) > 1232 {
		t.Errorf("UDP reply with EDNS0 1232: TC=%v, %d answers; want the full %d answers", w.written.Truncated, len(w.written.Answer), records)
	}

	// 4. UDP with a 600-byte EDNS0 buffer: cut to 600 bytes, TC set.
	w = &fakeWriter{remote: udp}
	req = buildReq("big.example.com")
	req.SetEdns0(600, false)
	h.ServeDNS(w, req)
	if n := packedLen(t, w.written); n > 600 || n <= 512 || !w.written.Truncated {
		t.Errorf("UDP reply with EDNS0 600: %d bytes, TC=%v; want 513 to 600 bytes with TC set", n, w.written.Truncated)
	}

	// 5. UDP without EDNS0 again, from the cache: cut again, so the cache
	// still holds the full reply.
	w = &fakeWriter{remote: udp}
	h.ServeDNS(w, buildReq("big.example.com"))
	if n := packedLen(t, w.written); n > 512 || !w.written.Truncated {
		t.Errorf("second UDP reply: %d bytes, TC=%v; want <= 512 with TC set", n, w.written.Truncated)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream got %d queries, want 1 (the rest from the cache)", got)
	}
	q := dns.Question{Name: "big.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if m, ok := c.Get(q); !ok || m.Truncated || len(m.Answer) != records {
		t.Errorf("cached reply: ok=%v, %d answers; want the full reply", ok, len(m.Answer))
	}
}

func TestServeDNS_TCPForwardedReplyIsNotCut(t *testing.T) {
	// D6: a reply forwarded to a TCP client is not changed.
	endpoint, _ := bigAnswerDoH(t, 40)
	h := NewHandler(blocklist.NewStore(), stats.New(), []string{endpoint}, nullLogger{}, "zero", 60, nil, false, "drop")
	w := &fakeWriter{remote: &net.TCPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 40000}}
	h.ServeDNS(w, buildReq("big.example.com"))
	if w.written == nil || w.written.Truncated || len(w.written.Answer) != 40 {
		t.Errorf("TCP reply: %v, want 40 answers without TC", w.written)
	}
}

func TestServeDNS_RecordsLowercaseDomain(t *testing.T) {
	// D7 (b/082): stats and the query log record the domain in lowercase. The
	// reply echoes the question name as the client sent it.
	upstream, _ := startMockUpstream(t, net.IPv4(4, 4, 4, 4))
	store := blocklist.NewStore()
	store.Replace([]string{"doubleclick.example.com"})
	counter := stats.New()
	log := &captureLogger{}
	h := NewHandler(store, counter, []string{upstream}, log, "zero", 60, nil, true, "drop")
	h.SetQueryLogMode("all")

	cases := []struct {
		sent, want string
		qtype      uint16
	}{
		{"DoubleClick.Example.COM.", "doubleclick.example.com.", dns.TypeA},
		{"WwW.Fresh.Example.", "www.fresh.example.", dns.TypeA},
		{"5.1.168.192.IN-ADDR.ARPA.", "5.1.168.192.in-addr.arpa.", dns.TypePTR},
	}
	for _, tc := range cases {
		w := fakeClient()
		req := new(dns.Msg)
		req.SetQuestion(tc.sent, tc.qtype)
		h.ServeDNS(w, req)
		if log.last.Domain != tc.want {
			t.Errorf("%s: query log domain = %q, want %q", tc.sent, log.last.Domain, tc.want)
		}
		if w.written == nil || len(w.written.Question) != 1 || w.written.Question[0].Name != tc.sent {
			t.Errorf("%s: reply question = %v, want the name as sent", tc.sent, w.written)
		}
	}
	// A second query in another case is the same domain in Top Domains.
	h.ServeDNS(fakeClient(), buildReq("DOUBLECLICK.example.com"))
	top := counter.Snapshot(10).TopDomains
	if len(top) != 1 || top[0].Name != "doubleclick.example.com." || top[0].Count != 2 {
		t.Errorf("top domains = %v, want one lowercase entry with count 2", top)
	}
}

func TestExchangeDoH_SendsFixedUserAgent(t *testing.T) {
	// D8: a DoH request sends "User-Agent: s-hole" and nothing that names
	// the Go version.
	var mu sync.Mutex
	var agents []string
	endpoint, _ := startDoHUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		agents = append(agents, r.Header.Get("User-Agent"))
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	_, _ = exchangeDoH(context.Background(), buildReq("example.com"), endpoint)
	mu.Lock()
	defer mu.Unlock()
	if len(agents) != 1 || agents[0] != "s-hole" {
		t.Errorf("User-Agent = %q, want [s-hole]", agents)
	}
}

func TestExchangeDoH_ErrorsHideURLSecrets(t *testing.T) {
	// D8: a DoH error names the upstream with its user info and query string
	// redacted (R1), for an HTTP status, a transport failure, and a bad body.
	status, _ := startDoHUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("mode") == "body" {
			w.Header().Set("Content-Type", dohMediaType)
			w.Write([]byte{0x01})
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	withSecrets := func(base, query string) string {
		return strings.Replace(base, "https://", "https://dohuser:dohpass@", 1) + "?token=dohtoken&" + query
	}
	// A closed port gives a transport failure.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "https://" + ln.Addr().String() + "/dns-query"
	ln.Close()

	for name, endpoint := range map[string]string{
		"status":    withSecrets(status, "mode=status"),
		"bad body":  withSecrets(status, "mode=body"),
		"transport": withSecrets(closed, "x=1"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := exchangeDoH(context.Background(), buildReq("secretname.example.com"), endpoint)
			if err == nil {
				t.Fatal("exchangeDoH = nil error, want a failure")
			}
			for _, secret := range []string{"dohuser", "dohpass", "dohtoken", "secretname"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q holds %q", err, secret)
				}
			}
			if !strings.Contains(err.Error(), "redacted") {
				t.Errorf("error %q does not show the redacted URL", err)
			}
		})
	}
}
