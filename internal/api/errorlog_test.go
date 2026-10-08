package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// PRIV-15 (b/103): net/http logs a handler panic ("http: panic serving
// <addr>: <value>" and a stack trace) and a TLS handshake error ("http: TLS
// handshake error from <addr>: ..."). The admin server's ErrorLog sends each
// line through the api logger at ERROR, as "admin HTTP server error" with the
// first line in "detail" and the stack trace in "stack", and replaces every
// IP address (with or without a port) with "client".

const errorLogMsg = "admin HTTP server error"

// captureDefaultJSONLogs routes slog's default handler to a JSON sink and
// restores it when the test ends. Unlike captureJSONLogs it keeps the package
// logger, so a record carries the pkg attribute that logging.For adds, and a
// line that net/http writes through the log package without an ErrorLog
// lands in the sink too (at INFO, with no pkg). Tests here do not run in
// parallel, so the swap of the global default is safe.
func captureDefaultJSONLogs(t *testing.T) *jsonRecords {
	t.Helper()
	j := &jsonRecords{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(j, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return j
}

// errorLogLine writes one net/http style line through the admin server's
// ErrorLog and returns the one record it produced.
func errorLogLine(t *testing.T, logs *jsonRecords, format string, args ...any) map[string]any {
	t.Helper()
	before := len(logs.records(t))
	newErrorLog().Printf(format, args...)
	recs := logs.records(t)[before:]
	if len(recs) != 1 {
		t.Fatalf("ErrorLog wrote %d records for one line, want 1: %v", len(recs), recs)
	}
	return recs[0]
}

// assertErrorRecord checks the level, the pkg, and the message of a record
// from the ErrorLog.
func assertErrorRecord(t *testing.T, r map[string]any) {
	t.Helper()
	if r["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR (record %v)", r["level"], r)
	}
	if r["pkg"] != "api" {
		t.Errorf("pkg = %v, want api (record %v)", r["pkg"], r)
	}
	if r["msg"] != errorLogMsg {
		t.Errorf("msg = %v, want %q (record %v)", r["msg"], errorLogMsg, r)
	}
}

// fakeStack is the shape of the stack trace that net/http appends to a
// panic line: function names, file:line, and hex offsets and pointers.
const fakeStack = "goroutine 42 [running]:\n" +
	"net/http.(*conn).serve.func1()\n" +
	"\t/usr/local/go/src/net/http/server.go:1908 +0xbe\n" +
	"panic({0x8a6e20?, 0xc000123456?})\n" +
	"\t/usr/local/go/src/runtime/panic.go:791 +0x132\n"

func TestErrorLog_PanicLineAddressForms(t *testing.T) {
	// PRIV-15: the panic line names the requester in net.JoinHostPort form.
	// Every form becomes "client": IPv4 (LAN, public, loopback), IPv6,
	// IPv4-mapped IPv6, and IPv6 with a zone.
	logs := captureDefaultJSONLogs(t)
	addrs := []struct{ addr, port string }{
		{"192.168.1.20:57082", "57082"},
		{"10.0.0.7:1024", "1024"},
		{"203.0.113.9:443", "443"},
		{"127.0.0.1:40000", "40000"},
		{"[2001:db8::1]:5678", "5678"},
		{"[2001:db8:85a3::8a2e:370:7334]:61000", "61000"},
		{"[fd00:1:2:3::42]:51515", "51515"},
		{"[::1]:39999", "39999"},
		{"[::ffff:192.168.1.20]:5678", "5678"},
		{"[fe80::1%eth0]:5678", "5678"},
		{"[fe80::abcd:ef01%wlan0]:6000", "6000"},
	}
	for _, a := range addrs {
		r := errorLogLine(t, logs, "http: panic serving %s: %v\n%s", a.addr, "boom", fakeStack)
		assertErrorRecord(t, r)
		assertNoAddressIn(t, r, a.port, "eth0", "wlan0")
		if got, want := r["detail"], "http: panic serving client: boom"; got != want {
			t.Errorf("%s: detail = %q, want %q", a.addr, got, want)
		}
		stack, _ := r["stack"].(string)
		for _, keep := range []string{"goroutine 42 [running]:", "net/http.(*conn).serve.func1()",
			"server.go:1908 +0xbe", "0xc000123456"} {
			if !strings.Contains(stack, keep) {
				t.Errorf("%s: stack %q lost %q", a.addr, stack, keep)
			}
		}
		if d, _ := r["detail"].(string); strings.Contains(d, "goroutine") {
			t.Errorf("%s: detail %q holds the stack trace", a.addr, d)
		}
	}
}

func TestErrorLog_TLSHandshakeLine(t *testing.T) {
	// PRIV-15: the TLS handshake line has the same shape, with no stack.
	logs := captureDefaultJSONLogs(t)
	cases := []struct{ addr, port string }{
		{"192.168.1.20:57082", "57082"},
		{"[2001:db8::1]:5678", "5678"},
		{"[fe80::1%eth0]:5678", "5678"},
	}
	for _, c := range cases {
		r := errorLogLine(t, logs, "http: TLS handshake error from %s: remote error: tls: bad certificate", c.addr)
		assertErrorRecord(t, r)
		assertNoAddressIn(t, r, c.port, "eth0")
		if got, want := r["detail"], "http: TLS handshake error from client: remote error: tls: bad certificate"; got != want {
			t.Errorf("%s: detail = %q, want %q", c.addr, got, want)
		}
	}
}

func TestErrorLog_BareAddressesInPanicValue(t *testing.T) {
	// PRIV-15: a panic value can hold a bare IP address without a port. It
	// is replaced too: IPv4, IPv6, IPv6 loopback, IPv4-mapped, and zoned.
	logs := captureDefaultJSONLogs(t)
	cases := []struct{ value, want string }{
		{"bad peer 192.168.1.20", "bad peer client"},
		{"bad peer 2001:db8::1", "bad peer client"},
		{"bad peer 2001:db8:85a3::8a2e:370:7334 again", "bad peer client again"},
		{"bad peer ::1", "bad peer client"},
		{"bad peer ::ffff:192.168.1.20", "bad peer client"},
		{"bad peer fe80::1%eth0", "bad peer client"},
		{"peers 192.168.1.20 and 2001:db8::2", "peers client and client"},
		{"peer=10.1.2.3,", "peer=client,"},
		{"(192.168.1.20)", "(client)"},
	}
	for _, c := range cases {
		r := errorLogLine(t, logs, "http: panic serving %s: %s\n%s", "192.168.1.20:57082", c.value, fakeStack)
		assertErrorRecord(t, r)
		assertNoAddressIn(t, r, "57082", "eth0")
		if got, want := r["detail"], "http: panic serving client: "+c.want; got != want {
			t.Errorf("value %q: detail = %q, want %q", c.value, got, want)
		}
	}
}

func TestErrorLog_BareIPv6BeforeColon(t *testing.T) {
	// PRIV-15: a bare IPv6 address followed by ": " (the common
	// "<addr>: <reason>" form of an error text) is replaced too.
	logs := captureDefaultJSONLogs(t)
	for _, addr := range []string{"2001:db8::1", "fd00::42", "::ffff:192.168.1.20", "192.168.1.20"} {
		r := errorLogLine(t, logs, "http: panic serving %s: dial %s: connection refused", "[2001:db8::9]:5678", addr)
		assertErrorRecord(t, r)
		assertNoAddressIn(t, r, "5678")
		if got, want := r["detail"], "http: panic serving client: dial client: connection refused"; got != want {
			t.Errorf("%s: detail = %q, want %q", addr, got, want)
		}
	}
}

func TestErrorLog_BareIPv6AfterColon(t *testing.T) {
	// PRIV-15: a bare IPv6 address right after a colon of the surrounding
	// text ("from:<addr>") is replaced too, and the colon stays.
	logs := captureDefaultJSONLogs(t)
	for _, addr := range []string{"2001:db8::1", "fd00::42", "::ffff:192.168.1.20"} {
		r := errorLogLine(t, logs, "http: panic serving %s: bad peer from:%s", "192.168.1.20:57082", addr)
		assertNoAddressIn(t, r, "57082")
		if got, want := r["detail"], "http: panic serving client: bad peer from:client"; got != want {
			t.Errorf("%s: detail = %q, want %q", addr, got, want)
		}
	}
}

func TestErrorLog_KeepsTextThatIsNotAnAddress(t *testing.T) {
	// PRIV-15: text that is not an IP address stays: a time of day, a
	// file:line, hex pointers and offsets, a MAC address, a version.
	logs := captureDefaultJSONLogs(t)
	values := []string{
		"at 12:34:56",
		"at 12:34:56.789",
		"in server.go:1908",
		"ptr 0xc000123456 +0x1a5",
		"mac 00:1a:2b:3c:4d:5e",
		"version 1.2.3",
		"ratio 3:2",
		"key=value: ok",
	}
	for _, v := range values {
		r := errorLogLine(t, logs, "http: panic serving %s: %s\n%s", "192.168.1.20:57082", v, fakeStack)
		if got, want := r["detail"], "http: panic serving client: "+v; got != want {
			t.Errorf("value %q: detail = %q, want %q", v, got, want)
		}
	}
	// A line without an address stays whole.
	r := errorLogLine(t, logs, "http: Accept error: accept tcp: too many open files; retrying in 5ms")
	assertErrorRecord(t, r)
	if got, want := r["detail"], "http: Accept error: accept tcp: too many open files; retrying in 5ms"; got != want {
		t.Errorf("detail = %q, want %q", got, want)
	}
}

// panicServer starts the admin server through Serve on a listener at
// listenAddr, with /api/stats wired to panic with the value that value
// returns. It returns the base URL; the server shuts down when the test ends.
func panicServer(t *testing.T, listenAddr string, value func() any) (*Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Skipf("listen %s: %v", listenAddr, err)
	}
	s, _, _ := secServer(t)
	s.SetWarnings(func() []string { panic(value()) })
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.Shutdown(ctx)
		<-done
	})
	return s, "http://" + ln.Addr().String()
}

// getRecordingPort sends GET url and returns the client's local port. The
// handler panics, so the request fails; the error does not matter.
func getRecordingPort(t *testing.T, url string) string {
	t.Helper()
	var local string
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err == nil {
				_, local, _ = net.SplitHostPort(c.LocalAddr().String())
			}
			return c, err
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if local == "" {
		t.Fatalf("GET %s: no connection (%v)", url, err)
	}
	return local
}

// waitForMsg polls logs until a record with msg appears, or fails after 2 s.
func waitForMsg(t *testing.T, logs *jsonRecords, msg string) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if recs := logs.withMsg(t, msg); len(recs) > 0 {
			return recs
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %q record after 2 s; records: %v", msg, logs.records(t))
	return nil
}

func TestErrorLog_HandlerPanicLogsNoAddress(t *testing.T) {
	// PRIV-15 acceptance: a handler that panics on the server that Serve
	// builds produces one record at ERROR with pkg=api, and no attribute
	// holds the requester's IP address or port. IPv4 and IPv6 requesters
	// (loopback here; the writer tests cover the LAN forms). The stack trace
	// stays.
	for _, listen := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(listen, func(t *testing.T) {
			logs := captureDefaultJSONLogs(t)
			_, base := panicServer(t, listen, func() any { return "boom from the handler" })
			port := getRecordingPort(t, base+"/api/stats")
			recs := waitForMsg(t, logs, errorLogMsg)
			if len(recs) != 1 {
				t.Fatalf("got %d %q records, want 1: %v", len(recs), errorLogMsg, recs)
			}
			r := recs[0]
			assertErrorRecord(t, r)
			// The stack holds hex pointers, which can hold the port's digits by
			// chance, so the bare port is checked in detail only.
			assertNoAddressIn(t, r, ":"+port)
			if d, _ := r["detail"].(string); d != "http: panic serving client: boom from the handler" {
				t.Errorf("detail = %q, want the panic line with the address replaced", d)
			}
			if st, _ := r["stack"].(string); !strings.Contains(st, "goroutine") || !strings.Contains(st, "net/http") {
				t.Errorf("stack = %.200q, want the stack trace", st)
			}
			// Nothing from net/http reached the log another way (through the
			// log package at INFO, with no pkg).
			for _, other := range logs.records(t) {
				if other["msg"] == errorLogMsg {
					continue
				}
				if strings.Contains(fmt.Sprint(other), "panic") || strings.Contains(fmt.Sprint(other), ":"+port) {
					t.Errorf("another record names the panic or the client: %v", other)
				}
			}
		})
	}
}

func TestErrorLog_AbortHandlerSilent(t *testing.T) {
	// PRIV-15: a handler that panics with http.ErrAbortHandler writes no
	// record. A later ordinary panic does, so the capture works.
	logs := captureDefaultJSONLogs(t)
	var calls atomic.Int32
	_, base := panicServer(t, "127.0.0.1:0", func() any {
		if calls.Add(1) == 1 {
			return http.ErrAbortHandler
		}
		return "second"
	})
	getRecordingPort(t, base+"/api/stats")
	// net/http logs a panic before it closes the connection, so the failed
	// request above means any record for it is already written.
	if recs := logs.withMsg(t, errorLogMsg); len(recs) != 0 {
		t.Errorf("http.ErrAbortHandler wrote %d records: %v", len(recs), recs)
	}
	getRecordingPort(t, base+"/api/stats")
	recs := waitForMsg(t, logs, errorLogMsg)
	if len(recs) != 1 {
		t.Errorf("got %d records, want 1 (only the ordinary panic): %v", len(recs), recs)
	}
	for _, r := range logs.records(t) {
		if strings.Contains(fmt.Sprint(r), "abort Handler") {
			t.Errorf("a record names http.ErrAbortHandler: %v", r)
		}
	}
}

func TestErrorLog_ServeWiresIt(t *testing.T) {
	// PRIV-15: the http.Server that Serve builds has an ErrorLog, and a line
	// written to it is redacted.
	logs := captureDefaultJSONLogs(t)
	s, _ := panicServer(t, "127.0.0.1:0", func() any { return "unused" })
	var hs *http.Server
	deadline := time.Now().Add(2 * time.Second)
	for hs == nil && time.Now().Before(deadline) {
		hs = s.httpServer.Load()
		time.Sleep(5 * time.Millisecond)
	}
	if hs == nil {
		t.Fatal("Serve stored no http.Server")
	}
	if hs.ErrorLog == nil {
		t.Fatal("the admin http.Server has no ErrorLog")
	}
	hs.ErrorLog.Printf("http: TLS handshake error from %s: EOF", net.JoinHostPort("192.168.1.20", strconv.Itoa(57082)))
	recs := waitForMsg(t, logs, errorLogMsg)
	assertErrorRecord(t, recs[0])
	assertNoAddressIn(t, recs[0], "57082")
}
