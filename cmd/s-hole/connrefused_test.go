package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// The b/094 tests that run on every platform: s-hole -purge goes offline
// only when the connection to the admin address is refused.

func TestConnRefused_DialToClosedPort(t *testing.T) {
	// b/094: a dial to a local port where nothing listens counts as refused
	// on every platform (WSAECONNREFUSED on Windows, ECONNREFUSED elsewhere),
	// also inside the *url.Error and fmt.Errorf wrappers that callers add.
	addr := closedAddr(t)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err == nil {
		conn.Close()
		t.Fatalf("dial to the closed port %s succeeded", addr)
	}
	if !connRefused(err) {
		t.Errorf("connRefused(%v) = false, want true", err)
	}
	wrapped := &url.Error{Op: "Post", URL: "http://" + addr + "/api/purge", Err: err}
	if !connRefused(wrapped) {
		t.Errorf("connRefused(%v) = false, want true", wrapped)
	}
	if e := fmt.Errorf("purge: %w", err); !connRefused(e) {
		t.Errorf("connRefused(%v) = false, want true", e)
	}
}

func TestConnRefused_OtherErrorsAreNotRefused(t *testing.T) {
	// b/094: only a refused connection counts. nil, a generic error (even
	// one whose text says "connection refused"), a timeout, and a DNS error
	// do not, so -purge does not delete files behind an s-hole that may run.
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, dialTimeout := (&net.Dialer{}).DialContext(expired, "tcp", closedAddr(t))
	if dialTimeout == nil {
		t.Fatal("a dial with an expired deadline succeeded")
	}
	dnsErr := &net.DNSError{Err: "no such host", Name: "s-hole.invalid", IsNotFound: true}

	cases := map[string]error{
		"nil":                     nil,
		"generic":                 errors.New("boom"),
		"generic, refused text":   errors.New("dial tcp 127.0.0.1:8080: connect: connection refused"),
		"dial timeout":            dialTimeout,
		"deadline in OpError":     &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded},
		"client timeout":          &url.Error{Op: "Post", URL: "http://127.0.0.1:8080/api/purge", Err: context.DeadlineExceeded},
		"DNS error":               dnsErr,
		"DNS error in OpError":    &net.OpError{Op: "dial", Net: "tcp", Err: dnsErr},
		"DNS error in url.Error":  &url.Error{Op: "Post", URL: "http://s-hole.invalid:8080/api/purge", Err: &net.OpError{Op: "dial", Net: "tcp", Err: dnsErr}},
		"context canceled":        context.Canceled,
		"errNotRunning sentinel":  errNotRunning,
		"wrapped generic":         fmt.Errorf("post: %w", errors.New("EOF")),
		"OpError, generic inside": &net.OpError{Op: "read", Net: "tcp", Err: errors.New("unexpected EOF")},
	}
	for name, err := range cases {
		if connRefused(err) {
			t.Errorf("%s: connRefused(%v) = true, want false", name, err)
		}
	}
}

func TestPurgeViaAPI_ClosedPortIsNotRunning(t *testing.T) {
	// b/094: a refused connection to the admin address is errNotRunning on
	// every platform, so runPurge purges offline.
	if _, err := purgeViaAPI(closedAddr(t)); !errors.Is(err, errNotRunning) {
		t.Errorf("purgeViaAPI(closed port) = %v, want errNotRunning", err)
	}
}

func TestRunPurge_ClosedAdminPortPurgesOffline(t *testing.T) {
	// b/094: with nothing on the admin address, -purge deletes the files
	// itself and exits 0. Before the fix, Windows exited 1 here with
	// "purge failed ... actively refused it" and deleted nothing.
	clearSholeEnv(t)
	cfgPath, paths, _ := storedFiles(t, closedAddr(t), "q.log")
	var j jsonLog
	var code int
	out := captureStdout(t, func() { code = runPurge(j.logger(), cfgPath) })
	if code != 0 || !strings.Contains(out, "not running") {
		t.Fatalf("exit %d, output %q; want 0 and the offline purge\n%s", code, out, j.buf.String())
	}
	if n := j.count(t, "ERROR", "purge failed"); n != 0 {
		t.Errorf("got %d purge failed lines, want 0", n)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists after the offline purge", p)
		}
	}
}

func TestRunPurge_OtherConnectionErrorDoesNotPurgeOffline(t *testing.T) {
	// b/094: a connection error that is not a refusal (here, the admin
	// address accepts and closes the connection at once) is not "s-hole is
	// not running". -purge fails with exit 1 and deletes nothing, because an
	// s-hole may still run and hold the files.
	clearSholeEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	if _, err := purgeViaAPI(ln.Addr().String()); err == nil || errors.Is(err, errNotRunning) {
		t.Errorf("purgeViaAPI(closing listener) = %v, want an error other than errNotRunning", err)
	}

	cfgPath, paths, _ := storedFiles(t, ln.Addr().String(), "q.log")
	var j jsonLog
	var code int
	out := captureStdout(t, func() { code = runPurge(j.logger(), cfgPath) })
	if code != 1 || j.count(t, "ERROR", "purge failed") != 1 {
		t.Errorf("exit %d; want 1 with a purge failed ERROR\n%s\n%s", code, out, j.buf.String())
	}
	if strings.Contains(out, "not running") {
		t.Errorf("output says s-hole is not running:\n%s", out)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was deleted although the connection was not refused: %v", p, err)
		}
	}
}
