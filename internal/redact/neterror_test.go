package redact

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

// clientOpError is the error that a write to a client that is gone returns:
// its text holds the local and the remote socket address.
func clientOpError(err error) *net.OpError {
	return &net.OpError{
		Op:     "write",
		Net:    "tcp",
		Source: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 35987},
		Addr:   &net.TCPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 57082},
		Err:    err,
	}
}

// addressParts are the parts of the socket addresses in clientOpError and
// in the IPv6 case below. None of them may be in a NetError result.
var addressParts = []string{"127.0.0.1", "35987", "192.168.1.20", "57082", "2001:db8::77", "44444", "fe80::1"}

func assertNoAddress(t *testing.T, got string) {
	t.Helper()
	for _, p := range addressParts {
		if strings.Contains(got, p) {
			t.Errorf("NetError = %q, holds the address part %q", got, p)
		}
	}
}

// addrWrapper wraps a *net.OpError with a text that shows the addresses in
// another form than the OpError's own text.
type addrWrapper struct{ op *net.OpError }

func (w addrWrapper) Error() string {
	return "peer 192.168.1.20 port 57082 via 127.0.0.1 port 35987: " + w.op.Err.Error()
}
func (w addrWrapper) Unwrap() error { return w.op }

func TestNetError(t *testing.T) {
	// PRIV-04 (b/099, b/078): NetError keeps the operation and the underlying
	// error of a *net.OpError and drops the socket addresses, also when the
	// OpError is wrapped. Another error is returned as it is.
	reset := errors.New("connection reset by peer")
	v6 := &net.OpError{
		Op:     "read",
		Net:    "udp",
		Source: &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 53},
		Addr:   &net.UDPAddr{IP: net.ParseIP("2001:db8::77"), Port: 44444},
		Err:    errors.New("i/o timeout"),
	}
	cases := []struct {
		name string
		err  error
		want string // exact result; "" means check only the parts in keep
		keep []string
	}{
		{"bare OpError", clientOpError(reset), "write: connection reset by peer", nil},
		{"bare OpError, IPv6", v6, "read: i/o timeout", nil},
		{"wrapped OpError", fmt.Errorf("x: %w", clientOpError(reset)), "", []string{"write: connection reset by peer"}},
		{"twice wrapped OpError", fmt.Errorf("export: %w", fmt.Errorf("row 3: %w", v6)), "", []string{"read: i/o timeout"}},
		{"wrapper with the addresses in its own text", addrWrapper{clientOpError(reset)}, "", []string{"write: connection reset by peer"}},
		{"plain error", errors.New("http: request body too large"), "http: request body too large", nil},
		{"wrapped plain error", fmt.Errorf("x: %w", reset), "x: connection reset by peer", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NetError(tc.err)
			if tc.want != "" && got != tc.want {
				t.Errorf("NetError = %q, want %q", got, tc.want)
			}
			for _, k := range tc.keep {
				if !strings.Contains(got, k) {
					t.Errorf("NetError = %q, lacks %q", got, k)
				}
			}
			assertNoAddress(t, got)
		})
	}
}

func TestNetError_OpErrorWithNilErr(t *testing.T) {
	// PRIV-04: a *net.OpError with no underlying error gives the operation
	// without the addresses. Its own Error method dereferences Err, so
	// NetError must not call it on such a value. A panic here is reported as
	// a failure, so the other tests in the package still run.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NetError(OpError with nil Err) panicked: %v", r)
		}
	}()
	got := NetError(clientOpError(nil))
	if !strings.Contains(got, "write") {
		t.Errorf("NetError = %q, lacks the operation \"write\"", got)
	}
	assertNoAddress(t, got)
}
