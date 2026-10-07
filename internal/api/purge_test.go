package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/stats"
)

// purgeServer returns a handler with a purge function that counts its calls
// and returns rep.
func purgeServer(t *testing.T, rep *PurgeReport) (http.Handler, *atomic.Int64) {
	t.Helper()
	s := New(stats.New(), nil, blocklist.NewStore(), nil, func() bool { return true })
	calls := new(atomic.Int64)
	if rep != nil {
		s.SetPurge(func(ctx context.Context) PurgeReport {
			calls.Add(1)
			if _, ok := ctx.Deadline(); !ok {
				t.Error("the purge function got a context without a deadline")
			}
			return *rep
		})
	}
	return s.handler(), calls
}

func purgeReq(h http.Handler, remote, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/purge", strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.RemoteAddr = remote
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ownAddress returns a non-loopback address of this host, or "" if it has
// none.
func ownAddress(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			return n.IP.String()
		}
	}
	return ""
}

// foreignAddress returns an address that is not one of this host's.
func foreignAddress(t *testing.T) string {
	t.Helper()
	own := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				own[n.IP.String()] = true
			}
		}
	}
	for _, c := range []string{"198.51.100.77", "203.0.113.77", "192.0.2.77"} {
		if !own[c] {
			return c
		}
	}
	t.Skip("every test address belongs to this host")
	return ""
}

func TestPurge_OnlyFromThisMachine(t *testing.T) {
	// A5: POST /api/purge is refused with 403 unless the remote address is a
	// loopback address or one of the host's own addresses. A device on the
	// LAN cannot wipe the history.
	rep := &PurgeReport{Steps: []PurgeStep{{What: "query database", Result: "deleted"}}}
	allowed := []string{"127.0.0.1:5000", "127.8.9.10:5000", "[::1]:5000", "[::ffff:127.0.0.1]:5000"}
	if own := ownAddress(t); own != "" {
		allowed = append(allowed, net.JoinHostPort(own, "5000"))
		if ip := net.ParseIP(own); ip.To4() != nil {
			// The same address as an IPv4-mapped IPv6 source (a dual-stack
			// listener reports it like this).
			allowed = append(allowed, net.JoinHostPort("::ffff:"+own, "5000"))
		}
	}
	for _, remote := range allowed {
		h, calls := purgeServer(t, rep)
		if rec := purgeReq(h, remote, "application/json", `{"confirm": true}`); rec.Code != http.StatusOK || calls.Load() != 1 {
			t.Errorf("remote %s: status %d, purge calls %d; want 200 and 1", remote, rec.Code, calls.Load())
		}
	}
	foreign := foreignAddress(t)
	for _, remote := range []string{net.JoinHostPort(foreign, "5000"), "[2001:db8::77]:5000", "not-an-address"} {
		h, calls := purgeServer(t, rep)
		rec := purgeReq(h, remote, "application/json", `{"confirm": true}`)
		if rec.Code != http.StatusForbidden || calls.Load() != 0 {
			t.Errorf("remote %s: status %d, purge calls %d; want 403 and 0", remote, rec.Code, calls.Load())
		}
		if !strings.Contains(rec.Body.String(), "-purge") {
			t.Errorf("remote %s: 403 body = %q, want it to name s-hole -purge", remote, rec.Body.String())
		}
		// The address check comes first: a foreign request is 403 even
		// without JSON.
		if rec := purgeReq(h, remote, "text/plain", "x"); rec.Code != http.StatusForbidden {
			t.Errorf("remote %s without JSON: status %d, want 403", remote, rec.Code)
		}
	}
}

func TestPurge_RequestChecks(t *testing.T) {
	// A5: 415 without JSON, 400 unless the body is {"confirm": true}, 503
	// when no purge function is wired. None of them runs the purge.
	rep := &PurgeReport{Steps: []PurgeStep{{What: "x", Result: "y"}}}
	cases := []struct {
		name, ct, body string
		want           int
	}{
		{"no content type", "", `{"confirm": true}`, http.StatusUnsupportedMediaType},
		{"text/plain", "text/plain", `{"confirm": true}`, http.StatusUnsupportedMediaType},
		{"form", "application/x-www-form-urlencoded", "confirm=true", http.StatusUnsupportedMediaType},
		{"empty body", "application/json", "", http.StatusBadRequest},
		{"empty object", "application/json", `{}`, http.StatusBadRequest},
		{"confirm false", "application/json", `{"confirm": false}`, http.StatusBadRequest},
		{"confirm string", "application/json", `{"confirm": "true"}`, http.StatusBadRequest},
		{"not JSON", "application/json", `confirm`, http.StatusBadRequest},
		{"confirm true with charset", "application/json; charset=utf-8", `{"confirm": true}`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, calls := purgeServer(t, rep)
			rec := purgeReq(h, "127.0.0.1:5000", tc.ct, tc.body)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			wantCalls := int64(0)
			if tc.want == http.StatusOK {
				wantCalls = 1
			}
			if calls.Load() != wantCalls {
				t.Errorf("purge ran %d times, want %d", calls.Load(), wantCalls)
			}
		})
	}
	h, _ := purgeServer(t, nil)
	if rec := purgeReq(h, "127.0.0.1:5000", "application/json", `{"confirm": true}`); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no purge function: status %d, want 503", rec.Code)
	}
}

func TestPurge_ReturnsTheReport(t *testing.T) {
	// A5: the reply is the PurgeReport as JSON, with 500 when a step failed.
	ok := &PurgeReport{Steps: []PurgeStep{
		{What: "query database", Result: "every row deleted"},
		{What: "DNS response cache", Result: "emptied"},
	}}
	failed := &PurgeReport{Steps: []PurgeStep{
		{What: "query database", Result: "delete failed: disk", Failed: true},
		{What: "DNS response cache", Result: "emptied"},
	}}
	for name, tc := range map[string]struct {
		rep  *PurgeReport
		want int
	}{"ok": {ok, http.StatusOK}, "failed step": {failed, http.StatusInternalServerError}} {
		t.Run(name, func(t *testing.T) {
			h, _ := purgeServer(t, tc.rep)
			rec := purgeReq(h, "127.0.0.1:5000", "application/json", `{"confirm": true}`)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			var got PurgeReport
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("body %q is not a report: %v", rec.Body.String(), err)
			}
			if !reflect.DeepEqual(got, *tc.rep) {
				t.Errorf("report = %+v, want %+v", got, *tc.rep)
			}
		})
	}
}

func TestPurgeReport_Failed(t *testing.T) {
	if (PurgeReport{}).Failed() {
		t.Error("an empty report failed")
	}
	if (PurgeReport{Steps: []PurgeStep{{What: "a"}, {What: "b"}}}).Failed() {
		t.Error("a report without a failed step failed")
	}
	if !(PurgeReport{Steps: []PurgeStep{{What: "a"}, {What: "b", Failed: true}}}).Failed() {
		t.Error("a report with a failed step did not fail")
	}
}

func TestPurge_OverARealConnection(t *testing.T) {
	// A5 end to end: a request from this machine over TCP reaches the purge.
	s := New(stats.New(), nil, blocklist.NewStore(), nil, func() bool { return true })
	var calls atomic.Int64
	s.SetPurge(func(context.Context) PurgeReport {
		calls.Add(1)
		return PurgeReport{Steps: []PurgeStep{{What: "x", Result: "y"}}}
	})
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(srv.URL+"/api/purge", "application/json", strings.NewReader(`{"confirm": true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || calls.Load() != 1 {
		t.Errorf("status %d, purge calls %d; want 200 and 1", resp.StatusCode, calls.Load())
	}
}
