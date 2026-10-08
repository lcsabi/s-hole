package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetrics_ForwardLimitedTotal(t *testing.T) {
	// SEC-12: /metrics has shole_forward_limited_total, a counter with the
	// value of the wired accessor (dnsserver.ForwardLimited). It is one
	// aggregate number, with no per-client or per-domain label. Without the
	// accessor the metric is not there.
	s, srv := newTestServer(t, nil)
	_, _, body := getRaw(t, srv.URL+"/metrics")
	if strings.Contains(string(body), "shole_forward_limited_total") {
		t.Error("shole_forward_limited_total is on /metrics without its accessor")
	}

	s.SetForwardLimited(func() uint64 { return 41 })
	srv2 := httptest.NewServer(s.handler())
	t.Cleanup(srv2.Close)
	_, _, body = getRaw(t, srv2.URL+"/metrics")
	text := string(body)
	if got := parseMetricValue(t, text, "shole_forward_limited_total"); got != 41 {
		t.Errorf("shole_forward_limited_total = %d, want 41", got)
	}
	if !strings.Contains(text, "# TYPE shole_forward_limited_total counter") {
		t.Error("shole_forward_limited_total has no counter TYPE line")
	}
	if strings.Contains(text, "shole_forward_limited_total{") {
		t.Error("shole_forward_limited_total has a label, want one aggregate number")
	}
}
