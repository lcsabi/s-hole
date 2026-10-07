package api

import (
	"strings"
	"testing"
)

func TestMetrics_LocalNamesTotal(t *testing.T) {
	// CL 94 R9: /metrics has shole_local_names_total with the counter value.
	// It is one aggregate number, with no per-domain or per-client label.
	s, srv := newTestServer(t, nil)
	for i := 0; i < 3; i++ {
		s.counter.RecordQuery("", "", false)
		s.counter.RecordLocalName()
	}
	_, _, body := getRaw(t, srv.URL+"/metrics")
	if got := parseMetricValue(t, string(body), "shole_local_names_total"); got != 3 {
		t.Errorf("shole_local_names_total = %d, want 3", got)
	}
	if strings.Contains(string(body), "shole_local_names_total{") {
		t.Error("shole_local_names_total has a label, want one aggregate number")
	}
}
