package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/stats"
)

// dotTestServer returns a server whose DoT status accessor reports st, or no
// accessor at all (DoT off) when st is nil.
func dotTestServer(t *testing.T, st *DoTStatus) *httptest.Server {
	t.Helper()
	s := New(stats.New(), nil, blocklist.NewStore(), nil, func() bool { return true })
	if st != nil {
		s.SetDoTStatus(func() DoTStatus { return *st })
	}
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return srv
}

func getBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func TestHandleStats_DoTOffReportsDisabled(t *testing.T) {
	var got struct {
		DoT map[string]any `json:"dot"`
	}
	if err := json.Unmarshal([]byte(getBody(t, dotTestServer(t, nil).URL+"/api/stats")), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.DoT) != 1 || got.DoT["enabled"] != false {
		t.Errorf(`dot = %v, want exactly {"enabled": false}`, got.DoT)
	}
}

func TestHandleStats_DoTOnReportsCertificate(t *testing.T) {
	// The dashboard badge reads these fields. expires_in_days is computed on
	// the server, so the browser clock does not matter.
	notAfter := time.Now().Add(10*24*time.Hour + time.Hour)
	st := &DoTStatus{
		Listen:          ":853",
		Names:           []string{"dns.home", "192.168.1.10"},
		NotAfter:        notAfter,
		State:           "expiring",
		LastReload:      time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC),
		LastReloadError: "",
	}
	var got struct {
		DoT dotResponse `json:"dot"`
	}
	if err := json.Unmarshal([]byte(getBody(t, dotTestServer(t, st).URL+"/api/stats")), &got); err != nil {
		t.Fatal(err)
	}
	d := got.DoT
	if !d.Enabled || d.Listen != ":853" || d.State != "expiring" {
		t.Errorf("dot = %+v, want enabled, :853, expiring", d)
	}
	if len(d.Names) != 2 || d.Names[0] != "dns.home" {
		t.Errorf("names = %v, want [dns.home 192.168.1.10]", d.Names)
	}
	if d.ExpiresInDays == nil || *d.ExpiresInDays != 10 {
		t.Errorf("expires_in_days = %v, want 10", d.ExpiresInDays)
	}
	if d.NotAfter != notAfter.UTC().Format(time.RFC3339) {
		t.Errorf("not_after = %q, want RFC3339 UTC of the expiry", d.NotAfter)
	}
	if d.LastReload != "2026-09-23T08:00:00Z" {
		t.Errorf("last_reload = %q, want 2026-09-23T08:00:00Z", d.LastReload)
	}
}

func TestHandleStats_DoTExpiredHasNegativeDays(t *testing.T) {
	st := &DoTStatus{NotAfter: time.Now().Add(-49 * time.Hour), State: "expired", LastReloadError: "tls: bad pem"}
	var got struct {
		DoT dotResponse `json:"dot"`
	}
	if err := json.Unmarshal([]byte(getBody(t, dotTestServer(t, st).URL+"/api/stats")), &got); err != nil {
		t.Fatal(err)
	}
	if got.DoT.ExpiresInDays == nil || *got.DoT.ExpiresInDays != -3 {
		t.Errorf("expires_in_days = %v, want -3 (floor of -2.04 days)", got.DoT.ExpiresInDays)
	}
	if got.DoT.LastReloadError != "tls: bad pem" || got.DoT.LastReload != "" {
		t.Errorf("dot = %+v, want the error echoed and no last_reload", got.DoT)
	}
}

func TestMetricsEndpoint_DoTMetricsWhenOn(t *testing.T) {
	st := &DoTStatus{NotAfter: time.Unix(1_800_000_000, 0), ReloadFailures: 3}
	body := getBody(t, dotTestServer(t, st).URL+"/metrics")
	for _, w := range []string{
		"# TYPE shole_dot_certificate_expiry_timestamp_seconds gauge",
		"shole_dot_certificate_expiry_timestamp_seconds 1800000000",
		"# TYPE shole_dot_certificate_reload_failures_total counter",
		"shole_dot_certificate_reload_failures_total 3",
	} {
		if !strings.Contains(body, w) {
			t.Errorf("metrics body missing %q\nfull body:\n%s", w, body)
		}
	}
}

func TestMetricsEndpoint_NoDoTMetricsWhenOff(t *testing.T) {
	if body := getBody(t, dotTestServer(t, nil).URL+"/metrics"); strings.Contains(body, "shole_dot_") {
		t.Errorf("DoT metrics present with DoT off:\n%s", body)
	}
}
