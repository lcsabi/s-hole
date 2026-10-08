package stats

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// recordActivity records 29 queries with a distinct count for each kind: 5
// blocked, 2 local PTR, 3 local names, 4 cache hits, 6 forward failures, and
// 7 upstream errors. The other 2 are plain forwarded queries.
func recordActivity(c *Counter) {
	for i := 0; i < 5; i++ {
		c.RecordQuery("192.168.1.5", "ads.example.com.", true)
	}
	for i := 0; i < 2; i++ {
		c.RecordQuery("192.168.1.5", "5.1.168.192.in-addr.arpa.", false)
		c.RecordLocalPTR()
	}
	for i := 0; i < 3; i++ {
		c.RecordQuery("192.168.1.5", "nas.home.arpa.", false)
		c.RecordLocalName()
	}
	for i := 0; i < 4; i++ {
		c.RecordQuery("192.168.1.6", "cached.example.com.", false)
		c.RecordCacheHit()
	}
	for i := 0; i < 6; i++ {
		c.RecordQuery("192.168.1.6", "dead.example.com.", false)
		c.RecordForwardFailure()
	}
	for i := 0; i < 7; i++ {
		c.RecordQuery("192.168.1.6", "bad.example.com.", false)
		c.RecordUpstreamError()
	}
	for i := 0; i < 2; i++ {
		c.RecordQuery("192.168.1.6", "ok.example.com.", false)
	}
}

func TestCounter_LogHoldsNoCounts(t *testing.T) {
	// PRIV-01 (b/098): the periodic stats line holds the uptime and no query
	// count. The difference between two lines would give the queries in each
	// interval. The line is the same under every query_log.mode, the default
	// (mode never set) included. The counts stay in Snapshot.
	for _, mode := range []string{"", "none", "blocked", "all"} {
		t.Run("mode="+mode, func(t *testing.T) {
			orig := slog.Default()
			t.Cleanup(func() { slog.SetDefault(orig) })
			var buf bytes.Buffer
			slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

			c := New()
			if mode != "" {
				c.SetQueryLogMode(mode)
			}
			recordActivity(c)
			c.Log()

			lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
			if len(lines) != 1 || lines[0] == "" {
				t.Fatalf("Log wrote %d records, want 1: %q", len(lines), buf.String())
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
				t.Fatalf("record is not JSON: %q: %v", lines[0], err)
			}
			if rec["msg"] != "stats" || rec["level"] != "INFO" {
				t.Errorf("record = %v, want an INFO line with msg stats", rec)
			}
			uptime, ok := rec["uptime"].(string)
			if !ok {
				t.Fatalf("uptime = %#v, want a duration string", rec["uptime"])
			}
			if _, err := time.ParseDuration(uptime); err != nil {
				t.Errorf("uptime = %q, want a duration string: %v", uptime, err)
			}
			for k, v := range rec {
				switch k {
				case "time", "level", "msg", "pkg", "uptime":
				default:
					t.Errorf("stats line has attribute %s = %v, want only the uptime", k, v)
				}
			}

			// The counts are still on the dashboard.
			s := c.Snapshot(0)
			if s.TotalQueries != 29 || s.BlockedCount != 5 || s.CacheHits != 4 || s.ForwardFailures != 6 || s.UpstreamErrors != 7 {
				t.Errorf("snapshot = %+v, want the counts kept", s)
			}
		})
	}
}

func TestTimeline_FollowsQueryLogMode(t *testing.T) {
	// PRIV-09: the per-minute graph records nothing under "none", when the
	// mode is never set, and for an unknown value; blocked queries only under
	// "blocked" (no cache hits or failures, which are allowed queries); and
	// every query under "all". The since-start counters count every query in
	// every mode.
	cases := []struct {
		name      string
		mode      string
		set       bool
		wantMode  string
		wantGraph TimelineBucket
	}{
		{"unset", "", false, "none", TimelineBucket{}},
		{"none", "none", true, "none", TimelineBucket{}},
		{"empty", "", true, "none", TimelineBucket{}},
		{"unknown", "everything", true, "none", TimelineBucket{}},
		{"blocked", "blocked", true, "blocked", TimelineBucket{Total: 2, Blocked: 2}},
		{"all", "all", true, "all", TimelineBucket{Total: 5, Blocked: 2, Cached: 1, Unresolved: 1, UpstreamError: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New()
			if tc.set {
				c.SetQueryLogMode(tc.mode)
			}
			c.RecordQuery("192.168.1.5", "ads.example.com.", true)
			c.RecordQuery("192.168.1.5", "ads.example.com.", true)
			c.RecordQuery("192.168.1.5", "cached.example.com.", false)
			c.RecordCacheHit()
			c.RecordQuery("192.168.1.5", "dead.example.com.", false)
			c.RecordForwardFailure()
			c.RecordQuery("192.168.1.5", "bad.example.com.", false)
			c.RecordUpstreamError()

			if got := c.GraphMode(); got != tc.wantMode {
				t.Errorf("GraphMode = %q, want %q", got, tc.wantMode)
			}
			series := c.Timeline(time.Hour, time.Minute, time.Now())
			if len(series) != 60 {
				t.Fatalf("series has %d buckets, want 60 (a dense series in every mode)", len(series))
			}
			got := sumTimeline(series)
			got.Start = 0
			if got != tc.wantGraph {
				t.Errorf("graph counts = %+v, want %+v", got, tc.wantGraph)
			}
			s := c.Snapshot(0)
			if s.TotalQueries != 5 || s.BlockedCount != 2 || s.CacheHits != 1 || s.ForwardFailures != 1 || s.UpstreamErrors != 1 {
				t.Errorf("counters = %+v, want {total 5, blocked 2, cache 1, failures 1, upstream errors 1} in every mode", s)
			}
		})
	}
}

func TestResetTimeline_BlockedMode(t *testing.T) {
	// PRIV-09: a purge clears the graph under "blocked" too, and the graph
	// records new blocked queries after it.
	c := New()
	c.SetQueryLogMode("blocked")
	for i := 0; i < 3; i++ {
		c.RecordQuery("", "", true)
	}
	if got := sumTimeline(c.Timeline(time.Hour, time.Minute, time.Now())).Blocked; got != 3 {
		t.Fatalf("blocked before the purge = %d, want 3", got)
	}
	c.ResetTimeline()
	if got := sumTimeline(c.Timeline(24*time.Hour, time.Minute, time.Now())); got != (TimelineBucket{}) {
		t.Errorf("graph after ResetTimeline sums to %+v, want zero", got)
	}
	c.RecordQuery("", "", true)
	c.RecordQuery("", "", false)
	if got := sumTimeline(c.Timeline(time.Hour, time.Minute, time.Now())); got.Total != 1 || got.Blocked != 1 {
		t.Errorf("graph after a blocked and an allowed query = %+v, want total 1, blocked 1", got)
	}
}
