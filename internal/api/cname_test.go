package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
)

// CL 117: the admin API shows what matched a blocked query (blocked_by) and
// the number of queries blocked through a CNAME target. It shows no target.

// cnameTestDB serves a database with a name block, a CNAME block, and an
// allowed row, logged in this order.
func cnameTestDB(t *testing.T) *httptest.Server {
	t.Helper()
	db, err := querylog.NewDBLogger(filepath.Join(t.TempDir(), "q.db"), "all", 50*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	db.Log(querylog.Record{ClientIP: "192.168.1.42", Domain: "ads.example.com.", Blocked: true, Synthesized: true, BlockSource: querylog.BlockedByName})
	db.Log(querylog.Record{ClientIP: "192.168.1.42", Domain: "metrics.shop.example.", Blocked: true, Synthesized: true, BlockSource: querylog.BlockedByCNAME})
	db.Log(querylog.Record{ClientIP: "192.168.1.42", Domain: "ok.example.com."})
	waitForRows(t, db, 3)

	s := New(stats.New(), db, blocklist.NewStore(), nil, func() bool { return true })
	s.SetPrivacy(PrivacyInfo{Clients: "full", Mode: "all"})
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return srv
}

// cnameWant is the blocked_by of each row; "-" means the key is absent.
var cnameWant = map[string]string{
	"ads.example.com.":      "name",
	"metrics.shop.example.": "cname",
	"ok.example.com.":       "-",
}

// checkRowsBlockedBy fails unless each JSON row has the blocked_by of its
// domain, and an allowed row has no blocked_by key.
func checkRowsBlockedBy(t *testing.T, where string, rows []map[string]any) {
	t.Helper()
	if len(rows) != len(cnameWant) {
		t.Fatalf("%s has %d rows, want %d", where, len(rows), len(cnameWant))
	}
	for _, r := range rows {
		d, _ := r["domain"].(string)
		want, ok := cnameWant[d]
		if !ok {
			t.Errorf("%s: unexpected row %v", where, r)
			continue
		}
		v, present := r["blocked_by"]
		if want == "-" {
			if present {
				t.Errorf("%s: allowed row %s has blocked_by %#v, want none", where, d, v)
			}
			continue
		}
		if v != want {
			t.Errorf("%s: %s blocked_by = %#v, want %q", where, d, v, want)
		}
	}
}

func TestQueriesEndpoint_CarriesBlockedBy(t *testing.T) {
	// CL 117 req 10: each /api/queries row carries blocked_by on a blocked row.
	srv := cnameTestDB(t)
	resp, err := http.Get(srv.URL + "/api/queries?limit=10")
	if err != nil {
		t.Fatalf("GET /api/queries: %v", err)
	}
	defer resp.Body.Close()
	body := decode[struct {
		Queries []map[string]any `json:"queries"`
	}](t, resp.Body)
	checkRowsBlockedBy(t, "/api/queries", body.Queries)
}

func TestQueriesExport_JSONCarriesBlockedBy(t *testing.T) {
	// CL 117 req 10: each JSON export row carries blocked_by on a blocked row.
	srv := cnameTestDB(t)
	resp, err := http.Get(srv.URL + "/api/queries/export?format=json")
	if err != nil {
		t.Fatalf("GET export: %v", err)
	}
	defer resp.Body.Close()
	body := decode[struct {
		Queries []map[string]any `json:"queries"`
	}](t, resp.Body)
	checkRowsBlockedBy(t, "JSON export", body.Queries)
}

func TestQueriesExport_CSVBlockedByColumn(t *testing.T) {
	// CL 117 req 10: the CSV header is exact, with blocked_by last, and each row
	// fills it: "name" or "cname" on a blocked row, empty on an allowed row.
	srv := cnameTestDB(t)
	_, _, body := getRaw(t, srv.URL+"/api/queries/export")
	records, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	wantHeader := []string{"ts", "client_ip", "label", "domain", "blocked", "outcome", "rcode", "synthesized", "blocked_by"}
	if len(records) == 0 || !reflect.DeepEqual(records[0], wantHeader) {
		t.Fatalf("header = %v, want %v", records[0], wantHeader)
	}
	if len(records) != 1+len(cnameWant) {
		t.Fatalf("CSV has %d records, want %d", len(records), 1+len(cnameWant))
	}
	for _, r := range records[1:] {
		if len(r) != len(wantHeader) {
			t.Errorf("row %v has %d fields, want %d", r, len(r), len(wantHeader))
			continue
		}
		want := cnameWant[r[3]]
		if want == "-" {
			want = ""
		}
		if r[8] != want {
			t.Errorf("row for %s: blocked_by = %q, want %q", r[3], r[8], want)
		}
	}
}

func TestStatsEndpoint_CarriesCNAMEBlockedCount(t *testing.T) {
	// CL 117 req 10: /api/stats carries cname_blocked_count.
	s, srv := newTestServer(t, nil)
	s.counter.RecordQuery("", "", true)
	s.counter.RecordCNAMEBlocked()
	s.counter.RecordQuery("", "", true)
	_, _, body := getRaw(t, srv.URL+"/api/stats")
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m["cname_blocked_count"] != float64(1) || m["blocked_count"] != float64(2) {
		t.Errorf("cname_blocked_count = %#v, blocked_count = %#v; want 1 and 2", m["cname_blocked_count"], m["blocked_count"])
	}
}

func TestMetrics_CNAMEBlockedTotal(t *testing.T) {
	// CL 117 req 10: /metrics has shole_cname_blocked_total, a counter with HELP
	// and TYPE lines and no label: one aggregate number.
	s, srv := newTestServer(t, nil)
	for range 3 {
		s.counter.RecordQuery("192.168.1.42", "metrics.shop.example.", true)
		s.counter.RecordCNAMEBlocked()
	}
	_, _, body := getRaw(t, srv.URL+"/metrics")
	text := string(body)
	if got := parseMetricValue(t, text, "shole_cname_blocked_total"); got != 3 {
		t.Errorf("shole_cname_blocked_total = %d, want 3", got)
	}
	if !strings.Contains(text, "# HELP shole_cname_blocked_total ") {
		t.Error("shole_cname_blocked_total has no HELP line")
	}
	if !strings.Contains(text, "# TYPE shole_cname_blocked_total counter\n") {
		t.Error("shole_cname_blocked_total has no counter TYPE line")
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "shole_cname_blocked_total{") {
			t.Errorf("shole_cname_blocked_total has a label: %q", line)
		}
	}
	for _, leak := range []string{"metrics.shop", "192.168.1.42"} {
		if strings.Contains(text, leak) {
			t.Errorf("/metrics holds %q", leak)
		}
	}
}
