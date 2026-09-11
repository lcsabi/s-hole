package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"github.com/lcsabi/s-hole/internal/querylog"
	"github.com/lcsabi/s-hole/internal/stats"
)

func TestClientLabeler(t *testing.T) {
	// An exact key wins over an overlapping CIDR; among CIDRs the most specific
	// (longest prefix) wins. The lookup keys off the stored value, which under
	// query_privacy "subnet" is a network address and under "drop" is "".
	l := newClientLabeler(map[string]string{
		"192.168.1.42":   "kids-ipad",  // exact host
		"192.168.1.0/24": "home-lan",   // less specific, overlaps the host
		"192.168.1.0/25": "home-lower", // more specific, still contains .42
		"10.0.5.0/24":    "iot-vlan",
	})

	cases := []struct {
		name, in, want string
	}{
		{"exact beats cidr", "192.168.1.42", "kids-ipad"},
		{"most specific cidr wins", "192.168.1.99", "home-lower"},
		{"outside the /25 falls to the /24", "192.168.1.200", "home-lan"},
		{"subnet network address matches its /24", "10.0.5.0", "iot-vlan"},
		{"no match", "172.16.0.1", ""},
		{"empty (drop mode) never labels", "", ""},
		{"unparseable value", "not-an-ip", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := l.label(c.in); got != c.want {
				t.Errorf("label(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestClientLabeler_NilAndEmpty(t *testing.T) {
	// A nil labeler (SetClientNames never called) and an empty map both label
	// nothing, so the feature is simply off.
	var nilLabeler *clientLabeler
	if got := nilLabeler.label("192.168.1.42"); got != "" {
		t.Errorf("nil labeler label = %q, want empty", got)
	}
	if got := newClientLabeler(nil).label("192.168.1.42"); got != "" {
		t.Errorf("empty labeler label = %q, want empty", got)
	}
}

// statsClientsResponse mirrors just the top_clients slice of /api/stats,
// including the client_names label added by handleStats.
type statsClientsResponse struct {
	TopClients []struct {
		Name  string `json:"name"`
		Count int64  `json:"count"`
		Label string `json:"label"`
	} `json:"top_clients"`
}

func TestHandleStats_AttachesClientLabels(t *testing.T) {
	store := blocklist.NewStore()
	s := New(stats.New(), nil, store, nil, func() bool { return true })
	s.SetClientNames(map[string]string{"192.168.1.42": "kids-ipad"})
	s.counter.RecordQuery("192.168.1.42", "ads.com.", true)
	s.counter.RecordQuery("192.168.1.99", "news.com.", false)

	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats: %v", err)
	}
	defer resp.Body.Close()
	body := decode[statsClientsResponse](t, resp.Body)

	labels := map[string]string{}
	for _, e := range body.TopClients {
		labels[e.Name] = e.Label
	}
	if got := labels["192.168.1.42"]; got != "kids-ipad" {
		t.Errorf("label for named client = %q, want kids-ipad", got)
	}
	if got, ok := labels["192.168.1.99"]; !ok || got != "" {
		t.Errorf("unnamed client label = %q (present=%v), want empty", got, ok)
	}
}

// queryLabelResponse mirrors the /api/queries rows including the label field.
type queryLabelResponse struct {
	Queries []struct {
		ClientIP string `json:"client_ip"`
		Label    string `json:"label"`
	} `json:"queries"`
}

func TestHandleQueries_AttachesClientLabels(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "q.db")
	db, err := querylog.NewDBLogger(dbPath, "all", 50*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewDBLogger: %v", err)
	}
	defer db.Close()

	db.Log("192.168.1.42", "first.com.", false)
	db.Log("192.168.1.99", "second.com.", true)
	waitForRows(t, db, 2)

	store := blocklist.NewStore()
	s := New(stats.New(), db, store, nil, func() bool { return true })
	s.SetClientNames(map[string]string{"192.168.1.0/24": "home-lan", "192.168.1.42": "kids-ipad"})

	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/queries?limit=10")
	if err != nil {
		t.Fatalf("GET /api/queries: %v", err)
	}
	defer resp.Body.Close()
	body := decode[queryLabelResponse](t, resp.Body)

	if len(body.Queries) != 2 {
		t.Fatalf("got %d rows, want 2", len(body.Queries))
	}
	for _, q := range body.Queries {
		want := "home-lan"
		if q.ClientIP == "192.168.1.42" {
			want = "kids-ipad" // exact beats the /24
		}
		if q.Label != want {
			t.Errorf("row %s label = %q, want %q", q.ClientIP, q.Label, want)
		}
	}

	// The label still attaches when a filter narrows the result set (the join
	// runs on the filtered rows, not only the unfiltered Recent path).
	fresp, err := http.Get(srv.URL + "/api/queries?domain=first")
	if err != nil {
		t.Fatalf("GET filtered: %v", err)
	}
	defer fresp.Body.Close()
	filtered := decode[queryLabelResponse](t, fresp.Body)
	if len(filtered.Queries) != 1 {
		t.Fatalf("filtered got %d rows, want 1", len(filtered.Queries))
	}
	if got := filtered.Queries[0]; got.ClientIP != "192.168.1.42" || got.Label != "kids-ipad" {
		t.Errorf("filtered row = %+v, want kids-ipad for 192.168.1.42", got)
	}
}
