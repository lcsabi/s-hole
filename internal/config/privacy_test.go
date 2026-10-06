package config

import (
	"reflect"
	"strings"
	"testing"
)

func warningKeys(ws []Warning) []string {
	keys := []string{}
	for _, w := range ws {
		keys = append(keys, w.Key)
	}
	return keys
}

func TestWarnings(t *testing.T) {
	// C8: one warning for each setting that is less private or less secure
	// than its default. The clients, file, and retention warnings apply only
	// while the query log records something.
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"defaults", "", nil},
		{"mode all", "query_log:\n  mode: all\n", []string{"query_log.mode"}},
		{"mode blocked", "query_log:\n  mode: blocked\n", []string{"query_log.mode"}},
		{"mode none hides the recording settings",
			"query_log:\n  mode: none\n  clients: full\n  file: stdout\n  database: q.db\n  retention_days: 0\n", nil},
		{"clients full", "query_log:\n  mode: all\n  clients: full\n", []string{"query_log.mode", "query_log.clients"}},
		{"clients subnet", "query_log:\n  mode: blocked\n  clients: subnet\n", []string{"query_log.mode", "query_log.clients"}},
		{"clients drop", "query_log:\n  mode: all\n  clients: drop\n", []string{"query_log.mode"}},
		{"file stdout", "query_log:\n  mode: all\n  file: stdout\n", []string{"query_log.mode", "query_log.file"}},
		{"file path", "query_log:\n  mode: blocked\n  file: q.log\n", []string{"query_log.mode", "query_log.file"}},
		{"file off", "query_log:\n  mode: all\n  file: off\n", []string{"query_log.mode"}},
		{"retention forever", "query_log:\n  mode: all\n  database: q.db\n  retention_days: 0\n", []string{"query_log.mode", "query_log.retention_days"}},
		{"retention 8 days", "query_log:\n  mode: all\n  database: q.db\n  retention_days: 8\n", []string{"query_log.mode", "query_log.retention_days"}},
		{"retention 7 days", "query_log:\n  mode: all\n  database: q.db\n  retention_days: 7\n", []string{"query_log.mode"}},
		{"retention 1 day", "query_log:\n  mode: all\n  database: q.db\n  retention_days: 1\n", []string{"query_log.mode"}},
		{"retention forever without a database", "query_log:\n  mode: all\n  retention_days: 0\n", []string{"query_log.mode"}},
		{"admin on every interface", "admin:\n  listen: \":8080\"\n", []string{"admin.listen"}},
		{"admin on 0.0.0.0", "admin:\n  listen: \"0.0.0.0:8080\"\n", []string{"admin.listen"}},
		{"admin on ::", "admin:\n  listen: \"[::]:8080\"\n", []string{"admin.listen"}},
		{"admin on a LAN address", "admin:\n  listen: \"192.168.1.2:8080\"\n", []string{"admin.listen"}},
		{"admin on localhost", "admin:\n  listen: \"localhost:8080\"\n", nil},
		{"admin on LOCALHOST", "admin:\n  listen: \"LOCALHOST:8080\"\n", nil},
		{"admin on 127.0.0.2", "admin:\n  listen: \"127.0.0.2:8080\"\n", nil},
		{"admin on ::1", "admin:\n  listen: \"[::1]:8080\"\n", nil},
		{"pprof", "admin:\n  pprof: true\n", []string{"admin.pprof"}},
		{"local_ptr off", "dns:\n  local_ptr: false\n", []string{"dns.local_ptr"}},
		{"plain upstreams only", "dns:\n  upstreams: [\"9.9.9.9:53\", \"1.1.1.1:53\"]\n", []string{"dns.upstreams"}},
		{"one DoH upstream among plain", "dns:\n  upstreams: [\"9.9.9.9:53\", \"https://1.1.1.1/dns-query\"]\n", nil},
		{"list over http", "blocking:\n  lists: [\"http://lists.example/a.txt\", \"https://lists.example/b.txt\"]\n", []string{"blocking.lists"}},
		{"list over HTTP", "blocking:\n  lists: [\"HTTP://lists.example/a.txt\"]\n", []string{"blocking.lists"}},
		{"two lists over http", "blocking:\n  lists: [\"http://a.example/a\", \"http://b.example/b\"]\n", []string{"blocking.lists", "blocking.lists"}},
		{"everything",
			"query_log:\n  mode: all\n  clients: full\n  file: stdout\n  database: q.db\n  retention_days: 0\n" +
				"admin:\n  listen: \"0.0.0.0:8080\"\n  pprof: true\n" +
				"dns:\n  local_ptr: false\n  upstreams: [\"9.9.9.9:53\"]\n" +
				"blocking:\n  lists: [\"http://a.example/a\"]\n",
			[]string{"query_log.mode", "query_log.clients", "query_log.file", "query_log.retention_days",
				"admin.listen", "admin.pprof", "dns.local_ptr", "dns.upstreams", "blocking.lists"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, tc.yaml, nil)
			if len(probs) != 0 {
				t.Fatalf("problems = %v, want none", probs)
			}
			ws := cfg.Warnings()
			want := tc.want
			if want == nil {
				want = []string{}
			}
			if got := warningKeys(ws); !sameKeys(got, want) {
				t.Errorf("warning keys = %v, want %v", got, want)
			}
			for _, w := range ws {
				if w.Key == "" || w.Detail == "" || w.Hint == "" {
					t.Errorf("warning %+v has an empty field", w)
				}
			}
		})
	}
}

// sameKeys compares two key lists as multisets.
func sameKeys(a, b []string) bool {
	count := map[string]int{}
	for _, k := range a {
		count[k]++
	}
	for _, k := range b {
		count[k]--
	}
	for _, n := range count {
		if n != 0 {
			return false
		}
	}
	return len(a) == len(b)
}

func TestWarnings_ClientNamesMentionedOnlyWhenSet(t *testing.T) {
	// C8: with clients "full", the detail mentions the client_names labels
	// when any are set.
	detail := func(yaml string) string {
		t.Helper()
		cfg, _ := mustLoadYAML(t, yaml, nil)
		for _, w := range cfg.Warnings() {
			if w.Key == "query_log.clients" {
				return w.Detail
			}
		}
		t.Fatalf("no query_log.clients warning for %q", yaml)
		return ""
	}
	with := detail("query_log:\n  mode: all\n  clients: full\n  client_names: {\"10.0.0.1\": tv}\n")
	if !strings.Contains(with, "client_names") {
		t.Errorf("detail with labels = %q, want it to mention client_names", with)
	}
	without := detail("query_log:\n  mode: all\n  clients: full\n")
	if strings.Contains(without, "client_names") {
		t.Errorf("detail without labels = %q, want no mention of client_names", without)
	}
}

func TestWarnings_ListURLIsRedacted(t *testing.T) {
	// C8: a list URL in a warning is redacted (R1): no user info and no query
	// string reach the log or the dashboard.
	cfg, _ := mustLoadYAML(t, "blocking:\n  lists: [\"http://listuser:listpass@lists.example/a.txt?key=listkey\"]\n", nil)
	ws := cfg.Warnings()
	if !reflect.DeepEqual(warningKeys(ws), []string{"blocking.lists"}) {
		t.Fatalf("warnings = %+v, want one for blocking.lists", ws)
	}
	for _, secret := range []string{"listuser", "listpass", "listkey"} {
		if strings.Contains(ws[0].Detail, secret) || strings.Contains(ws[0].Hint, secret) {
			t.Errorf("warning shows %q: %+v", secret, ws[0])
		}
	}
	if !strings.Contains(ws[0].Detail, "lists.example/a.txt") {
		t.Errorf("detail = %q, want it to name the list", ws[0].Detail)
	}
}

func TestWarnings_DefaultsGiveNone(t *testing.T) {
	// C8: the default config gives no warning. This also uses the constructor
	// main uses, not only an empty file.
	if ws := defaults().Warnings(); len(ws) != 0 {
		t.Errorf("defaults().Warnings() = %+v, want none", ws)
	}
}

func TestWarnings_MalformedAdminListenIsNotLoopback(t *testing.T) {
	// Load replaces a malformed admin.listen, but Warnings must not read one
	// as loopback when it gets a Config from elsewhere: it fails closed.
	c := defaults()
	c.Admin.Listen = "not-an-address"
	if got := warningKeys(c.Warnings()); !reflect.DeepEqual(got, []string{"admin.listen"}) {
		t.Errorf("warning keys = %v, want [admin.listen]", got)
	}
}
