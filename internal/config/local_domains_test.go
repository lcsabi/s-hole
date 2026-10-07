package config

import (
	"reflect"
	"strings"
	"testing"
)

// CL 94 R13: dns.local_domains is a list of extra local-only suffixes.

// localDomainsYAML writes a dns.local_domains list with each entry quoted.
func localDomainsYAML(entries ...string) string {
	var b strings.Builder
	b.WriteString("dns:\n  local_domains:\n")
	for _, e := range entries {
		b.WriteString("    - \"" + e + "\"\n")
	}
	return b.String()
}

func TestLoad_LocalDomainsDefaultIsEmpty(t *testing.T) {
	// CL 94 R13: the default is an empty list, with no problem.
	cfg, probs := mustLoadYAML(t, "", nil)
	if len(cfg.DNS.LocalDomains) != 0 {
		t.Errorf("default local_domains = %v, want empty", cfg.DNS.LocalDomains)
	}
	if len(probs) != 0 {
		t.Errorf("problems = %v, want none", probs)
	}
	if len(defaults().DNS.LocalDomains) != 0 {
		t.Errorf("defaults().DNS.LocalDomains = %v, want empty", defaults().DNS.LocalDomains)
	}
}

func TestLoad_LocalDomainsNormalized(t *testing.T) {
	// CL 94 R13: every spelling of one domain is stored once as "fritz.box",
	// in first-seen order. A single label is valid.
	cases := []struct {
		name    string
		entries []string
		want    []string
	}{
		{"plain", []string{"fritz.box"}, []string{"fritz.box"}},
		{"leading dot", []string{".fritz.box"}, []string{"fritz.box"}},
		{"wildcard", []string{"*.fritz.box"}, []string{"fritz.box"}},
		{"trailing dot", []string{"fritz.box."}, []string{"fritz.box"}},
		{"upper case", []string{"FRITZ.BOX"}, []string{"fritz.box"}},
		{"mixed case wildcard", []string{"*.Fritz.Box"}, []string{"fritz.box"}},
		{"every spelling once", []string{"fritz.box", ".fritz.box", "*.fritz.box", "fritz.box.", "Fritz.Box"}, []string{"fritz.box"}},
		{"single labels", []string{"fritz", "LAN"}, []string{"fritz", "lan"}},
		{"first-seen order", []string{"b.example", "a.example", "B.Example.", "c", "*.a.example"}, []string{"b.example", "a.example", "c"}},
		{"valid characters", []string{"my-router.box", "_svc.home", "r2d2.lan", "xn--bcher-kva.example"}, []string{"my-router.box", "_svc.home", "r2d2.lan", "xn--bcher-kva.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, localDomainsYAML(tc.entries...), nil)
			if !reflect.DeepEqual(cfg.DNS.LocalDomains, tc.want) {
				t.Errorf("local_domains = %q, want %q", cfg.DNS.LocalDomains, tc.want)
			}
			if len(probs) != 0 {
				t.Errorf("problems = %v, want none", probs)
			}
		})
	}
}

func TestLoad_LocalDomainsLengthLimits(t *testing.T) {
	// CL 94 R13: a label of 63 characters and a name of 253 characters are
	// valid; one more character makes each invalid.
	l63 := strings.Repeat("a", 63)
	name253 := l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 61)
	if len(name253) != 253 {
		t.Fatalf("fixture: name is %d characters", len(name253))
	}
	cfg, probs := mustLoadYAML(t, localDomainsYAML(l63+".box", name253), nil)
	if !reflect.DeepEqual(cfg.DNS.LocalDomains, []string{l63 + ".box", name253}) || len(probs) != 0 {
		t.Errorf("local_domains = %q, problems %v; want both kept and no problem", cfg.DNS.LocalDomains, probs)
	}

	l64 := l63 + "a"
	name254 := name253 + "b"
	cfg, probs = mustLoadYAML(t, localDomainsYAML(l64+".box", name254), nil)
	if len(cfg.DNS.LocalDomains) != 0 || len(probs) != 2 {
		t.Errorf("local_domains = %q, %d problems; want none kept and 2 problems", cfg.DNS.LocalDomains, len(probs))
	}
}

func TestLoad_LocalDomainsInvalidEntriesAreProblems(t *testing.T) {
	// CL 94 R13: an invalid entry is dropped and reported as a problem with
	// key dns.local_domains. The valid entries in the same list are kept, in
	// order.
	bad := []string{
		"  ",
		"a..b",
		"fritz box",
		"-bad.box",
		"bad-.box",
		"a.-b",
		"fr!tz.box",
		"fritz/box",
		"fritz:box",
		"*",
		".",
		"..",
		"fritz.box..",
	}
	good := []string{"fritz.box", "lan", "home.example"}
	var entries []string
	for i, b := range bad {
		entries = append(entries, b)
		if i < len(good) {
			entries = append(entries, good[i])
		}
	}
	cfg, probs := mustLoadYAML(t, localDomainsYAML(entries...), nil)
	if !reflect.DeepEqual(cfg.DNS.LocalDomains, good) {
		t.Errorf("local_domains = %q, want %q", cfg.DNS.LocalDomains, good)
	}
	if len(probs) != len(bad) {
		t.Errorf("got %d problems, want %d:\n%s", len(probs), len(bad), problemText(probs))
	}
	for _, p := range probs {
		if p.Key != "dns.local_domains" {
			t.Errorf("problem key = %q, want dns.local_domains", p.Key)
		}
	}
}

func TestLoad_LocalDomainsHasNoEnvironmentVariable(t *testing.T) {
	// CL 94 R13: the list has no environment variable. Such a variable is an
	// unknown variable, and the setting stays empty.
	cfg, probs := mustLoadYAML(t, "", map[string]string{"S_HOLE_DNS_LOCAL_DOMAINS": "fritz.box"})
	if len(cfg.DNS.LocalDomains) != 0 {
		t.Errorf("local_domains = %v, want empty", cfg.DNS.LocalDomains)
	}
	if !reflect.DeepEqual(problemKeys(probs), []string{"S_HOLE_DNS_LOCAL_DOMAINS"}) {
		t.Errorf("problems = %v, want one for S_HOLE_DNS_LOCAL_DOMAINS", probs)
	}
}

func TestWarnings_LocalDomainsGiveNone(t *testing.T) {
	// CL 94 R13: dns.local_domains records nothing, so it adds no warning.
	cfg, _ := mustLoadYAML(t, localDomainsYAML("fritz.box", "lan", "corp.example"), nil)
	if len(cfg.DNS.LocalDomains) != 3 {
		t.Fatalf("fixture: local_domains = %v", cfg.DNS.LocalDomains)
	}
	if ws := cfg.Warnings(); len(ws) != 0 {
		t.Errorf("Warnings() = %+v, want none", ws)
	}
}

func TestLoad_LocalDomainsEmptyEntryIsAProblem(t *testing.T) {
	// CL 94 R13: an empty entry is invalid: it is dropped and reported as a
	// problem with key dns.local_domains, so -check-config fails on it.
	cfg, probs := mustLoadYAML(t, localDomainsYAML("fritz.box", ""), nil)
	if !reflect.DeepEqual(cfg.DNS.LocalDomains, []string{"fritz.box"}) {
		t.Errorf("local_domains = %q, want [fritz.box]", cfg.DNS.LocalDomains)
	}
	if !reflect.DeepEqual(problemKeys(probs), []string{"dns.local_domains"}) {
		t.Errorf("problems = %v, want one for dns.local_domains", probs)
	}
}

func TestLoad_LocalDomainsNullEntryIsAProblem(t *testing.T) {
	// CL 94 R13: a null entry is invalid too: dropped and reported.
	cfg, probs := mustLoadYAML(t, "dns:\n  local_domains:\n    - fritz.box\n    - ~\n    -\n", nil)
	if !reflect.DeepEqual(cfg.DNS.LocalDomains, []string{"fritz.box"}) {
		t.Errorf("local_domains = %q, want [fritz.box]", cfg.DNS.LocalDomains)
	}
	if !reflect.DeepEqual(problemKeys(probs), []string{"dns.local_domains", "dns.local_domains"}) {
		t.Errorf("problems = %v, want two for dns.local_domains", probs)
	}
}

func TestLoad_OtherListsSkipEmptyEntriesSilently(t *testing.T) {
	// CL 94: the other lists keep their behavior from before CL 94. An empty
	// or null entry is dropped with no problem.
	cases := []struct {
		key  string
		yaml string
		got  func(*Config) []string
		want []string
	}{
		{"blocking.allowlist", "blocking:\n  allowlist:\n    - example.com\n    - \"\"\n    - ~\n    -\n",
			func(c *Config) []string { return c.Blocking.Allowlist }, []string{"example.com"}},
		{"blocking.lists", "blocking:\n  lists:\n    - https://lists.example/a.txt\n    - \"\"\n    - ~\n    -\n",
			func(c *Config) []string { return c.Blocking.Lists }, []string{"https://lists.example/a.txt"}},
		{"dns.upstreams", "dns:\n  upstreams:\n    - 192.168.1.1:53\n    - \"\"\n    - ~\n    -\n",
			func(c *Config) []string { return c.DNS.Upstreams }, []string{"192.168.1.1:53"}},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, tc.yaml, nil)
			if got := tc.got(cfg); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
			}
			if len(probs) != 0 {
				t.Errorf("problems = %v, want none", probs)
			}
		})
	}
}
