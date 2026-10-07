package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// loadYAML runs load on body with only the environment in env, so an
// S_HOLE_* variable on the test host cannot change the result.
func loadYAML(t *testing.T, body string, env map[string]string) (*Config, []Problem, error) {
	t.Helper()
	lookup := func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
	var environ []string
	for k, v := range env {
		environ = append(environ, k+"="+v)
	}
	sort.Strings(environ)
	return load([]byte(body), lookup, environ)
}

// mustLoadYAML is loadYAML for a config that must not be fatal.
func mustLoadYAML(t *testing.T, body string, env map[string]string) (*Config, []Problem) {
	t.Helper()
	cfg, probs, err := loadYAML(t, body, env)
	if err != nil {
		t.Fatalf("load(%q) = %v, want no fatal error", body, err)
	}
	if cfg == nil {
		t.Fatalf("load(%q) returned a nil config without an error", body)
	}
	return cfg, probs
}

// wantDefaults is the config that C1 specifies for an empty file. It is
// written out here, not built with defaults(), so a changed default in
// config.go fails the test.
func wantDefaults() *Config {
	return &Config{
		DNS: DNS{
			Listen:       ":53",
			Upstreams:    []string{"https://9.9.9.9/dns-query", "https://1.1.1.1/dns-query", "9.9.9.9:53", "1.1.1.1:53"},
			CacheEntries: 2000,
			LocalPTR:     true,
		},
		Blocking: Blocking{
			Reply:           "zero_ip",
			ReplyTTLSeconds: 300,
			RefreshInterval: 24 * time.Hour,
			CacheDir:        ".",
		},
		QueryLog: QueryLog{
			Mode:          "none",
			Clients:       "drop",
			RetentionDays: 7,
			FlushInterval: 30 * time.Second,
		},
		Admin:         Admin{Listen: "127.0.0.1:8080"},
		StatsInterval: 5 * time.Minute,
	}
}

func problemKeys(probs []Problem) []string {
	keys := make([]string, len(probs))
	for i, p := range probs {
		keys[i] = p.Key
	}
	return keys
}

func problemText(probs []Problem) string {
	var out []string
	for _, p := range probs {
		out = append(out, p.String())
	}
	return strings.Join(out, "\n")
}

// clearSholeEnv unsets every S_HOLE_* variable for the duration of the test.
// t.Setenv records the old value and restores it at cleanup.
func clearSholeEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "S_HOLE_") {
			t.Setenv(name, "")
			os.Unsetenv(name)
		}
	}
}

// writeKeyPair writes a valid self-signed certificate and its key.
func writeKeyPair(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dns.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"dns.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// yamlFor builds a YAML document that sets one key path to val.
func yamlFor(key, val string) string {
	section, name, ok := strings.Cut(key, ".")
	if !ok {
		return key + ": " + val + "\n"
	}
	return section + ":\n  " + name + ": " + val + "\n"
}

func TestLoad_EmptyInputGivesDefaults(t *testing.T) {
	// C1: an empty file, a comments-only file, and empty (null) sections are
	// valid, report no problem, and give every default.
	cases := map[string]string{
		"empty file":     "",
		"comments only":  "# s-hole config\n# nothing set\n",
		"null document":  "~\n",
		"null lists":     "dns:\n  upstreams:\nblocking:\n  lists:\n  allowlist:\nquery_log:\n  client_names:\n",
		"null sections":  "dns:\nblocking:\nquery_log:\nadmin:\n",
		"empty sections": "dns: {}\nblocking: {}\nquery_log: {}\nadmin: {}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, body, nil)
			if len(probs) != 0 {
				t.Errorf("problems = %v, want none", probs)
			}
			if want := wantDefaults(); !reflect.DeepEqual(cfg, want) {
				t.Errorf("config = %+v\nwant     %+v", cfg, want)
			}
		})
	}
}

func TestLoad_FileOnDiskGivesDefaults(t *testing.T) {
	// Load reads the file and the process environment. Every S_HOLE_* variable
	// is cleared first, so the host's settings cannot change the result.
	clearSholeEnv(t)
	cfg, probs, err := Load(writeTemp(t, "# empty\n"))
	if err != nil || len(probs) != 0 {
		t.Fatalf("Load = (%v, %v), want no problem and no error", probs, err)
	}
	if want := wantDefaults(); !reflect.DeepEqual(cfg, want) {
		t.Errorf("config = %+v\nwant     %+v", cfg, want)
	}
}

func TestLoad_EverySettingIsRead(t *testing.T) {
	// C1: each key in each section reaches its field.
	dir := t.TempDir()
	cert, key := writeKeyPair(t, dir)
	body := `
dns:
  listen: "127.0.0.1:5353"
  dot_listen: "127.0.0.1:8853"
  dot_cert: "` + cert + `"
  dot_key: "` + key + `"
  upstreams:
    - "https://1.1.1.1/dns-query"
    - "8.8.8.8:53"
  cache_entries: 0
  local_ptr: false
blocking:
  lists:
    - "https://lists.example/hosts.txt"
  allowlist:
    - "safe.example.com"
  reply: nxdomain
  reply_ttl_seconds: 4294967295
  refresh_interval: 6h
  cache_dir: "cache"
query_log:
  mode: blocked
  clients: subnet
  database: "q.db"
  file: "q.log"
  retention_days: 0
  flush_interval: 2s
  client_names:
    "192.168.1.0/24": lan
    "10.0.0.5": printer
admin:
  listen: "127.0.0.1:9090"
  pprof: true
stats_interval: 1m
`
	cfg, probs := mustLoadYAML(t, body, nil)
	if len(probs) != 0 {
		t.Fatalf("problems = %v, want none", probs)
	}
	want := &Config{
		DNS: DNS{
			Listen:       "127.0.0.1:5353",
			DoTListen:    "127.0.0.1:8853",
			DoTCert:      cert,
			DoTKey:       key,
			Upstreams:    []string{"https://1.1.1.1/dns-query", "8.8.8.8:53"},
			CacheEntries: 0,
			LocalPTR:     false,
		},
		Blocking: Blocking{
			Lists:           []string{"https://lists.example/hosts.txt"},
			Allowlist:       []string{"safe.example.com"},
			Reply:           "nxdomain",
			ReplyTTLSeconds: 4294967295,
			RefreshInterval: 6 * time.Hour,
			CacheDir:        "cache",
		},
		QueryLog: QueryLog{
			Mode:          "blocked",
			Clients:       "subnet",
			Database:      "q.db",
			File:          "q.log",
			RetentionDays: 0,
			FlushInterval: 2 * time.Second,
			ClientNames:   map[string]string{"192.168.1.0/24": "lan", "10.0.0.5": "printer"},
		},
		Admin:         Admin{Listen: "127.0.0.1:9090", Pprof: true},
		StatsInterval: time.Minute,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("config = %+v\nwant     %+v", cfg, want)
	}
}

// scalarCase is one scalar setting: its key and variable, a valid YAML value,
// a different valid environment value, and the expected field values.
type scalarCase struct {
	key, env     string
	yaml, envVal string
	get          func(*Config) any
	wantYAML     any
	wantEnv      any
	wantDefault  any
}

func scalarCases(t *testing.T) []scalarCase {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.pem"), filepath.Join(dir, "b.pem")
	return []scalarCase{
		{"dns.listen", "S_HOLE_DNS_LISTEN", `"127.0.0.1:5353"`, "127.0.0.1:6363", func(c *Config) any { return c.DNS.Listen }, "127.0.0.1:5353", "127.0.0.1:6363", ":53"},
		{"dns.dot_listen", "S_HOLE_DNS_DOT_LISTEN", "off", "off", func(c *Config) any { return c.DNS.DoTListen }, "", "", ""},
		{"dns.dot_cert", "S_HOLE_DNS_DOT_CERT", `"` + a + `"`, b, func(c *Config) any { return c.DNS.DoTCert }, a, b, ""},
		{"dns.dot_key", "S_HOLE_DNS_DOT_KEY", `"` + a + `"`, b, func(c *Config) any { return c.DNS.DoTKey }, a, b, ""},
		{"dns.cache_entries", "S_HOLE_DNS_CACHE_ENTRIES", "500", "0", func(c *Config) any { return c.DNS.CacheEntries }, 500, 0, 2000},
		{"dns.local_ptr", "S_HOLE_DNS_LOCAL_PTR", "false", "true", func(c *Config) any { return c.DNS.LocalPTR }, false, true, true},
		{"blocking.reply", "S_HOLE_BLOCKING_REPLY", "nxdomain", "zero_ip", func(c *Config) any { return c.Blocking.Reply }, "nxdomain", "zero_ip", "zero_ip"},
		{"blocking.reply_ttl_seconds", "S_HOLE_BLOCKING_REPLY_TTL_SECONDS", "60", "0", func(c *Config) any { return c.Blocking.ReplyTTLSeconds }, uint32(60), uint32(0), uint32(300)},
		{"blocking.refresh_interval", "S_HOLE_BLOCKING_REFRESH_INTERVAL", "1h", "2h", func(c *Config) any { return c.Blocking.RefreshInterval }, time.Hour, 2 * time.Hour, 24 * time.Hour},
		{"blocking.cache_dir", "S_HOLE_BLOCKING_CACHE_DIR", "a", "b", func(c *Config) any { return c.Blocking.CacheDir }, "a", "b", "."},
		{"query_log.mode", "S_HOLE_QUERY_LOG_MODE", "all", "blocked", func(c *Config) any { return c.QueryLog.Mode }, "all", "blocked", "none"},
		{"query_log.clients", "S_HOLE_QUERY_LOG_CLIENTS", "full", "subnet", func(c *Config) any { return c.QueryLog.Clients }, "full", "subnet", "drop"},
		{"query_log.database", "S_HOLE_QUERY_LOG_DATABASE", "a.db", "b.db", func(c *Config) any { return c.QueryLog.Database }, "a.db", "b.db", ""},
		{"query_log.file", "S_HOLE_QUERY_LOG_FILE", "a.log", "stdout", func(c *Config) any { return c.QueryLog.File }, "a.log", "stdout", ""},
		{"query_log.retention_days", "S_HOLE_QUERY_LOG_RETENTION_DAYS", "3", "0", func(c *Config) any { return c.QueryLog.RetentionDays }, 3, 0, 7},
		{"query_log.flush_interval", "S_HOLE_QUERY_LOG_FLUSH_INTERVAL", "5s", "10s", func(c *Config) any { return c.QueryLog.FlushInterval }, 5 * time.Second, 10 * time.Second, 30 * time.Second},
		{"admin.listen", "S_HOLE_ADMIN_LISTEN", `"127.0.0.1:9090"`, "127.0.0.1:9191", func(c *Config) any { return c.Admin.Listen }, "127.0.0.1:9090", "127.0.0.1:9191", "127.0.0.1:8080"},
		{"admin.pprof", "S_HOLE_ADMIN_PPROF", "true", "false", func(c *Config) any { return c.Admin.Pprof }, true, false, false},
		{"stats_interval", "S_HOLE_STATS_INTERVAL", "1m", "2m", func(c *Config) any { return c.StatsInterval }, time.Minute, 2 * time.Minute, 5 * time.Minute},
	}
}

func TestLoad_EnvironmentPrecedence(t *testing.T) {
	// C2: S_HOLE_<KEY PATH> > YAML > default, for every scalar key. An empty
	// value means the default, from YAML and from the environment.
	for _, tc := range scalarCases(t) {
		t.Run(tc.key, func(t *testing.T) {
			if got := envName(tc.key); got != tc.env {
				t.Errorf("envName(%q) = %q, want %q", tc.key, got, tc.env)
			}
			body := yamlFor(tc.key, tc.yaml)
			check := func(what, body string, env map[string]string, want any) {
				t.Helper()
				cfg, probs := mustLoadYAML(t, body, env)
				if got := tc.get(cfg); got != want || len(probs) != 0 {
					t.Errorf("%s: %s = %v (problems %v), want %v", what, tc.key, got, probs, want)
				}
			}
			check("YAML only", body, nil, tc.wantYAML)
			check("YAML and variable", body, map[string]string{tc.env: tc.envVal}, tc.wantEnv)
			check("variable only", "", map[string]string{tc.env: tc.envVal}, tc.wantEnv)
			check("YAML and empty variable", body, map[string]string{tc.env: ""}, tc.wantDefault)
			check("empty YAML value", yamlFor(tc.key, `""`), nil, tc.wantDefault)
			check("null YAML value", yamlFor(tc.key, ""), nil, tc.wantDefault)
		})
	}
}

func TestLoad_ProcessEnvironmentOverridesFile(t *testing.T) {
	// C2 through Load: the real process environment is read.
	clearSholeEnv(t)
	t.Setenv("S_HOLE_QUERY_LOG_RETENTION_DAYS", "2")
	t.Setenv("S_HOLE_DNS_LISTEN", "127.0.0.1:5300")
	cfg, probs, err := Load(writeTemp(t, "dns:\n  listen: \":53\"\nquery_log:\n  retention_days: 9\n"))
	if err != nil || len(probs) != 0 {
		t.Fatalf("Load = (%v, %v), want no problem", probs, err)
	}
	if cfg.QueryLog.RetentionDays != 2 || cfg.DNS.Listen != "127.0.0.1:5300" {
		t.Errorf("retention_days = %d, listen = %q; want the environment values 2 and 127.0.0.1:5300",
			cfg.QueryLog.RetentionDays, cfg.DNS.Listen)
	}
}

func TestLoad_BadEnvironmentValueKeepsYAMLValue(t *testing.T) {
	// C3: a bad environment value is a problem, and the setting keeps its
	// YAML value.
	cases := []struct {
		yaml, env, val string
		get            func(*Config) any
		want           any
	}{
		{"dns:\n  cache_entries: 500\n", "S_HOLE_DNS_CACHE_ENTRIES", "lots", func(c *Config) any { return c.DNS.CacheEntries }, 500},
		{"query_log:\n  mode: blocked\n", "S_HOLE_QUERY_LOG_MODE", "ALL", func(c *Config) any { return c.QueryLog.Mode }, "blocked"},
		{"query_log:\n  retention_days: 3\n", "S_HOLE_QUERY_LOG_RETENTION_DAYS", "-1", func(c *Config) any { return c.QueryLog.RetentionDays }, 3},
		{"admin:\n  pprof: true\n", "S_HOLE_ADMIN_PPROF", "maybe", func(c *Config) any { return c.Admin.Pprof }, true},
		{"stats_interval: 1m\n", "S_HOLE_STATS_INTERVAL", "0s", func(c *Config) any { return c.StatsInterval }, time.Minute},
		{"blocking:\n  reply_ttl_seconds: 9\n", "S_HOLE_BLOCKING_REPLY_TTL_SECONDS", "-9", func(c *Config) any { return c.Blocking.ReplyTTLSeconds }, uint32(9)},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, tc.yaml, map[string]string{tc.env: tc.val})
			if got := tc.get(cfg); got != tc.want {
				t.Errorf("value = %v, want the YAML value %v", got, tc.want)
			}
			if !reflect.DeepEqual(problemKeys(probs), []string{tc.env}) {
				t.Errorf("problems = %v, want one for %s", probs, tc.env)
			}
		})
	}
}

func TestLoad_ListsAndMapsHaveNoEnvironmentVariable(t *testing.T) {
	// C2: lists and maps have no variable. Such a variable is unknown (C3), and
	// the setting does not change.
	for _, env := range []string{"S_HOLE_DNS_UPSTREAMS", "S_HOLE_BLOCKING_LISTS", "S_HOLE_BLOCKING_ALLOWLIST", "S_HOLE_QUERY_LOG_CLIENT_NAMES"} {
		t.Run(env, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, "", map[string]string{env: "8.8.8.8:53"})
			if !reflect.DeepEqual(cfg, wantDefaults()) {
				t.Errorf("config changed by %s: %+v", env, cfg)
			}
			if !reflect.DeepEqual(problemKeys(probs), []string{env}) {
				t.Errorf("problems = %v, want one for %s", probs, env)
			}
		})
	}
}

func TestLoad_UnknownKeys(t *testing.T) {
	// C3: an unknown key at the top level or in a section is a problem; the
	// known keys around it still load.
	body := "bogus: 1\ndns:\n  listen: \"127.0.0.1:53\"\n  lissten: x\nadmin:\n  pprof: true\n  port: 1\n"
	cfg, probs := mustLoadYAML(t, body, nil)
	want := []string{"bogus", "dns.lissten", "admin.port"}
	if !reflect.DeepEqual(problemKeys(probs), want) {
		t.Errorf("problem keys = %v, want %v", problemKeys(probs), want)
	}
	if cfg.DNS.Listen != "127.0.0.1:53" || !cfg.Admin.Pprof {
		t.Errorf("known keys not loaded: listen=%q pprof=%v", cfg.DNS.Listen, cfg.Admin.Pprof)
	}
}

func TestLoad_RenamedKeysAreIgnored(t *testing.T) {
	// C3: every s-hole 1.x top-level key is a problem whose detail names the
	// 2.0 key, and its value is ignored. Most values below would make s-hole
	// less private if they were applied.
	cases := []struct{ old, val, newKey string }{
		{"listen", `"0.0.0.0:5353"`, "dns.listen"},
		{"dot_listen", `":853"`, "dns.dot_listen"},
		{"tls_cert", "c.pem", "dns.dot_cert"},
		{"tls_key", "k.pem", "dns.dot_key"},
		{"upstreams", "[\"8.8.8.8:53\"]", "dns.upstreams"},
		{"cache_size", "10", "dns.cache_entries"},
		{"local_ptr", "false", "dns.local_ptr"},
		{"blocklists", "[\"http://lists.example/a.txt\"]", "blocking.lists"},
		{"whitelist", "[\"example.com\"]", "blocking.allowlist"},
		{"block_mode", "nxdomain", "blocking.reply"},
		{"block_ttl", "1", "blocking.reply_ttl_seconds"},
		{"refresh_interval", "1h", "blocking.refresh_interval"},
		{"cache_dir", "/tmp", "blocking.cache_dir"},
		{"log_queries", "all", "query_log.mode"},
		{"query_privacy", "full", "query_log.clients"},
		{"query_db", "queries.db", "query_log.database"},
		{"log_file", "stdout", "query_log.file"},
		{"query_db_retention_days", "0", "query_log.retention_days"},
		{"db_flush_interval", "1s", "query_log.flush_interval"},
		{"client_names", "{\"10.0.0.1\": tv}", "query_log.client_names"},
		{"api_listen", `"0.0.0.0:8080"`, "admin.listen"},
		{"enable_pprof", "true", "admin.pprof"},
	}
	if len(cases) != 22 {
		t.Fatalf("table has %d keys, want the 22 keys of C3", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.old, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, tc.old+": "+tc.val+"\n", nil)
			if !reflect.DeepEqual(cfg, wantDefaults()) {
				t.Errorf("old key %s changed the config: %+v", tc.old, cfg)
			}
			if len(probs) != 1 || probs[0].Key != tc.old || !strings.Contains(probs[0].Detail, tc.newKey) {
				t.Errorf("problems = %v, want one for %s that names %s", probs, tc.old, tc.newKey)
			}
		})
	}
}

func TestLoad_RenamedEnvironmentVariablesAreIgnored(t *testing.T) {
	// C3: every 1.x environment variable is a problem that names the new
	// variable, and its value is ignored.
	cases := []struct{ old, val, newName string }{
		{"S_HOLE_LISTEN", "0.0.0.0:5353", "S_HOLE_DNS_LISTEN"},
		{"S_HOLE_API_LISTEN", "0.0.0.0:8080", "S_HOLE_ADMIN_LISTEN"},
		{"S_HOLE_QUERY_DB", "q.db", "S_HOLE_QUERY_LOG_DATABASE"},
		{"S_HOLE_LOG_FILE", "stdout", "S_HOLE_QUERY_LOG_FILE"},
		{"S_HOLE_LOG_QUERIES", "all", "S_HOLE_QUERY_LOG_MODE"},
		{"S_HOLE_QUERY_PRIVACY", "full", "S_HOLE_QUERY_LOG_CLIENTS"},
		{"S_HOLE_RETENTION_DAYS", "0", "S_HOLE_QUERY_LOG_RETENTION_DAYS"},
		{"S_HOLE_ENABLE_PPROF", "true", "S_HOLE_ADMIN_PPROF"},
		{"S_HOLE_LOCAL_PTR", "false", "S_HOLE_DNS_LOCAL_PTR"},
		{"S_HOLE_CACHE_SIZE", "1", "S_HOLE_DNS_CACHE_ENTRIES"},
		{"S_HOLE_BLOCK_MODE", "nxdomain", "S_HOLE_BLOCKING_REPLY"},
		{"S_HOLE_BLOCK_TTL", "1", "S_HOLE_BLOCKING_REPLY_TTL_SECONDS"},
		{"S_HOLE_REFRESH_INTERVAL", "1h", "S_HOLE_BLOCKING_REFRESH_INTERVAL"},
		{"S_HOLE_CACHE_DIR", "/tmp", "S_HOLE_BLOCKING_CACHE_DIR"},
		{"S_HOLE_DB_FLUSH_INTERVAL", "1s", "S_HOLE_QUERY_LOG_FLUSH_INTERVAL"},
		{"S_HOLE_DOT_LISTEN", ":853", "S_HOLE_DNS_DOT_LISTEN"},
		{"S_HOLE_TLS_CERT", "c.pem", "S_HOLE_DNS_DOT_CERT"},
		{"S_HOLE_TLS_KEY", "k.pem", "S_HOLE_DNS_DOT_KEY"},
	}
	if len(cases) != 18 {
		t.Fatalf("table has %d variables, want the 18 variables of C3", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.old, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, "", map[string]string{tc.old: tc.val})
			if !reflect.DeepEqual(cfg, wantDefaults()) {
				t.Errorf("%s changed the config: %+v", tc.old, cfg)
			}
			if len(probs) != 1 || probs[0].Key != tc.old || !strings.Contains(probs[0].Detail, tc.newName) {
				t.Errorf("problems = %v, want one for %s that names %s", probs, tc.old, tc.newName)
			}
		})
	}
}

func TestLoad_UnknownEnvironmentVariables(t *testing.T) {
	// C3: an unknown S_HOLE_* variable is a problem, except S_HOLE_LOG_FORMAT
	// and S_HOLE_ASCII_BANNER, which main reads. A variable without the
	// S_HOLE_ prefix is not checked.
	env := map[string]string{
		"S_HOLE_FOO":          "1",
		"S_HOLE_LOG_FORMAT":   "json",
		"S_HOLE_ASCII_BANNER": "1",
		"SHOLE_DNS_LISTEN":    "x",
		"PATH":                "/bin",
	}
	cfg, probs := mustLoadYAML(t, "", env)
	if !reflect.DeepEqual(problemKeys(probs), []string{"S_HOLE_FOO"}) {
		t.Errorf("problems = %v, want only S_HOLE_FOO", probs)
	}
	if !reflect.DeepEqual(cfg, wantDefaults()) {
		t.Errorf("config changed: %+v", cfg)
	}
}

func TestLoad_KeySetTwice(t *testing.T) {
	// C3: a key set twice is a problem, and the last value is used. A section
	// that appears twice sets its keys twice.
	cases := []struct {
		name, body string
		key        string
		get        func(*Config) any
		want       any
	}{
		{"in a section", "dns:\n  cache_entries: 5\n  cache_entries: 6\n", "dns.cache_entries", func(c *Config) any { return c.DNS.CacheEntries }, 6},
		{"section twice", "admin:\n  listen: \"127.0.0.1:1\"\nadmin:\n  listen: \"127.0.0.1:2\"\n", "admin.listen", func(c *Config) any { return c.Admin.Listen }, "127.0.0.1:2"},
		{"top level", "stats_interval: 1m\nstats_interval: 2m\n", "stats_interval", func(c *Config) any { return c.StatsInterval }, 2 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, tc.body, nil)
			if got := tc.get(cfg); got != tc.want {
				t.Errorf("%s = %v, want the last value %v", tc.key, got, tc.want)
			}
			if !reflect.DeepEqual(problemKeys(probs), []string{tc.key}) {
				t.Errorf("problems = %v, want one for %s", probs, tc.key)
			}
		})
	}
}

func TestLoad_WrongShapes(t *testing.T) {
	// C3: a section that is not a mapping, a scalar key given a list or a map,
	// and a list or map given a scalar are problems. The setting keeps its
	// default, and the load is not fatal.
	cases := []struct {
		name, body, key string
	}{
		{"section is a scalar", "dns: 5\n", "dns"},
		{"section is a list", "query_log:\n  - mode\n", "query_log"},
		{"scalar given a list", "dns:\n  listen: [\":53\"]\n", "dns.listen"},
		{"scalar given a map", "admin:\n  listen: {host: x}\n", "admin.listen"},
		{"top-level scalar given a map", "stats_interval: {a: 1}\n", "stats_interval"},
		{"list given a scalar", "dns:\n  upstreams: \"8.8.8.8:53\"\n", "dns.upstreams"},
		{"list entry is a list", "blocking:\n  lists:\n    - [a]\n", "blocking.lists"},
		{"map given a scalar", "query_log:\n  client_names: tv\n", "query_log.client_names"},
		{"map given a list", "query_log:\n  client_names: [tv]\n", "query_log.client_names"},
		{"map value is a list", "query_log:\n  client_names:\n    \"10.0.0.1\": [tv]\n", "query_log.client_names"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, tc.body, nil)
			if !reflect.DeepEqual(cfg, wantDefaults()) {
				t.Errorf("config = %+v, want the defaults", cfg)
			}
			if !reflect.DeepEqual(problemKeys(probs), []string{tc.key}) {
				t.Errorf("problems = %v, want one for %s", probs, tc.key)
			}
		})
	}
}

func TestLoad_FileThatIsNotAMappingIsIgnored(t *testing.T) {
	// A top-level list is valid YAML, so it is not fatal (C4). It is a problem,
	// and every setting keeps its default.
	cfg, probs := mustLoadYAML(t, "- dns\n- admin\n", nil)
	if len(probs) == 0 {
		t.Error("no problem reported for a file that is a list")
	}
	if !reflect.DeepEqual(cfg, wantDefaults()) {
		t.Errorf("config = %+v, want the defaults", cfg)
	}
}

func TestLoad_InvalidValuesKeepDefault(t *testing.T) {
	// C3: an invalid value is a problem, and the setting keeps its default.
	cases := []struct {
		name, key, val string
		get            func(*Config) any
	}{
		{"enum outside its set", "blocking.reply", "zero", func(c *Config) any { return c.Blocking.Reply }},
		{"enum is case-sensitive", "blocking.reply", "NXDOMAIN", func(c *Config) any { return c.Blocking.Reply }},
		{"mode is case-sensitive", "query_log.mode", "All", func(c *Config) any { return c.QueryLog.Mode }},
		{"mode outside its set", "query_log.mode", "everything", func(c *Config) any { return c.QueryLog.Mode }},
		{"clients is case-sensitive", "query_log.clients", "Full", func(c *Config) any { return c.QueryLog.Clients }},
		{"clients outside its set", "query_log.clients", "mask", func(c *Config) any { return c.QueryLog.Clients }},
		{"cache_entries not a number", "dns.cache_entries", "many", func(c *Config) any { return c.DNS.CacheEntries }},
		{"cache_entries negative", "dns.cache_entries", "-1", func(c *Config) any { return c.DNS.CacheEntries }},
		{"cache_entries fraction", "dns.cache_entries", "1.5", func(c *Config) any { return c.DNS.CacheEntries }},
		{"reply_ttl above range", "blocking.reply_ttl_seconds", "4294967296", func(c *Config) any { return c.Blocking.ReplyTTLSeconds }},
		{"reply_ttl negative", "blocking.reply_ttl_seconds", "-1", func(c *Config) any { return c.Blocking.ReplyTTLSeconds }},
		{"reply_ttl not a number", "blocking.reply_ttl_seconds", "5m", func(c *Config) any { return c.Blocking.ReplyTTLSeconds }},
		{"retention negative", "query_log.retention_days", "-1", func(c *Config) any { return c.QueryLog.RetentionDays }},
		{"retention not a number", "query_log.retention_days", "week", func(c *Config) any { return c.QueryLog.RetentionDays }},
		{"duration does not parse", "blocking.refresh_interval", "daily", func(c *Config) any { return c.Blocking.RefreshInterval }},
		{"duration has no unit", "blocking.refresh_interval", "24", func(c *Config) any { return c.Blocking.RefreshInterval }},
		{"duration zero", "query_log.flush_interval", "0s", func(c *Config) any { return c.QueryLog.FlushInterval }},
		{"duration negative", "stats_interval", "-1m", func(c *Config) any { return c.StatsInterval }},
		{"boolean other word", "dns.local_ptr", "maybe", func(c *Config) any { return c.DNS.LocalPTR }},
		{"boolean other number", "admin.pprof", "2", func(c *Config) any { return c.Admin.Pprof }},
	}
	def := wantDefaults()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, yamlFor(tc.key, tc.val), nil)
			if got, want := tc.get(cfg), tc.get(def); got != want {
				t.Errorf("%s = %v after %q, want the default %v", tc.key, got, tc.val, want)
			}
			if !reflect.DeepEqual(problemKeys(probs), []string{tc.key}) {
				t.Errorf("problems = %v, want one for %s", probs, tc.key)
			}
		})
	}
}

func TestLoad_RangeEndsAreValid(t *testing.T) {
	// The ends of each numeric range are valid values, not problems.
	body := "dns:\n  cache_entries: 0\nblocking:\n  reply_ttl_seconds: 0\nquery_log:\n  retention_days: 0\n"
	cfg, probs := mustLoadYAML(t, body, nil)
	if len(probs) != 0 {
		t.Fatalf("problems = %v, want none", probs)
	}
	if cfg.DNS.CacheEntries != 0 || cfg.Blocking.ReplyTTLSeconds != 0 || cfg.QueryLog.RetentionDays != 0 {
		t.Errorf("cache_entries=%d reply_ttl_seconds=%d retention_days=%d, want 0 each",
			cfg.DNS.CacheEntries, cfg.Blocking.ReplyTTLSeconds, cfg.QueryLog.RetentionDays)
	}
	cfg, probs = mustLoadYAML(t, "blocking:\n  reply_ttl_seconds: 4294967295\n", nil)
	if len(probs) != 0 || cfg.Blocking.ReplyTTLSeconds != 4294967295 {
		t.Errorf("reply_ttl_seconds = %d (problems %v), want 4294967295", cfg.Blocking.ReplyTTLSeconds, probs)
	}
}

func TestLoad_BooleanSpellings(t *testing.T) {
	// C3: true/false/yes/no/1/0 are booleans in any case, from YAML and from
	// the environment.
	cases := map[string]bool{
		"true": true, "TRUE": true, "True": true, "yes": true, "YES": true, "1": true,
		"false": false, "FALSE": false, "No": false, "no": false, "0": false,
	}
	for val, want := range cases {
		t.Run(val, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, "admin:\n  pprof: "+val+"\ndns:\n  local_ptr: "+val+"\n", nil)
			if len(probs) != 0 || cfg.Admin.Pprof != want || cfg.DNS.LocalPTR != want {
				t.Errorf("YAML %q: pprof=%v local_ptr=%v (problems %v), want %v", val, cfg.Admin.Pprof, cfg.DNS.LocalPTR, probs, want)
			}
			cfg, probs = mustLoadYAML(t, "", map[string]string{"S_HOLE_ADMIN_PPROF": val, "S_HOLE_DNS_LOCAL_PTR": val})
			if len(probs) != 0 || cfg.Admin.Pprof != want || cfg.DNS.LocalPTR != want {
				t.Errorf("variable %q: pprof=%v local_ptr=%v (problems %v), want %v", val, cfg.Admin.Pprof, cfg.DNS.LocalPTR, probs, want)
			}
		})
	}
}

func TestLoad_BadListenAddresses(t *testing.T) {
	// C3: an admin.listen that is not host:port falls back to 127.0.0.1:8080,
	// and a dns.dot_listen that is not host:port leaves DoT off. Neither is
	// fatal, and DoT stays off although no certificate is set.
	for _, val := range []string{"8080", "localhost", "0.0.0.0", "[::1]"} {
		t.Run("admin.listen "+val, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, yamlFor("admin.listen", `"`+val+`"`), nil)
			if cfg.Admin.Listen != "127.0.0.1:8080" {
				t.Errorf("admin.listen = %q, want 127.0.0.1:8080", cfg.Admin.Listen)
			}
			if !reflect.DeepEqual(problemKeys(probs), []string{"admin.listen"}) {
				t.Errorf("problems = %v, want one for admin.listen", probs)
			}
		})
		t.Run("dns.dot_listen "+val, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, yamlFor("dns.dot_listen", `"`+val+`"`), nil)
			if cfg.DNS.DoTListen != "" {
				t.Errorf("dns.dot_listen = %q, want off", cfg.DNS.DoTListen)
			}
			if !reflect.DeepEqual(problemKeys(probs), []string{"dns.dot_listen"}) {
				t.Errorf("problems = %v, want one for dns.dot_listen", probs)
			}
		})
	}
	// The environment variable takes the same path.
	cfg, probs := mustLoadYAML(t, "", map[string]string{"S_HOLE_ADMIN_LISTEN": "8080"})
	if cfg.Admin.Listen != "127.0.0.1:8080" || len(probs) != 1 {
		t.Errorf("S_HOLE_ADMIN_LISTEN=8080: admin.listen = %q (problems %v), want 127.0.0.1:8080 and one problem", cfg.Admin.Listen, probs)
	}
}

func TestLoad_DroppedEntriesAreProblems(t *testing.T) {
	// C3: an allowlist entry that is not a valid domain and a client_names key
	// that is not an IP or a CIDR are dropped, each as one problem.
	body := "blocking:\n  allowlist:\n    - example.com\n    - com\n    - \"bad host\"\n" +
		"query_log:\n  client_names:\n    \"10.0.0.0/8\": lan\n    printer: x\n"
	cfg, probs := mustLoadYAML(t, body, nil)
	if !reflect.DeepEqual(cfg.Blocking.Allowlist, []string{"example.com"}) {
		t.Errorf("allowlist = %v, want [example.com]", cfg.Blocking.Allowlist)
	}
	if !reflect.DeepEqual(cfg.QueryLog.ClientNames, map[string]string{"10.0.0.0/8": "lan"}) {
		t.Errorf("client_names = %v, want only the CIDR", cfg.QueryLog.ClientNames)
	}
	want := []string{"blocking.allowlist", "blocking.allowlist", "query_log.client_names"}
	if !reflect.DeepEqual(problemKeys(probs), want) {
		t.Errorf("problem keys = %v, want %v", problemKeys(probs), want)
	}
	for _, s := range []string{`"com"`, `"bad host"`, `"printer"`} {
		if !strings.Contains(problemText(probs), s) {
			t.Errorf("problems do not name %s:\n%s", s, problemText(probs))
		}
	}
}

func TestLoad_AllowlistRejectsBadLabels(t *testing.T) {
	// CL 95 (W3): an allowlist entry with an empty label or a label that
	// starts or ends with "-" is a problem that names it, and the entry is
	// dropped. Hyphens inside a label, underscore labels, and a root dot stay
	// valid.
	bad := []string{"-ads.example.com", "ads-.example.com", "a..com", "example.com..", "a.-b.com", "a.com-", "a.com-.", "-728.90."}
	good := []string{"a-b.example.com", "xn--bcher-kva.de", "_dmarc.example.com", "example.com."}
	var body strings.Builder
	body.WriteString("blocking:\n  allowlist:\n")
	for i := range bad {
		// Interleave the bad and good entries to check that order is kept.
		body.WriteString("    - \"" + bad[i] + "\"\n")
		if i < len(good) {
			body.WriteString("    - \"" + good[i] + "\"\n")
		}
	}
	cfg, probs := mustLoadYAML(t, body.String(), nil)
	if !reflect.DeepEqual(cfg.Blocking.Allowlist, good) {
		t.Errorf("allowlist = %v, want %v", cfg.Blocking.Allowlist, good)
	}
	if len(probs) != len(bad) {
		t.Errorf("got %d problems, want %d:\n%s", len(probs), len(bad), problemText(probs))
	}
	for _, p := range probs {
		if p.Key != "blocking.allowlist" {
			t.Errorf("problem key = %q, want blocking.allowlist", p.Key)
		}
	}
	for _, d := range bad {
		if !strings.Contains(problemText(probs), `"`+d+`"`) {
			t.Errorf("problems do not name %q:\n%s", d, problemText(probs))
		}
	}
	for _, d := range good {
		if strings.Contains(problemText(probs), `"`+d+`"`) {
			t.Errorf("a valid entry %q is a problem:\n%s", d, problemText(probs))
		}
	}
}

func TestLoad_MalformedUpstreamHidesQueryString(t *testing.T) {
	// C3: a malformed upstream is shown with its query string redacted, as well
	// as its user info (TestLoad_NormalizesDoHAndReportsDrops covers that).
	body := "dns:\n  upstreams:\n    - \"https://dns.example/dns-query?token=t0psecret\"\n    - \"9.9.9.9:53\"\n"
	cfg, probs := mustLoadYAML(t, body, nil)
	if !reflect.DeepEqual(cfg.DNS.Upstreams, []string{"9.9.9.9:53"}) {
		t.Errorf("upstreams = %v, want [9.9.9.9:53]", cfg.DNS.Upstreams)
	}
	if len(probs) != 1 || probs[0].Key != "dns.upstreams" {
		t.Fatalf("problems = %v, want one for dns.upstreams", probs)
	}
	if strings.Contains(probs[0].Detail, "t0psecret") {
		t.Errorf("problem shows the query string: %s", probs[0].Detail)
	}
	if !strings.Contains(probs[0].Detail, "dns.example") {
		t.Errorf("problem does not name the entry: %s", probs[0].Detail)
	}
}

func TestLoad_FatalErrors(t *testing.T) {
	// C4: only these mistakes are fatal, and a fatal error returns no config.
	dir := t.TempDir()
	cert, key := writeKeyPair(t, dir)
	otherCert, _ := writeKeyPair(t, t.TempDir())
	cases := []struct {
		name, body string
		env        map[string]string
	}{
		{"invalid YAML", "dns: [\n", nil},
		{"invalid YAML indentation", "dns:\n  listen: a\n listen: b\n", nil},
		{"dns.listen not host:port", "dns:\n  listen: \"53\"\n", nil},
		{"dns.listen from the environment", "", map[string]string{"S_HOLE_DNS_LISTEN": "localhost"}},
		{"every upstream malformed", "dns:\n  upstreams:\n    - \"8.8.8.8\"\n    - \"https://dns.example/dns-query\"\n", nil},
		{"DoT without a certificate", "dns:\n  dot_listen: \":853\"\n", nil},
		{"DoT without a key", "dns:\n  dot_listen: \":853\"\n  dot_cert: \"" + cert + "\"\n", nil},
		{"DoT without a certificate, key set", "dns:\n  dot_listen: \":853\"\n  dot_key: \"" + key + "\"\n", nil},
		{"DoT certificate file missing", "dns:\n  dot_listen: \":853\"\n  dot_cert: \"" + filepath.Join(dir, "no.pem") + "\"\n  dot_key: \"" + key + "\"\n", nil},
		{"DoT key does not match", "dns:\n  dot_listen: \":853\"\n  dot_cert: \"" + otherCert + "\"\n  dot_key: \"" + key + "\"\n", nil},
		{"DoT from the environment", "", map[string]string{"S_HOLE_DNS_DOT_LISTEN": ":853"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := loadYAML(t, tc.body, tc.env)
			if err == nil {
				t.Fatalf("load = nil error, want a fatal error")
			}
			if cfg != nil {
				t.Errorf("load returned a config with a fatal error: %+v", cfg)
			}
		})
	}
}

func TestLoad_UnreadableFileIsFatal(t *testing.T) {
	// C4: a file that cannot be read is fatal.
	dir := t.TempDir()
	for name, path := range map[string]string{
		"missing":   filepath.Join(dir, "nope.yaml"),
		"directory": dir,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, probs, err := Load(path)
			if err == nil || cfg != nil || probs != nil {
				t.Errorf("Load(%s) = (%v, %v, %v), want (nil, nil, error)", path, cfg, probs, err)
			}
		})
	}
}

func TestLoad_DoTOnWithValidPair(t *testing.T) {
	// C4 negative: DoT with a pair that loads is not fatal, and DoT turned off
	// needs no certificate.
	cert, key := writeKeyPair(t, t.TempDir())
	cfg, probs := mustLoadYAML(t, "dns:\n  dot_listen: \":853\"\n  dot_cert: \""+cert+"\"\n  dot_key: \""+key+"\"\n", nil)
	if cfg.DNS.DoTListen != ":853" || len(probs) != 0 {
		t.Errorf("dot_listen = %q (problems %v), want :853", cfg.DNS.DoTListen, probs)
	}
	cfg, probs = mustLoadYAML(t, "dns:\n  dot_listen: \"off\"\n", nil)
	if cfg.DNS.DoTListen != "" || len(probs) != 0 {
		t.Errorf("dot_listen = %q (problems %v), want off", cfg.DNS.DoTListen, probs)
	}
}

func TestLoad_OffAndStdout(t *testing.T) {
	// C5: "off" in any case, or empty, turns off dns.dot_listen,
	// query_log.database, and query_log.file. "stdout" in any case is standard
	// output; any other value is a path.
	for _, off := range []string{"off", "OFF", "Off", `""`} {
		body := "dns:\n  dot_listen: " + off + "\nquery_log:\n  database: " + off + "\n  file: " + off + "\n"
		cfg, probs := mustLoadYAML(t, body, nil)
		if len(probs) != 0 || cfg.DNS.DoTListen != "" || cfg.QueryLog.Database != "" || cfg.QueryLog.File != "" {
			t.Errorf("%s: dot_listen=%q database=%q file=%q (problems %v), want all off",
				off, cfg.DNS.DoTListen, cfg.QueryLog.Database, cfg.QueryLog.File, probs)
		}
	}
	for _, std := range []string{"stdout", "STDOUT", "Stdout"} {
		cfg, _ := mustLoadYAML(t, "query_log:\n  file: "+std+"\n", nil)
		if cfg.QueryLog.File != "stdout" {
			t.Errorf("file %s = %q, want stdout", std, cfg.QueryLog.File)
		}
	}
	cfg, _ := mustLoadYAML(t, "query_log:\n  file: logs/stdout.log\n  database: offline.db\n", nil)
	if cfg.QueryLog.File != "logs/stdout.log" || cfg.QueryLog.Database != "offline.db" {
		t.Errorf("file=%q database=%q, want the paths", cfg.QueryLog.File, cfg.QueryLog.Database)
	}
	// The environment turns an output off over the YAML.
	cfg, _ = mustLoadYAML(t, "query_log:\n  file: q.log\n  database: q.db\n",
		map[string]string{"S_HOLE_QUERY_LOG_FILE": "Off", "S_HOLE_QUERY_LOG_DATABASE": "OFF"})
	if cfg.QueryLog.File != "" || cfg.QueryLog.Database != "" {
		t.Errorf("file=%q database=%q, want both off from the environment", cfg.QueryLog.File, cfg.QueryLog.Database)
	}
	for v, want := range map[string]bool{"": true, "off": true, "OFF": true, "of": false, "stdout": false} {
		if got := IsOff(v); got != want {
			t.Errorf("IsOff(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestLoad_EmptyUpstreamListGivesDefaults(t *testing.T) {
	// C6: an empty upstream list means the defaults.
	for _, body := range []string{"dns:\n  upstreams: []\n", "dns:\n  upstreams:\n", "dns:\n  upstreams:\n    - \"\"\n"} {
		cfg, probs := mustLoadYAML(t, body, nil)
		if !reflect.DeepEqual(cfg.DNS.Upstreams, wantDefaults().DNS.Upstreams) || len(probs) != 0 {
			t.Errorf("%q: upstreams = %v (problems %v), want the defaults", body, cfg.DNS.Upstreams, probs)
		}
	}
}

func TestUpstreamNotes(t *testing.T) {
	// C7: a note for a single upstream, one when every upstream is DoH, and
	// one when DoH and plain entries are mixed. Two plain entries give none.
	cases := []struct {
		name      string
		upstreams []string
		want      int
	}{
		{"two plain", []string{"9.9.9.9:53", "1.1.1.1:53"}, 0},
		{"single plain", []string{"9.9.9.9:53"}, 1},
		{"every upstream DoH", []string{"https://9.9.9.9/dns-query", "https://1.1.1.1/dns-query"}, 1},
		{"mixed", []string{"https://9.9.9.9/dns-query", "9.9.9.9:53"}, 1},
		{"single DoH", []string{"https://9.9.9.9/dns-query"}, 2},
	}
	notes := map[string][]string{}
	for _, tc := range cases {
		c := &Config{DNS: DNS{Upstreams: tc.upstreams}}
		got := c.UpstreamNotes()
		notes[tc.name] = got
		if len(got) != tc.want {
			t.Errorf("%s: notes = %q, want %d", tc.name, got, tc.want)
		}
	}
	if len(notes["mixed"]) == 1 && !strings.Contains(notes["mixed"][0], "fallback") {
		t.Errorf("mixed note = %q, want it to say that plain upstreams are a fallback", notes["mixed"][0])
	}
	if len(notes["every upstream DoH"]) == 1 && len(notes["mixed"]) == 1 && notes["every upstream DoH"][0] == notes["mixed"][0] {
		t.Error("the DoH-only note and the mixed note are the same")
	}
	if len(notes["single plain"]) == 1 && !slices.Contains(notes["single DoH"], notes["single plain"][0]) {
		t.Errorf("single DoH notes %q do not include the single-upstream note %q", notes["single DoH"], notes["single plain"][0])
	}
	// The default list is mixed. Its note is not a problem.
	cfg, probs := mustLoadYAML(t, "", nil)
	if len(probs) != 0 || len(cfg.UpstreamNotes()) != 1 {
		t.Errorf("default config: notes = %q, problems = %v; want one note and no problem", cfg.UpstreamNotes(), probs)
	}
}

func TestSettings_CurrentDescribesTheValueInEffect(t *testing.T) {
	// Each setting describes its value in effect; a problem message quotes it
	// ("using ..."). The list and map settings count their entries.
	cfg, _ := mustLoadYAML(t, "blocking:\n  lists: [\"https://a.example/l\"]\n  allowlist: [\"a.example\", \"b.example\"]\n"+
		"query_log:\n  client_names: {\"10.0.0.1\": tv}\n", nil)
	want := map[string]string{
		"dns.listen":                 `":53"`,
		"dns.dot_listen":             "off",
		"dns.dot_cert":               `""`,
		"dns.dot_key":                `""`,
		"dns.upstreams":              "https://9.9.9.9/dns-query, https://1.1.1.1/dns-query, 9.9.9.9:53, 1.1.1.1:53",
		"dns.cache_entries":          "2000",
		"dns.local_ptr":              "true",
		"dns.local_domains":          "0 domains",
		"blocking.lists":             "1 lists",
		"blocking.allowlist":         "2 domains",
		"blocking.reply":             `"zero_ip"`,
		"blocking.reply_ttl_seconds": "300",
		"blocking.refresh_interval":  "24h0m0s",
		"blocking.cache_dir":         `"."`,
		"query_log.mode":             `"none"`,
		"query_log.clients":          `"drop"`,
		"query_log.database":         "off",
		"query_log.file":             "off",
		"query_log.retention_days":   "7",
		"query_log.flush_interval":   "30s",
		"query_log.client_names":     "1 labels",
		"admin.listen":               `"127.0.0.1:8080"`,
		"admin.pprof":                "false",
		"stats_interval":             "5m0s",
	}
	seen := 0
	for _, s := range cfg.settings() {
		w, ok := want[s.key]
		if !ok {
			t.Errorf("setting %q is not in C1", s.key)
			continue
		}
		seen++
		if got := s.current(); got != w {
			t.Errorf("%s current() = %q, want %q", s.key, got, w)
		}
	}
	if seen != len(want) {
		t.Errorf("settings() has %d of the %d keys in C1", seen, len(want))
	}
	cfg.QueryLog.Database = "q.db"
	for _, s := range cfg.settings() {
		if s.key == "query_log.database" && s.current() != `"q.db"` {
			t.Errorf("query_log.database current() = %q, want \"q.db\"", s.current())
		}
	}
}

func TestQuoteJoin(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"a"}, `"a"`},
		{[]string{"a", "b"}, `"a" or "b"`},
		{[]string{"a", "b", "c"}, `"a", "b" or "c"`},
	}
	for _, tc := range cases {
		if got := quoteJoin(tc.in); got != tc.want {
			t.Errorf("quoteJoin(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
