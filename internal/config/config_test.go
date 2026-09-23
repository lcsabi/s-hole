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
	"sort"
	"strings"
	"testing"
	"time"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoad_EmptyAppliesDefaults(t *testing.T) {
	cfg, err := Load(writeTemp(t, ""))
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	// ":53" is the dual-stack wildcard; IPv4-only "0.0.0.0:53" would
	// silently drop IPv6 clients on dual-stack LANs.
	if cfg.Listen != ":53" {
		t.Errorf("Listen default = %q, want :53 (dual-stack)", cfg.Listen)
	}
	if len(cfg.Upstreams) != 2 {
		t.Errorf("Upstreams default = %v, want 2 entries", cfg.Upstreams)
	}
	if cfg.BlockMode != "zero" {
		t.Errorf("BlockMode default = %q, want zero", cfg.BlockMode)
	}
	if cfg.LogQueries != "all" {
		t.Errorf("LogQueries default = %q, want all", cfg.LogQueries)
	}
	if cfg.QueryPrivacy != "raw" {
		t.Errorf("QueryPrivacy default = %q, want raw", cfg.QueryPrivacy)
	}
	if cfg.CacheSize != 2000 {
		t.Errorf("CacheSize default = %d, want 2000", cfg.CacheSize)
	}
	if cfg.DBFlushInterval != "30s" {
		t.Errorf("DBFlushInterval default = %q, want 30s", cfg.DBFlushInterval)
	}
	if cfg.APIListen != "127.0.0.1:8080" {
		t.Errorf("APIListen default = %q, want 127.0.0.1:8080 (R18 conservative default)", cfg.APIListen)
	}
}

func TestLoad_PartialOverridesDefaultsForSetFields(t *testing.T) {
	cfg, err := Load(writeTemp(t, "block_mode: nxdomain\ncache_size: 500\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BlockMode != "nxdomain" {
		t.Errorf("BlockMode = %q, want nxdomain", cfg.BlockMode)
	}
	if cfg.CacheSize != 500 {
		t.Errorf("CacheSize = %d, want 500", cfg.CacheSize)
	}
	// Unset field still picks up its default.
	if cfg.LogQueries != "all" {
		t.Errorf("LogQueries default = %q, want all", cfg.LogQueries)
	}
}

func TestLoad_CacheSizeZeroDisables(t *testing.T) {
	// T1 regression: an explicit `cache_size: 0` must survive Load. The
	// old post-decode applyDefaults could not tell 0-from-YAML apart from
	// an absent key and silently re-enabled the default 2000-entry cache,
	// contradicting the documented "set to 0 to disable".
	cfg, err := Load(writeTemp(t, "cache_size: 0\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CacheSize != 0 {
		t.Errorf("CacheSize = %d, want 0 (cache disabled)", cfg.CacheSize)
	}
}

func TestLoad_BlockTTLZeroHonored(t *testing.T) {
	// T1 regression, same zero-value collision as cache_size: block_ttl 0
	// is legal DNS ("do not cache this reply") and must not be promoted
	// to the 300-second default.
	cfg, err := Load(writeTemp(t, "block_ttl: 0\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BlockTTL != 0 {
		t.Errorf("BlockTTL = %d, want 0", cfg.BlockTTL)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load("/no/such/file.yaml"); err == nil {
		t.Fatal("Load on missing file should error")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	if _, err := Load(writeTemp(t, "block_mode: : :\n")); err == nil {
		t.Fatal("Load on invalid YAML should error")
	}
}

func TestValidate_AcceptsValidValues(t *testing.T) {
	tests := []struct {
		blockMode    string
		logQueries   string
		queryPrivacy string
	}{
		{"zero", "all", "raw"},
		{"zero", "blocked", "drop"},
		{"zero", "none", "subnet"},
		{"nxdomain", "all", "raw"},
	}
	for _, tc := range tests {
		t.Run(tc.blockMode+"_"+tc.logQueries+"_"+tc.queryPrivacy, func(t *testing.T) {
			// Two valid upstreams so the enum cases do not trip the empty-list
			// fatal or the single-upstream INFO note; both are exercised below.
			cfg := &Config{
				BlockMode:    tc.blockMode,
				LogQueries:   tc.logQueries,
				QueryPrivacy: tc.queryPrivacy,
				Upstreams:    []string{"1.1.1.1:53", "8.8.8.8:53"},
			}
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate(%q, %q, %q) = %v, want nil", tc.blockMode, tc.logQueries, tc.queryPrivacy, err)
			}
		})
	}
}

func TestValidate_RejectsBogusBlockMode(t *testing.T) {
	// Regression for b/017: typo'd block_mode must be a startup error,
	// not a silent fallback.
	cfg := &Config{BlockMode: "NXDOMAIN", LogQueries: "all", QueryPrivacy: "raw"}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted bogus block_mode")
	}
}

func TestValidate_RejectsBogusLogQueries(t *testing.T) {
	cfg := &Config{BlockMode: "zero", LogQueries: "verbose", QueryPrivacy: "raw"}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted bogus log_queries")
	}
}

func TestValidate_RejectsBogusQueryPrivacy(t *testing.T) {
	cfg := &Config{BlockMode: "zero", LogQueries: "all", QueryPrivacy: "anonymize"}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted bogus query_privacy")
	}
}

func TestValidate_RejectsEmptyUpstreams(t *testing.T) {
	// Load drops malformed upstreams, so an empty list reaching Validate means
	// every configured upstream was malformed. A config that cannot forward at
	// all is fatal, the same as a bad block_mode (ROADMAP #28).
	cfg := &Config{BlockMode: "zero", LogQueries: "all", QueryPrivacy: "raw"}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted a config with no usable upstream")
	}
}

func TestValidate_SingleUpstreamIsValid(t *testing.T) {
	// A single upstream is a valid setup (a deliberate local resolver). Validate
	// logs an INFO note about the missing fallback but never fails (ROADMAP #28).
	cfg := &Config{
		BlockMode:    "zero",
		LogQueries:   "all",
		QueryPrivacy: "raw",
		Upstreams:    []string{"127.0.0.1:53"},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate with one upstream = %v, want nil", err)
	}
}

func TestFilterWhitelist(t *testing.T) {
	// Whitelist entries are suffix-matched (CL 30): a bare label like a TLD
	// would exempt its whole subtree. filterWhitelist drops invalid entries
	// (Load WARNs on them) instead of aborting startup, and a dropped entry
	// fails safe: the domain stays blockable.
	// "com." is the b/040 case: a bare TLD with a trailing root dot must be
	// dropped, or normalize would store bare "com" and exempt the whole TLD.
	in := []string{"safe.doubleclick.net", "com", "com.", "example.com", "bad host"}
	valid, dropped := filterWhitelist(in)

	wantValid := []string{"safe.doubleclick.net", "example.com"}
	if !reflect.DeepEqual(valid, wantValid) {
		t.Errorf("valid = %v, want %v", valid, wantValid)
	}
	wantDropped := []string{"com", "com.", "bad host"}
	if !reflect.DeepEqual(dropped, wantDropped) {
		t.Errorf("dropped = %v, want %v", dropped, wantDropped)
	}
}

func TestFilterWhitelist_Empty(t *testing.T) {
	valid, dropped := filterWhitelist(nil)
	if valid != nil || dropped != nil {
		t.Errorf("filterWhitelist(nil) = (%v, %v), want (nil, nil)", valid, dropped)
	}
}

func TestLoad_DropsInvalidWhitelistEntries(t *testing.T) {
	path := writeTemp(t, "whitelist:\n  - example.com\n  - com\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load = %v, want nil", err)
	}
	want := []string{"example.com"}
	if !reflect.DeepEqual(cfg.Whitelist, want) {
		t.Errorf("cfg.Whitelist = %v, want %v", cfg.Whitelist, want)
	}
}

func TestFilterClientNames(t *testing.T) {
	// A key is an exact IP or a CIDR; anything else is dropped with a WARN in
	// Load. The label map is a display cosmetic, so a bad key must not abort
	// startup. Values (labels) are never validated.
	in := map[string]string{
		"192.168.1.42": "kids-ipad",
		"10.0.5.0/24":  "iot-vlan",
		"fd00::/8":     "ula",
		"not-an-ip":    "bad",
		"":             "empty-key",
	}
	valid, dropped := filterClientNames(in)

	wantValid := map[string]string{
		"192.168.1.42": "kids-ipad",
		"10.0.5.0/24":  "iot-vlan",
		"fd00::/8":     "ula",
	}
	if !reflect.DeepEqual(valid, wantValid) {
		t.Errorf("valid = %v, want %v", valid, wantValid)
	}
	sort.Strings(dropped)
	wantDropped := []string{"", "not-an-ip"}
	if !reflect.DeepEqual(dropped, wantDropped) {
		t.Errorf("dropped = %v, want %v", dropped, wantDropped)
	}
}

func TestFilterClientNames_Empty(t *testing.T) {
	// A nil map and an all-invalid map both collapse to nil ("attribution off").
	if valid, dropped := filterClientNames(nil); valid != nil || dropped != nil {
		t.Errorf("filterClientNames(nil) = (%v, %v), want (nil, nil)", valid, dropped)
	}
	if valid, _ := filterClientNames(map[string]string{"nope": "x"}); valid != nil {
		t.Errorf("all-invalid valid = %v, want nil", valid)
	}
}

func TestLoad_DropsInvalidClientNames(t *testing.T) {
	path := writeTemp(t, "client_names:\n  \"192.168.1.42\": kids-ipad\n  bogus: nope\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load = %v, want nil", err)
	}
	want := map[string]string{"192.168.1.42": "kids-ipad"}
	if !reflect.DeepEqual(cfg.ClientNames, want) {
		t.Errorf("cfg.ClientNames = %v, want %v", cfg.ClientNames, want)
	}
}

func TestFilterUpstreams(t *testing.T) {
	// Upstreams must be host:port. A bare address (no port), a missing host,
	// and a missing port are all dropped; order is preserved. This is a shape
	// check only, so a syntactically valid but unreachable address is kept.
	in := []string{"1.1.1.1:53", "1.1.1.1", "8.8.8.8:53", ":53", "1.1.1.1:", "[2001:4860:4860::8888]:53"}
	valid, dropped := filterUpstreams(in)

	wantValid := []string{"1.1.1.1:53", "8.8.8.8:53", "[2001:4860:4860::8888]:53"}
	if !reflect.DeepEqual(valid, wantValid) {
		t.Errorf("valid = %v, want %v", valid, wantValid)
	}
	wantDropped := []string{"1.1.1.1", ":53", "1.1.1.1:"}
	if !reflect.DeepEqual(dropped, wantDropped) {
		t.Errorf("dropped = %v, want %v", dropped, wantDropped)
	}
}

func TestFilterUpstreams_Empty(t *testing.T) {
	valid, dropped := filterUpstreams(nil)
	if valid != nil || dropped != nil {
		t.Errorf("filterUpstreams(nil) = (%v, %v), want (nil, nil)", valid, dropped)
	}
}

func TestFilterUpstreams_DoH(t *testing.T) {
	// A DoH endpoint with an IP host is accepted and kept in the mixed list; a
	// DoH URL with a hostname, a non-https scheme, or a malformed URL is
	// dropped. Order (DoH first, plain fallback) is preserved.
	in := []string{
		"https://1.1.1.1/dns-query",                // IP host: accepted
		"1.1.1.1:53",                               // plain fallback: accepted
		"https://cloudflare-dns.com/dns-query",     // hostname host: dropped
		"http://9.9.9.9/dns-query",                 // not https: dropped
		"https://[2606:4700:4700::1111]/dns-query", // IPv6 host: accepted
	}
	valid, dropped := filterUpstreams(in)

	wantValid := []string{"https://1.1.1.1/dns-query", "1.1.1.1:53", "https://[2606:4700:4700::1111]/dns-query"}
	if !reflect.DeepEqual(valid, wantValid) {
		t.Errorf("valid = %v, want %v", valid, wantValid)
	}
	wantDropped := []string{"https://cloudflare-dns.com/dns-query", "http://9.9.9.9/dns-query"}
	if !reflect.DeepEqual(dropped, wantDropped) {
		t.Errorf("dropped = %v, want %v", dropped, wantDropped)
	}
}

func TestLoad_AcceptsDoHUpstream(t *testing.T) {
	// A DoH IP-literal endpoint survives Load next to a plain fallback, so an
	// operator can order "DoH first, plain fallback" in one list.
	path := writeTemp(t, "upstreams:\n  - https://1.1.1.1/dns-query\n  - 1.1.1.1:53\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load = %v, want nil", err)
	}
	want := []string{"https://1.1.1.1/dns-query", "1.1.1.1:53"}
	if !reflect.DeepEqual(cfg.Upstreams, want) {
		t.Errorf("cfg.Upstreams = %v, want %v", cfg.Upstreams, want)
	}
}

func TestLoad_DropsMalformedUpstreams(t *testing.T) {
	// A malformed entry is dropped (Load WARNs on it) and the valid ones remain,
	// so one fat-finger does not take down a working config.
	path := writeTemp(t, "upstreams:\n  - 1.1.1.1:53\n  - 8.8.8.8\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load = %v, want nil", err)
	}
	want := []string{"1.1.1.1:53"}
	if !reflect.DeepEqual(cfg.Upstreams, want) {
		t.Errorf("cfg.Upstreams = %v, want %v", cfg.Upstreams, want)
	}
}

func TestParsedDurations(t *testing.T) {
	cfg := &Config{
		RefreshInterval: "1h",
		StatsInterval:   "10m",
		DBFlushInterval: "45s",
	}
	if d, err := cfg.ParsedRefreshInterval(); err != nil || d.String() != "1h0m0s" {
		t.Errorf("ParsedRefreshInterval = (%v, %v), want 1h0m0s", d, err)
	}
	if d, err := cfg.ParsedStatsInterval(); err != nil || d.String() != "10m0s" {
		t.Errorf("ParsedStatsInterval = (%v, %v), want 10m0s", d, err)
	}
	if d, err := cfg.ParsedDBFlushInterval(); err != nil || d.String() != "45s" {
		t.Errorf("ParsedDBFlushInterval = (%v, %v), want 45s", d, err)
	}
}

func TestParsedDurations_InvalidErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		call func(*Config) error
	}{
		{
			name: "refresh_interval",
			cfg:  &Config{RefreshInterval: "soon"},
			call: func(c *Config) error { _, e := c.ParsedRefreshInterval(); return e },
		},
		{
			name: "stats_interval",
			cfg:  &Config{StatsInterval: "soonish"},
			call: func(c *Config) error { _, e := c.ParsedStatsInterval(); return e },
		},
		{
			name: "db_flush_interval",
			cfg:  &Config{DBFlushInterval: "later"},
			call: func(c *Config) error { _, e := c.ParsedDBFlushInterval(); return e },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(tc.cfg); err == nil {
				t.Errorf("%s parser accepted garbage", tc.name)
			}
		})
	}
}

func TestLoadAndValidate_HappyPathReturnsDurations(t *testing.T) {
	// An empty config decodes to all defaults, which are valid; the helper must
	// return the parsed default durations (24h / 5m / 30s) with no error.
	cfg, refresh, stats, dbFlush, err := LoadAndValidate(writeTemp(t, ""))
	if err != nil {
		t.Fatalf("LoadAndValidate on defaults: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadAndValidate returned nil config on success")
	}
	if refresh != 24*time.Hour {
		t.Errorf("refresh = %v, want 24h", refresh)
	}
	if stats != 5*time.Minute {
		t.Errorf("stats = %v, want 5m", stats)
	}
	if dbFlush != 30*time.Second {
		t.Errorf("dbFlush = %v, want 30s", dbFlush)
	}
}

func TestLoadAndValidate_RejectsEachStage(t *testing.T) {
	// One case per stage of the startup sequence, so a config the installer's
	// -check-config dry-run accepts is one the service will start on (ROADMAP #27).
	cases := []struct {
		name string
		yaml string
	}{
		{"load_bad_yaml", "block_mode: : :\n"},
		{"validate_bad_block_mode", "block_mode: bogus\n"},
		{"validate_bad_query_privacy", "query_privacy: anonymize\n"},
		{"validate_all_malformed_upstreams", "upstreams:\n  - 1.1.1.1\n  - 8.8.8.8\n"},
		{"duration_bad_refresh", "refresh_interval: soon\n"},
		{"duration_nonpositive_refresh", "refresh_interval: 0s\n"},
		{"duration_bad_stats", "stats_interval: soon\n"},
		{"duration_nonpositive_stats", "stats_interval: -5s\n"},
		{"duration_nonpositive_db_flush", "db_flush_interval: 0s\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, refresh, stats, dbFlush, err := LoadAndValidate(writeTemp(t, tc.yaml))
			if err == nil {
				t.Fatalf("LoadAndValidate(%q) = nil error, want rejection", tc.yaml)
			}
			// On failure every value is the zero value, so a caller cannot
			// mistake a partial result for a valid one.
			if cfg != nil || refresh != 0 || stats != 0 || dbFlush != 0 {
				t.Errorf("LoadAndValidate error path returned non-zero values: cfg=%v r=%v s=%v d=%v",
					cfg, refresh, stats, dbFlush)
			}
		})
	}
}

func TestLoadAndValidate_MissingFile(t *testing.T) {
	if _, _, _, _, err := LoadAndValidate(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("LoadAndValidate on missing file should error")
	}
}

func TestParsedDBFlushInterval_RejectsNonPositive(t *testing.T) {
	// A well-formed but non-positive interval must be rejected here so main's
	// config-error path logs and exits, instead of panicking the DB writer
	// goroutine on time.NewTicker later (b/046).
	for _, v := range []string{"0s", "-5s"} {
		t.Run("value="+v, func(t *testing.T) {
			cfg := &Config{DBFlushInterval: v}
			if _, err := cfg.ParsedDBFlushInterval(); err == nil {
				t.Errorf("ParsedDBFlushInterval(%q) = nil error, want non-positive rejected", v)
			}
		})
	}
}

func TestParsedRefreshStatsInterval_RejectNonPositive(t *testing.T) {
	// b/055: refresh_interval and stats_interval also feed time.NewTicker in
	// runTicker, which panics on a non-positive duration. They must be rejected
	// at the same gate as db_flush_interval so -check-config and startup fail
	// cleanly instead of crashing a ticker goroutine after the service is up.
	for _, v := range []string{"0s", "-5s"} {
		t.Run("refresh="+v, func(t *testing.T) {
			cfg := &Config{RefreshInterval: v}
			if _, err := cfg.ParsedRefreshInterval(); err == nil {
				t.Errorf("ParsedRefreshInterval(%q) = nil error, want non-positive rejected", v)
			}
		})
		t.Run("stats="+v, func(t *testing.T) {
			cfg := &Config{StatsInterval: v}
			if _, err := cfg.ParsedStatsInterval(); err == nil {
				t.Errorf("ParsedStatsInterval(%q) = nil error, want non-positive rejected", v)
			}
		})
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	// R5: S_HOLE_* env vars must override the corresponding YAML fields
	// after applyDefaults. Each env var is cleared at test exit via
	// t.Setenv so other tests are unaffected.
	t.Setenv("S_HOLE_LISTEN", "127.0.0.1:5354")
	t.Setenv("S_HOLE_API_LISTEN", "127.0.0.1:9090")
	t.Setenv("S_HOLE_CACHE_SIZE", "777")
	t.Setenv("S_HOLE_BLOCK_TTL", "120")
	t.Setenv("S_HOLE_RETENTION_DAYS", "14")

	cfg, err := Load(writeTemp(t, ""))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:5354" {
		t.Errorf("Listen = %q, want override 127.0.0.1:5354", cfg.Listen)
	}
	if cfg.APIListen != "127.0.0.1:9090" {
		t.Errorf("APIListen = %q, want override 127.0.0.1:9090", cfg.APIListen)
	}
	if cfg.CacheSize != 777 {
		t.Errorf("CacheSize = %d, want override 777", cfg.CacheSize)
	}
	if cfg.BlockTTL != 120 {
		t.Errorf("BlockTTL = %d, want override 120", cfg.BlockTTL)
	}
	if cfg.QueryDBRetentionDays != 14 {
		t.Errorf("QueryDBRetentionDays = %d, want override 14", cfg.QueryDBRetentionDays)
	}
}

func TestApplyEnvOverrides_AllStringFields(t *testing.T) {
	t.Setenv("S_HOLE_LOG_FILE", "/var/log/x.log")
	t.Setenv("S_HOLE_LOG_QUERIES", "blocked")
	t.Setenv("S_HOLE_QUERY_PRIVACY", "subnet")
	t.Setenv("S_HOLE_QUERY_DB", "/data/q.db")
	t.Setenv("S_HOLE_CACHE_DIR", "/data/cache")
	t.Setenv("S_HOLE_BLOCK_MODE", "nxdomain")
	t.Setenv("S_HOLE_REFRESH_INTERVAL", "12h")
	t.Setenv("S_HOLE_STATS_INTERVAL", "1m")
	t.Setenv("S_HOLE_DB_FLUSH_INTERVAL", "1s")
	t.Setenv("S_HOLE_DOT_LISTEN", ":8853")
	t.Setenv("S_HOLE_TLS_CERT", "/etc/s-hole/cert.pem")
	t.Setenv("S_HOLE_TLS_KEY", "/etc/s-hole/key.pem")

	cfg, err := Load(writeTemp(t, ""))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]string{
		"LogFile":         cfg.LogFile,
		"LogQueries":      cfg.LogQueries,
		"QueryPrivacy":    cfg.QueryPrivacy,
		"QueryDB":         cfg.QueryDB,
		"CacheDir":        cfg.CacheDir,
		"BlockMode":       cfg.BlockMode,
		"RefreshInterval": cfg.RefreshInterval,
		"StatsInterval":   cfg.StatsInterval,
		"DBFlushInterval": cfg.DBFlushInterval,
		"DoTListen":       cfg.DoTListen,
		"TLSCert":         cfg.TLSCert,
		"TLSKey":          cfg.TLSKey,
	}
	expected := map[string]string{
		"LogFile":         "/var/log/x.log",
		"LogQueries":      "blocked",
		"QueryPrivacy":    "subnet",
		"QueryDB":         "/data/q.db",
		"CacheDir":        "/data/cache",
		"BlockMode":       "nxdomain",
		"RefreshInterval": "12h",
		"StatsInterval":   "1m",
		"DBFlushInterval": "1s",
		"DoTListen":       ":8853",
		"TLSCert":         "/etc/s-hole/cert.pem",
		"TLSKey":          "/etc/s-hole/key.pem",
	}
	for k, v := range expected {
		if want[k] != v {
			t.Errorf("%s = %q, want %q", k, want[k], v)
		}
	}
}

func TestApplyEnvOverrides_EnablePprof(t *testing.T) {
	// Recognised tokens (1/true/yes and 0/false/no) set pprof case-insensitively.
	// An empty or unrecognised value leaves the default (false) in place (b/047).
	cases := []struct {
		value string
		want  bool
	}{
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"yes", true},
		{"0", false},
		{"false", false},
		{"no", false},
		{"", false},        // unrecognised: default (false) preserved
		{"garbage", false}, // unrecognised: default preserved
	}
	for _, tc := range cases {
		t.Run("value="+tc.value, func(t *testing.T) {
			t.Setenv("S_HOLE_ENABLE_PPROF", tc.value)
			cfg, err := Load(writeTemp(t, ""))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.EnablePprof != tc.want {
				t.Errorf("EnablePprof = %v for env=%q, want %v",
					cfg.EnablePprof, tc.value, tc.want)
			}
		})
	}
}

func TestLoad_LocalPTRDefaultTrue(t *testing.T) {
	// local_ptr defaults to true (RFC 6303 private-range PTR answering on).
	// This requires seeding it before the YAML decode because the zero value
	// of bool is false, which is the opt-out, not the default.
	cfg, err := Load(writeTemp(t, ""))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.LocalPTR {
		t.Error("LocalPTR default = false, want true")
	}
}

func TestLoad_LocalPTRFalseHonored(t *testing.T) {
	// An explicit `local_ptr: false` in the YAML must survive the decode
	// and not be promoted back to the default true.
	cfg, err := Load(writeTemp(t, "local_ptr: false\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LocalPTR {
		t.Error("LocalPTR = true after explicit false in YAML")
	}
}

func TestApplyEnvOverrides_LocalPTR(t *testing.T) {
	// local_ptr defaults to true. Recognised tokens set it case-insensitively;
	// an empty or unrecognised value must leave the default in place, never flip
	// a default-on privacy feature off (b/047).
	cases := []struct {
		value string
		want  bool
	}{
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"yes", true},
		{"Yes", true},
		{"0", false},
		{"false", false},
		{"no", false},
		{"NO", false},
		{"", true},        // unrecognised: default (true) preserved
		{"garbage", true}, // unrecognised: default preserved, not flipped off
	}
	for _, tc := range cases {
		t.Run("value="+tc.value, func(t *testing.T) {
			t.Setenv("S_HOLE_LOCAL_PTR", tc.value)
			cfg, err := Load(writeTemp(t, ""))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.LocalPTR != tc.want {
				t.Errorf("LocalPTR = %v for env=%q, want %v",
					cfg.LocalPTR, tc.value, tc.want)
			}
		})
	}
}

func TestApplyEnvOverrides_IgnoresMalformedNumerics(t *testing.T) {
	// A bogus CACHE_SIZE should leave the default in place, not zero it
	// or crash startup. Same for BLOCK_TTL and RETENTION_DAYS.
	t.Setenv("S_HOLE_CACHE_SIZE", "not-a-number")
	cfg, err := Load(writeTemp(t, ""))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CacheSize != 2000 {
		t.Errorf("CacheSize = %d, want default 2000 (malformed env ignored)", cfg.CacheSize)
	}
}

// writeKeyPair writes a self-signed ECDSA certificate and its private key as
// PEM files in dir and returns the two paths. Validate only needs a pair that
// tls.LoadX509KeyPair accepts, so the certificate fields are minimal.
func writeKeyPair(t *testing.T, dir, prefix string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dns.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
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
	certFile = filepath.Join(dir, prefix+"cert.pem")
	keyFile = filepath.Join(dir, prefix+"key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestValidate_DoT(t *testing.T) {
	// dot_listen turns DoT on, and then Validate requires a loadable
	// certificate and key, so -check-config catches a bad pair before the
	// service starts. With DoT off, the TLS paths are ignored.
	dir := t.TempDir()
	certFile, keyFile := writeKeyPair(t, dir, "a-")
	otherCert, _ := writeKeyPair(t, dir, "b-")

	cases := []struct {
		name    string
		listen  string
		cert    string
		key     string
		wantErr string // substring; "" means Validate must pass
	}{
		{"off ignores tls paths", "", "/no/such/cert.pem", "", ""},
		{"valid pair", ":853", certFile, keyFile, ""},
		{"address without port", "853", certFile, keyFile, "dot_listen"},
		{"address with empty port", "0.0.0.0:", certFile, keyFile, "dot_listen"},
		{"missing key", ":853", certFile, "", "tls_cert and tls_key are required"},
		{"missing cert", ":853", "", keyFile, "tls_cert and tls_key are required"},
		{"unreadable files", ":853", filepath.Join(dir, "nope.pem"), keyFile, "cannot load the DoT certificate"},
		{"mismatched key", ":853", otherCert, keyFile, "cannot load the DoT certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				BlockMode:    "zero",
				LogQueries:   "all",
				QueryPrivacy: "raw",
				Upstreams:    []string{"1.1.1.1:53", "8.8.8.8:53"},
				DoTListen:    tc.listen,
				TLSCert:      tc.cert,
				TLSKey:       tc.key,
			}
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("Validate = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}
