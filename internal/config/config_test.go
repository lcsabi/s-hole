package config

import (
	"os"
	"path/filepath"
	"testing"
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
	if cfg.Listen != "0.0.0.0:53" {
		t.Errorf("Listen default = %q, want 0.0.0.0:53", cfg.Listen)
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
		blockMode  string
		logQueries string
	}{
		{"zero", "all"},
		{"zero", "blocked"},
		{"zero", "none"},
		{"nxdomain", "all"},
	}
	for _, tc := range tests {
		t.Run(tc.blockMode+"_"+tc.logQueries, func(t *testing.T) {
			cfg := &Config{BlockMode: tc.blockMode, LogQueries: tc.logQueries}
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate(%q, %q) = %v, want nil", tc.blockMode, tc.logQueries, err)
			}
		})
	}
}

func TestValidate_RejectsBogusBlockMode(t *testing.T) {
	// Regression for b/017: typo'd block_mode must be a startup error,
	// not a silent fallback.
	cfg := &Config{BlockMode: "NXDOMAIN", LogQueries: "all"}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted bogus block_mode")
	}
}

func TestValidate_RejectsBogusLogQueries(t *testing.T) {
	cfg := &Config{BlockMode: "zero", LogQueries: "verbose"}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted bogus log_queries")
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
	cfg := &Config{RefreshInterval: "soon"}
	if _, err := cfg.ParsedRefreshInterval(); err == nil {
		t.Error("ParsedRefreshInterval accepted garbage")
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
