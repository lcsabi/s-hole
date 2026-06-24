// Package config loads s-hole's YAML configuration, applies safe defaults
// for every field (an empty config file is valid), validates enumerated
// values, and finally applies environment-variable overrides (S_HOLE_*)
// so container deployments can tune the binary without rebuilding a
// bind-mounted config. Duration fields are stored as strings and parsed
// lazily via ParsedXxx helpers so a malformed duration produces a
// precise startup error.
//
// Precedence (highest wins): S_HOLE_* env vars > YAML file > built-in
// defaults. Validate runs explicitly after Load and reports unrecognised
// enum values as fatal startup errors rather than letting them silently
// fall back to defaults.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the in-memory representation of config.yaml. All fields have
// safe defaults applied by applyDefaults; enumerated fields are checked
// by Validate. See config.yaml in the repo root for documentation of each
// field.
type Config struct {
	Listen          string   `yaml:"listen"`
	Upstreams       []string `yaml:"upstreams"`
	Blocklists      []string `yaml:"blocklists"`
	Whitelist       []string `yaml:"whitelist"`
	LogFile         string   `yaml:"log_file"`
	CacheDir        string   `yaml:"cache_dir"`
	RefreshInterval string   `yaml:"refresh_interval"`
	StatsInterval   string   `yaml:"stats_interval"`
	// BlockMode controls what blocked queries return: "zero" (0.0.0.0) or "nxdomain"
	BlockMode  string `yaml:"block_mode"`
	BlockTTL   uint32 `yaml:"block_ttl"`
	// LogQueries controls which queries are written to the log: "all", "blocked", or "none"
	LogQueries string `yaml:"log_queries"`
	// QueryDB is a path to a SQLite file for persistent query logging; empty disables it
	QueryDB string `yaml:"query_db"`
	// APIListen is the address:port for the admin HTTP server
	APIListen string `yaml:"api_listen"`
	// CacheSize is the maximum number of DNS responses held in memory.
	// Set to 0 to disable the cache.
	CacheSize int `yaml:"cache_size"`
	// DBFlushInterval controls how often batched queries are written to SQLite.
	// Longer values reduce SD card writes on embedded hardware.
	DBFlushInterval string `yaml:"db_flush_interval"`
	// QueryDBRetentionDays caps how long query rows are kept in SQLite. A
	// background prune deletes rows older than this. 0 = retain forever.
	QueryDBRetentionDays int `yaml:"query_db_retention_days"`
}

// Load reads and parses the YAML config at path. Missing fields receive
// their default values. Callers should invoke Validate on the result
// before constructing any runtime objects.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &Config{}
	// An empty file decodes to io.EOF; we treat that as "no overrides" and
	// fall through to applyDefaults — the README states an empty config is
	// valid.
	if err := yaml.NewDecoder(f).Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	cfg.applyDefaults()
	cfg.applyEnvOverrides()
	return cfg, nil
}

// applyEnvOverrides reads S_HOLE_* environment variables and overrides
// the corresponding YAML fields. Container deployments use this to avoid
// rebuilding a config bind-mount for every change. Unknown keys are
// ignored; malformed numeric values are silently ignored to preserve
// startup (a warn-level slog message would also work but the config
// package deliberately avoids logging).
//
// Supported overrides:
//
//	S_HOLE_LISTEN              → listen
//	S_HOLE_API_LISTEN          → api_listen
//	S_HOLE_LOG_FILE            → log_file
//	S_HOLE_LOG_QUERIES         → log_queries
//	S_HOLE_QUERY_DB            → query_db
//	S_HOLE_CACHE_DIR           → cache_dir
//	S_HOLE_BLOCK_MODE          → block_mode
//	S_HOLE_REFRESH_INTERVAL    → refresh_interval
//	S_HOLE_STATS_INTERVAL      → stats_interval
//	S_HOLE_DB_FLUSH_INTERVAL   → db_flush_interval
//	S_HOLE_CACHE_SIZE          → cache_size (integer)
//	S_HOLE_BLOCK_TTL           → block_ttl  (integer)
//	S_HOLE_RETENTION_DAYS      → query_db_retention_days (integer)
func (c *Config) applyEnvOverrides() {
	if v, ok := os.LookupEnv("S_HOLE_LISTEN"); ok {
		c.Listen = v
	}
	if v, ok := os.LookupEnv("S_HOLE_API_LISTEN"); ok {
		c.APIListen = v
	}
	if v, ok := os.LookupEnv("S_HOLE_LOG_FILE"); ok {
		c.LogFile = v
	}
	if v, ok := os.LookupEnv("S_HOLE_LOG_QUERIES"); ok {
		c.LogQueries = v
	}
	if v, ok := os.LookupEnv("S_HOLE_QUERY_DB"); ok {
		c.QueryDB = v
	}
	if v, ok := os.LookupEnv("S_HOLE_CACHE_DIR"); ok {
		c.CacheDir = v
	}
	if v, ok := os.LookupEnv("S_HOLE_BLOCK_MODE"); ok {
		c.BlockMode = v
	}
	if v, ok := os.LookupEnv("S_HOLE_REFRESH_INTERVAL"); ok {
		c.RefreshInterval = v
	}
	if v, ok := os.LookupEnv("S_HOLE_STATS_INTERVAL"); ok {
		c.StatsInterval = v
	}
	if v, ok := os.LookupEnv("S_HOLE_DB_FLUSH_INTERVAL"); ok {
		c.DBFlushInterval = v
	}
	if v, ok := os.LookupEnv("S_HOLE_CACHE_SIZE"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			c.CacheSize = n
		}
	}
	if v, ok := os.LookupEnv("S_HOLE_BLOCK_TTL"); ok {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			c.BlockTTL = uint32(n)
		}
	}
	if v, ok := os.LookupEnv("S_HOLE_RETENTION_DAYS"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			c.QueryDBRetentionDays = n
		}
	}
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = "0.0.0.0:53"
	}
	if len(c.Upstreams) == 0 {
		c.Upstreams = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	if c.CacheDir == "" {
		c.CacheDir = "."
	}
	if c.RefreshInterval == "" {
		c.RefreshInterval = "24h"
	}
	if c.StatsInterval == "" {
		c.StatsInterval = "5m"
	}
	if c.BlockMode == "" {
		c.BlockMode = "zero"
	}
	if c.BlockTTL == 0 {
		c.BlockTTL = 300
	}
	if c.LogQueries == "" {
		c.LogQueries = "all"
	}
	if c.APIListen == "" {
		// Localhost-only default: the admin UI is unauthenticated and
		// exposing it to the LAN should be an opt-in. Operators who want
		// LAN access set api_listen: "0.0.0.0:8080" explicitly.
		c.APIListen = "127.0.0.1:8080"
	}
	if c.CacheSize == 0 {
		c.CacheSize = 2000
	}
	if c.DBFlushInterval == "" {
		c.DBFlushInterval = "30s"
	}
}

// Validate checks enumerated fields and returns an error on invalid values.
func (c *Config) Validate() error {
	switch c.BlockMode {
	case "zero", "nxdomain":
	default:
		return fmt.Errorf("block_mode %q: must be \"zero\" or \"nxdomain\"", c.BlockMode)
	}
	switch c.LogQueries {
	case "all", "blocked", "none":
	default:
		return fmt.Errorf("log_queries %q: must be \"all\", \"blocked\", or \"none\"", c.LogQueries)
	}
	return nil
}

// ParsedDBFlushInterval parses DBFlushInterval as a Go duration string
// (e.g. "30s", "5m"). Returns a descriptive error on malformed input.
func (c *Config) ParsedDBFlushInterval() (time.Duration, error) {
	d, err := time.ParseDuration(c.DBFlushInterval)
	if err != nil {
		return 0, fmt.Errorf("db_flush_interval %q: %w", c.DBFlushInterval, err)
	}
	return d, nil
}

// ParsedRefreshInterval parses RefreshInterval as a Go duration string
// (e.g. "24h", "1h"). Returns a descriptive error on malformed input.
func (c *Config) ParsedRefreshInterval() (time.Duration, error) {
	d, err := time.ParseDuration(c.RefreshInterval)
	if err != nil {
		return 0, fmt.Errorf("refresh_interval %q: %w", c.RefreshInterval, err)
	}
	return d, nil
}

// ParsedStatsInterval parses StatsInterval as a Go duration string
// (e.g. "5m", "1h"). Returns a descriptive error on malformed input.
func (c *Config) ParsedStatsInterval() (time.Duration, error) {
	d, err := time.ParseDuration(c.StatsInterval)
	if err != nil {
		return 0, fmt.Errorf("stats_interval %q: %w", c.StatsInterval, err)
	}
	return d, nil
}
