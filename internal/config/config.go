// Package config loads s-hole's YAML configuration and applies safe
// defaults for every field (an empty config file is valid): two
// zero-is-meaningful fields are seeded before the decode (see Load),
// the rest are filled in by applyDefaults afterwards, and finally
// environment-variable overrides (S_HOLE_*) are applied so container
// deployments can tune the binary without rebuilding a bind-mounted
// config. Duration fields are stored as strings and parsed lazily via
// ParsedXxx helpers so a malformed duration produces a precise startup
// error.
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
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/lcsabi/s-hole/internal/blocklist"
)

var logger = slog.With("pkg", "config")

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
	BlockMode string `yaml:"block_mode"`
	// BlockTTL is the TTL (seconds) advertised on blocked replies. An
	// explicit 0 is honored: it tells clients not to cache the sinkhole
	// answer at all, so whitelist changes take effect immediately.
	BlockTTL uint32 `yaml:"block_ttl"`
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
	// EnablePprof exposes net/http/pprof handlers under /debug/pprof/ on
	// the admin HTTP server. Off by default; only enable when investigating
	// a running incident, and only when the admin server is bound to
	// localhost; pprof reveals enough internal state to be useful to an
	// attacker who can reach it.
	EnablePprof bool `yaml:"enable_pprof"`
	// LocalPTR enables local authoritative NXDOMAIN replies for PTR queries
	// targeting RFC 6303 private-range reverse zones (10/8, 172.16/12,
	// 192.168/16, fc00::/7, fe80::/10). No public resolver can answer these
	// queries; forwarding them wastes a round-trip and leaks LAN addressing
	// to the upstream resolver. Set to false only if you run a private
	// reverse DNS zone on your LAN and want those queries forwarded.
	LocalPTR bool `yaml:"local_ptr"`
}

// Defaults for the two fields whose zero value is itself a meaningful
// setting (cache_size 0 disables the cache; block_ttl 0 disables client
// caching of sinkhole replies). They are seeded onto the struct before
// the YAML decode; a post-decode fixup cannot tell an explicit 0 in the
// file apart from an absent key, and would silently re-apply the default
// (finding T1). All other defaults live in applyDefaults.
const (
	defaultCacheSize = 2000
	defaultBlockTTL  = 300
)

// Load reads and parses the YAML config at path. Missing fields receive
// their default values. Callers should invoke Validate on the result
// before constructing any runtime objects.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Seed zero-is-meaningful defaults before decoding; see the constant
	// block above for why CacheSize and BlockTTL cannot go through
	// applyDefaults. LocalPTR is seeded here for the same reason: its zero
	// value (false) is a meaningful opt-out, and applyDefaults cannot
	// distinguish an explicit `local_ptr: false` from an absent key.
	cfg := &Config{
		CacheSize: defaultCacheSize,
		BlockTTL:  defaultBlockTTL,
		LocalPTR:  true,
	}
	// An empty file decodes to io.EOF; we treat that as "no overrides" and
	// fall through to applyDefaults; the README states an empty config is
	// valid.
	if err := yaml.NewDecoder(f).Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	cfg.applyDefaults()
	cfg.applyEnvOverrides()
	// Drop invalid whitelist entries with a WARN rather than aborting: a
	// whitelist typo must not take DNS down for the whole LAN, and a dropped
	// entry fails safe (the domain stays blockable). See filterWhitelist.
	var dropped []string
	cfg.Whitelist, dropped = filterWhitelist(cfg.Whitelist)
	for _, d := range dropped {
		logger.Warn("ignoring invalid whitelist entry", "entry", d)
	}
	return cfg, nil
}

// filterWhitelist splits entries into those that pass blocklist.ValidDomain
// and those that do not, preserving order. Whitelist matching is
// suffix-based (CL 30), so an invalid entry such as a bare TLD would exempt
// its whole subtree; Load drops the invalid ones (with a WARN) instead of
// making one typo a fatal startup error. This mirrors the blocklist loader,
// which likewise skips tokens that fail ValidDomain, and uses the same rule
// the REST /api/whitelist handler applies to interactive additions.
func filterWhitelist(entries []string) (valid, dropped []string) {
	for _, d := range entries {
		if blocklist.ValidDomain(d) {
			valid = append(valid, d)
		} else {
			dropped = append(dropped, d)
		}
	}
	return valid, dropped
}

// applyEnvOverrides reads S_HOLE_* environment variables and overrides
// the corresponding YAML fields. Container deployments use this to avoid
// rebuilding a config bind-mount for every change. Unknown keys are
// ignored; malformed numeric values and unrecognised boolean values are
// silently ignored to preserve startup (a bad boolean keeps the current
// setting rather than flipping it, b/047). Env overrides are best-effort
// container knobs (an orchestrator
// may inject a stray value), so a per-typo WARN on every restart is noise,
// not signal; the invariant is only that a bad env var never blocks
// startup. The invalid-whitelist path in Load does WARN (CL 31), because a
// silently dropped whitelist entry can widen blocking to a whole subtree.
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
//	S_HOLE_ENABLE_PPROF        → enable_pprof (1/true/yes turns it on, case-insensitive)
//	S_HOLE_LOCAL_PTR           → local_ptr    (1/true/yes keeps it on; 0/false/no opts out; case-insensitive)
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
	if v, ok := os.LookupEnv("S_HOLE_ENABLE_PPROF"); ok {
		c.EnablePprof = parseBoolEnv(v, c.EnablePprof)
	}
	if v, ok := os.LookupEnv("S_HOLE_LOCAL_PTR"); ok {
		c.LocalPTR = parseBoolEnv(v, c.LocalPTR)
	}
}

// parseBoolEnv reads a boolean env override. It accepts the documented tokens
// (1/true/yes and 0/false/no) case-insensitively and returns def on anything
// else, so an unrecognised value never flips the setting. This is not
// strconv.ParseBool: that rejects yes/no, which the README documents for these
// vars, so it would break documented input and silently flip the default.
func parseBoolEnv(v string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	default:
		return def
	}
}

// applyDefaults fills every field whose zero value is NOT a meaningful
// setting. CacheSize, BlockTTL, and LocalPTR are deliberately absent:
// their defaults are seeded in Load before the YAML decode so an explicit
// 0 / false in the file is honored (see the constant block above).
func (c *Config) applyDefaults() {
	if c.Listen == "" {
		// ":53" binds a dual-stack wildcard socket (IPv4 + IPv6) on every
		// mainstream OS. The old "0.0.0.0:53" default was IPv4-only, which
		// silently ignored clients that query over IPv6 on dual-stack LANs.
		c.Listen = ":53"
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
	if c.LogQueries == "" {
		c.LogQueries = "all"
	}
	if c.APIListen == "" {
		// Localhost-only default: the admin UI is unauthenticated and
		// exposing it to the LAN should be an opt-in. Operators who want
		// LAN access set api_listen: "0.0.0.0:8080" explicitly.
		c.APIListen = "127.0.0.1:8080"
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
	// A non-positive interval is well-formed but unusable: it panics
	// time.NewTicker in the DB writer goroutine. Reject it here so main's
	// config-error path logs and exits cleanly, the same as a malformed
	// duration string (b/046).
	if d <= 0 {
		return 0, fmt.Errorf("db_flush_interval %q: must be positive", c.DBFlushInterval)
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

// parsedDurations parses the three duration fields in the order startup needs
// them, returning the first error. Each field error names itself, so the
// caller logs it once rather than per field.
func (c *Config) parsedDurations() (refresh, stats, dbFlush time.Duration, err error) {
	if refresh, err = c.ParsedRefreshInterval(); err != nil {
		return 0, 0, 0, err
	}
	if stats, err = c.ParsedStatsInterval(); err != nil {
		return 0, 0, 0, err
	}
	if dbFlush, err = c.ParsedDBFlushInterval(); err != nil {
		return 0, 0, 0, err
	}
	return refresh, stats, dbFlush, nil
}

// LoadAndValidate loads the config at path, validates its enumerated fields,
// and parses the three duration fields, returning the parsed durations. It is
// the single startup sequence main runs, so a `-check-config` dry-run and the
// running service accept and reject exactly the same configs; there is no
// second copy of the sequence to drift.
func LoadAndValidate(path string) (cfg *Config, refresh, stats, dbFlush time.Duration, err error) {
	cfg, err = Load(path)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	if err = cfg.Validate(); err != nil {
		return nil, 0, 0, 0, err
	}
	refresh, stats, dbFlush, err = cfg.parsedDurations()
	if err != nil {
		return nil, 0, 0, 0, err
	}
	return cfg, refresh, stats, dbFlush, nil
}
