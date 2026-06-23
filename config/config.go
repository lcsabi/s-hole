package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

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
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &Config{}
	if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	return cfg, nil
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
		c.APIListen = "0.0.0.0:8080"
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

func (c *Config) ParsedDBFlushInterval() (time.Duration, error) {
	d, err := time.ParseDuration(c.DBFlushInterval)
	if err != nil {
		return 0, fmt.Errorf("db_flush_interval %q: %w", c.DBFlushInterval, err)
	}
	return d, nil
}

func (c *Config) ParsedRefreshInterval() (time.Duration, error) {
	d, err := time.ParseDuration(c.RefreshInterval)
	if err != nil {
		return 0, fmt.Errorf("refresh_interval %q: %w", c.RefreshInterval, err)
	}
	return d, nil
}

func (c *Config) ParsedStatsInterval() (time.Duration, error) {
	d, err := time.ParseDuration(c.StatsInterval)
	if err != nil {
		return 0, fmt.Errorf("stats_interval %q: %w", c.StatsInterval, err)
	}
	return d, nil
}
