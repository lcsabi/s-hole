// Package config loads s-hole's YAML configuration.
//
// The file has four sections and one top-level key:
//
//	dns:        how s-hole listens and forwards (listen, dot_listen, dot_cert,
//	            dot_key, upstreams, cache_entries, local_ptr)
//	blocking:   what s-hole blocks (lists, allowlist, reply, reply_ttl_seconds,
//	            refresh_interval, cache_dir)
//	query_log:  what s-hole records about queries (mode, clients, database,
//	            file, retention_days, flush_interval, client_names)
//	admin:      the dashboard and REST API (listen, pprof)
//	stats_interval
//
// Every setting has a default, so an empty file is valid. The defaults are
// the most private choice for every setting: s-hole records no queries and
// no client addresses until the operator opts in.
//
// Precedence (highest wins): S_HOLE_* environment variables > YAML file >
// defaults. A scalar setting has an environment variable named after its key
// path, for example dns.listen is S_HOLE_DNS_LISTEN. Lists and maps
// (upstreams, lists, allowlist, client_names) have none.
//
// A mistake in the config never takes DNS down and never makes s-hole less
// private. Load reports each unknown key, each key renamed since s-hole 1.x,
// and each invalid value as a Problem, and keeps the default for that
// setting. Startup logs the problems as warnings and runs; -check-config
// fails on any problem, so an operator catches a typo before a restart. Only
// three mistakes are fatal, because nothing can work without the setting: a
// malformed dns.listen, an upstream list in which every entry is malformed,
// and a DoT certificate pair that cannot load while DoT is on.
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lcsabi/s-hole/internal/blocklist"
	"gopkg.in/yaml.v3"
)

// Config is the loaded configuration with every value parsed and checked.
type Config struct {
	DNS           DNS
	Blocking      Blocking
	QueryLog      QueryLog
	Admin         Admin
	StatsInterval time.Duration
}

// DNS holds the dns: section.
type DNS struct {
	// Listen is the address:port for plain DNS over UDP and TCP.
	Listen string
	// DoTListen is the address:port for DNS over TLS; empty when DoT is off.
	// DoTCert and DoTKey are the PEM certificate and key DoT presents. They are
	// read at startup and again on every reload.
	DoTListen string
	DoTCert   string
	DoTKey    string
	// Upstreams are the resolvers s-hole forwards to, in order: plain
	// "IP:port" entries or DoH "https://IP/path" endpoints.
	Upstreams []string
	// CacheEntries is the size of the DNS response cache; 0 turns it off.
	CacheEntries int
	// LocalPTR answers reverse lookups for private address ranges locally
	// (RFC 6303) instead of forwarding them, so LAN addresses stay on the LAN.
	LocalPTR bool
}

// Blocking holds the blocking: section.
type Blocking struct {
	Lists     []string // blocklist URLs
	Allowlist []string // domains that are never blocked, with their subdomains
	// Reply is how a blocked query is answered: ReplyZeroIP (0.0.0.0 or ::)
	// or ReplyNXDomain.
	Reply           string
	ReplyTTLSeconds uint32
	RefreshInterval time.Duration
	CacheDir        string // where downloaded blocklists are cached
}

// QueryLog holds the query_log: section: what s-hole records about queries.
type QueryLog struct {
	// Mode selects which queries are recorded: ModeNone, ModeBlocked, or
	// ModeAll. It covers every place a domain is kept: the database, the log
	// file, and the in-memory Top Domains and Top Clients lists.
	Mode string
	// Clients selects how much of the client address is kept with a recorded
	// query: ClientsDrop (nothing), ClientsSubnet (IPv4 /24, IPv6 /64), or
	// ClientsFull.
	Clients string
	// Database is the SQLite file for the query history; empty when off.
	Database string
	// File is where query lines are written: empty when off, FileStdout, or a
	// file path.
	File string
	// RetentionDays deletes database rows older than this; 0 keeps them
	// forever.
	RetentionDays int
	FlushInterval time.Duration
	// ClientNames maps an exact IP or a CIDR to a display label. A label is
	// resolved from the stored client value, so it never shows more than
	// Clients allows.
	ClientNames map[string]string
}

// Admin holds the admin: section.
type Admin struct {
	Listen string // address:port of the dashboard and REST API
	Pprof  bool   // expose /debug/pprof/*
}

// Enumerated values. The query_log values are also the strings the DNS
// handler, the query loggers, and the API use.
const (
	ModeNone    = "none"
	ModeBlocked = "blocked"
	ModeAll     = "all"

	ClientsDrop   = "drop"
	ClientsSubnet = "subnet"
	ClientsFull   = "full"

	ReplyZeroIP   = "zero_ip"
	ReplyNXDomain = "nxdomain"

	// FileStdout is the query_log.file value that writes query lines to
	// standard output. Off is the keyword that turns an optional output off.
	FileStdout = "stdout"
	Off        = "off"
)

// DefaultUpstreams is the upstream list when the config sets none: two
// encrypted DoH resolvers first, then the same two over plain DNS as a
// fallback. s-hole uses a plain entry only when every DoH entry has failed,
// and warns each time it does.
var DefaultUpstreams = []string{
	"https://9.9.9.9/dns-query",
	"https://1.1.1.1/dns-query",
	"9.9.9.9:53",
	"1.1.1.1:53",
}

// Default values for the settings below. RetentionDays and the durations are
// also quoted in the problem messages.
const (
	defaultListen          = ":53"
	defaultCacheEntries    = 2000
	defaultReplyTTL        = 300
	defaultRefreshInterval = 24 * time.Hour
	defaultCacheDir        = "."
	defaultRetentionDays   = 7
	defaultFlushInterval   = 30 * time.Second
	defaultAdminListen     = "127.0.0.1:8080"
	defaultStatsInterval   = 5 * time.Minute
)

func defaults() *Config {
	return &Config{
		DNS: DNS{
			Listen:       defaultListen,
			Upstreams:    append([]string(nil), DefaultUpstreams...),
			CacheEntries: defaultCacheEntries,
			LocalPTR:     true,
		},
		Blocking: Blocking{
			Reply:           ReplyZeroIP,
			ReplyTTLSeconds: defaultReplyTTL,
			RefreshInterval: defaultRefreshInterval,
			CacheDir:        defaultCacheDir,
		},
		QueryLog: QueryLog{
			Mode:          ModeNone,
			Clients:       ClientsDrop,
			RetentionDays: defaultRetentionDays,
			FlushInterval: defaultFlushInterval,
		},
		Admin:         Admin{Listen: defaultAdminListen},
		StatsInterval: defaultStatsInterval,
	}
}

// Problem is a config mistake that s-hole works around: an unknown key, a
// renamed key, or an invalid value. The setting keeps its default (or the
// YAML value, when only an environment variable was wrong).
type Problem struct {
	Key    string // config key or environment variable
	Detail string // what is wrong and what s-hole uses instead
}

func (p Problem) String() string { return p.Key + ": " + p.Detail }

// Load reads the config at path. It returns the config, the problems s-hole
// works around (see Problem), and an error only for a fatal mistake: the file
// cannot be read or parsed as YAML, dns.listen is malformed, every upstream is
// malformed, or DoT is on and its certificate pair cannot load.
func Load(path string) (*Config, []Problem, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return load(data, os.LookupEnv, os.Environ())
}

// load is Load on in-memory input, so tests can pass the YAML and the
// environment directly.
func load(data []byte, lookup func(string) (string, bool), environ []string) (*Config, []Problem, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, nil, fmt.Errorf("config is not valid YAML: %w", err)
	}
	c := defaults()
	var probs []Problem
	probs = append(probs, c.applyYAML(&root)...)
	probs = append(probs, c.applyEnv(lookup, environ)...)
	more, err := c.check()
	probs = append(probs, more...)
	if err != nil {
		return nil, probs, err
	}
	return c, probs, nil
}

// setting is one config key: how to parse it and how to describe the value
// in effect. scalar parses a scalar value (from YAML or an environment
// variable) and stores it only when it is valid, so a bad value leaves the
// earlier one in place. node handles a list or a map and has no environment
// variable.
type setting struct {
	key     string
	scalar  func(string) error
	node    func(*yaml.Node) ([]Problem, error)
	current func() string
}

// envName is the environment variable for a scalar key: S_HOLE_ plus the key
// path in upper case, with dots as underscores.
func envName(key string) string {
	return "S_HOLE_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

func (c *Config) settings() []setting {
	return []setting{
		{key: "dns.listen", scalar: setString(&c.DNS.Listen, defaultListen), current: quoted(&c.DNS.Listen)},
		{key: "dns.dot_listen", scalar: setOptional(&c.DNS.DoTListen), current: offOr(&c.DNS.DoTListen)},
		{key: "dns.dot_cert", scalar: setPath(&c.DNS.DoTCert), current: quoted(&c.DNS.DoTCert)},
		{key: "dns.dot_key", scalar: setPath(&c.DNS.DoTKey), current: quoted(&c.DNS.DoTKey)},
		{key: "dns.upstreams", node: setList(&c.DNS.Upstreams), current: func() string { return strings.Join(c.DNS.Upstreams, ", ") }},
		{key: "dns.cache_entries", scalar: setInt(&c.DNS.CacheEntries, 0, defaultCacheEntries), current: itoa(&c.DNS.CacheEntries)},
		{key: "dns.local_ptr", scalar: setBool(&c.DNS.LocalPTR, true), current: btoa(&c.DNS.LocalPTR)},

		{key: "blocking.lists", node: setList(&c.Blocking.Lists), current: func() string { return fmt.Sprintf("%d lists", len(c.Blocking.Lists)) }},
		{key: "blocking.allowlist", node: setList(&c.Blocking.Allowlist), current: func() string { return fmt.Sprintf("%d domains", len(c.Blocking.Allowlist)) }},
		{key: "blocking.reply", scalar: setEnum(&c.Blocking.Reply, ReplyZeroIP, ReplyZeroIP, ReplyNXDomain), current: quoted(&c.Blocking.Reply)},
		{key: "blocking.reply_ttl_seconds", scalar: setUint32(&c.Blocking.ReplyTTLSeconds, defaultReplyTTL), current: func() string { return strconv.FormatUint(uint64(c.Blocking.ReplyTTLSeconds), 10) }},
		{key: "blocking.refresh_interval", scalar: setDuration(&c.Blocking.RefreshInterval, defaultRefreshInterval), current: dtoa(&c.Blocking.RefreshInterval)},
		{key: "blocking.cache_dir", scalar: setString(&c.Blocking.CacheDir, defaultCacheDir), current: quoted(&c.Blocking.CacheDir)},

		{key: "query_log.mode", scalar: setEnum(&c.QueryLog.Mode, ModeNone, ModeNone, ModeBlocked, ModeAll), current: quoted(&c.QueryLog.Mode)},
		{key: "query_log.clients", scalar: setEnum(&c.QueryLog.Clients, ClientsDrop, ClientsDrop, ClientsSubnet, ClientsFull), current: quoted(&c.QueryLog.Clients)},
		{key: "query_log.database", scalar: setOptional(&c.QueryLog.Database), current: offOr(&c.QueryLog.Database)},
		{key: "query_log.file", scalar: setFile(&c.QueryLog.File), current: offOr(&c.QueryLog.File)},
		{key: "query_log.retention_days", scalar: setInt(&c.QueryLog.RetentionDays, 0, defaultRetentionDays), current: itoa(&c.QueryLog.RetentionDays)},
		{key: "query_log.flush_interval", scalar: setDuration(&c.QueryLog.FlushInterval, defaultFlushInterval), current: dtoa(&c.QueryLog.FlushInterval)},
		{key: "query_log.client_names", node: setMap(&c.QueryLog.ClientNames), current: func() string { return fmt.Sprintf("%d labels", len(c.QueryLog.ClientNames)) }},

		{key: "admin.listen", scalar: setString(&c.Admin.Listen, defaultAdminListen), current: quoted(&c.Admin.Listen)},
		{key: "admin.pprof", scalar: setBool(&c.Admin.Pprof, false), current: btoa(&c.Admin.Pprof)},

		{key: "stats_interval", scalar: setDuration(&c.StatsInterval, defaultStatsInterval), current: dtoa(&c.StatsInterval)},
	}
}

// sections are the top-level keys that hold a mapping of settings.
var sections = map[string]bool{"dns": true, "blocking": true, "query_log": true, "admin": true}

// renamedKeys maps each s-hole 1.x top-level key to its 2.0 name. Load
// reports an old key and ignores its value, so an upgraded config falls back
// to the 2.0 default, which is never less private than the old value.
var renamedKeys = map[string]string{
	"listen":                  "dns.listen",
	"dot_listen":              "dns.dot_listen",
	"tls_cert":                "dns.dot_cert",
	"tls_key":                 "dns.dot_key",
	"upstreams":               "dns.upstreams",
	"cache_size":              "dns.cache_entries",
	"local_ptr":               "dns.local_ptr",
	"blocklists":              "blocking.lists",
	"whitelist":               "blocking.allowlist",
	"block_mode":              "blocking.reply",
	"block_ttl":               "blocking.reply_ttl_seconds",
	"refresh_interval":        "blocking.refresh_interval",
	"cache_dir":               "blocking.cache_dir",
	"log_queries":             "query_log.mode",
	"query_privacy":           "query_log.clients",
	"query_db":                "query_log.database",
	"log_file":                "query_log.file",
	"query_db_retention_days": "query_log.retention_days",
	"db_flush_interval":       "query_log.flush_interval",
	"client_names":            "query_log.client_names",
	"api_listen":              "admin.listen",
	"enable_pprof":            "admin.pprof",
}

// renamedEnv maps each s-hole 1.x environment variable to its 2.0 name.
var renamedEnv = map[string]string{
	"S_HOLE_LISTEN":            "S_HOLE_DNS_LISTEN",
	"S_HOLE_DOT_LISTEN":        "S_HOLE_DNS_DOT_LISTEN",
	"S_HOLE_TLS_CERT":          "S_HOLE_DNS_DOT_CERT",
	"S_HOLE_TLS_KEY":           "S_HOLE_DNS_DOT_KEY",
	"S_HOLE_CACHE_SIZE":        "S_HOLE_DNS_CACHE_ENTRIES",
	"S_HOLE_LOCAL_PTR":         "S_HOLE_DNS_LOCAL_PTR",
	"S_HOLE_BLOCK_MODE":        "S_HOLE_BLOCKING_REPLY",
	"S_HOLE_BLOCK_TTL":         "S_HOLE_BLOCKING_REPLY_TTL_SECONDS",
	"S_HOLE_REFRESH_INTERVAL":  "S_HOLE_BLOCKING_REFRESH_INTERVAL",
	"S_HOLE_CACHE_DIR":         "S_HOLE_BLOCKING_CACHE_DIR",
	"S_HOLE_LOG_QUERIES":       "S_HOLE_QUERY_LOG_MODE",
	"S_HOLE_QUERY_PRIVACY":     "S_HOLE_QUERY_LOG_CLIENTS",
	"S_HOLE_QUERY_DB":          "S_HOLE_QUERY_LOG_DATABASE",
	"S_HOLE_LOG_FILE":          "S_HOLE_QUERY_LOG_FILE",
	"S_HOLE_RETENTION_DAYS":    "S_HOLE_QUERY_LOG_RETENTION_DAYS",
	"S_HOLE_DB_FLUSH_INTERVAL": "S_HOLE_QUERY_LOG_FLUSH_INTERVAL",
	"S_HOLE_API_LISTEN":        "S_HOLE_ADMIN_LISTEN",
	"S_HOLE_ENABLE_PPROF":      "S_HOLE_ADMIN_PPROF",
}

// otherEnv are S_HOLE_* variables that are not config settings: main reads
// them directly.
var otherEnv = map[string]bool{"S_HOLE_LOG_FORMAT": true, "S_HOLE_ASCII_BANNER": true}

// applyYAML stores the values from the parsed document and returns a problem
// for each unknown, renamed, duplicate, or invalid key.
func (c *Config) applyYAML(root *yaml.Node) []Problem {
	if root.Kind == 0 || len(root.Content) == 0 {
		return nil // empty file
	}
	doc := root.Content[0]
	if doc.Kind == yaml.ScalarNode && doc.Tag == "!!null" {
		return nil // a file with only comments
	}
	if doc.Kind != yaml.MappingNode {
		return []Problem{{Key: "config", Detail: "the file must be a mapping of keys to values; the whole file is ignored and every setting uses its default"}}
	}
	byKey := map[string]setting{}
	for _, s := range c.settings() {
		byKey[s.key] = s
	}
	var probs []Problem
	seen := map[string]bool{}
	apply := func(key string, val *yaml.Node) {
		if seen[key] {
			probs = append(probs, Problem{Key: key, Detail: "is set more than once; the last value is used"})
		}
		seen[key] = true
		s, ok := byKey[key]
		if !ok {
			probs = append(probs, Problem{Key: key, Detail: "is not a known setting; it is ignored"})
			return
		}
		probs = append(probs, applyNode(s, val)...)
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		k, v := doc.Content[i].Value, doc.Content[i+1]
		switch {
		case sections[k]:
			if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
				continue // an empty section
			}
			if v.Kind != yaml.MappingNode {
				probs = append(probs, Problem{Key: k, Detail: "must be a section of settings; it is ignored"})
				continue
			}
			for j := 0; j+1 < len(v.Content); j += 2 {
				apply(k+"."+v.Content[j].Value, v.Content[j+1])
			}
		case renamedKeys[k] != "":
			probs = append(probs, Problem{Key: k, Detail: fmt.Sprintf("was renamed to %s in s-hole 2.0; the old key is ignored", renamedKeys[k])})
		default:
			apply(k, v)
		}
	}
	return probs
}

// applyNode stores one YAML value through its setting.
func applyNode(s setting, val *yaml.Node) []Problem {
	if s.node != nil {
		probs, err := s.node(val)
		if err != nil {
			probs = append(probs, Problem{Key: s.key, Detail: err.Error() + "; using the default"})
		}
		return probs
	}
	if val.Kind != yaml.ScalarNode {
		return []Problem{{Key: s.key, Detail: "must be a single value; using " + s.current()}}
	}
	raw := val.Value
	if val.Tag == "!!null" {
		raw = ""
	}
	if err := s.scalar(raw); err != nil {
		return []Problem{{Key: s.key, Detail: err.Error() + "; using " + s.current()}}
	}
	return nil
}

// applyEnv applies the S_HOLE_* overrides over the YAML values and reports a
// bad value, a 1.x variable name, and an unknown S_HOLE_* variable.
func (c *Config) applyEnv(lookup func(string) (string, bool), environ []string) []Problem {
	var probs []Problem
	known := map[string]bool{}
	for _, s := range c.settings() {
		if s.scalar == nil {
			continue
		}
		name := envName(s.key)
		known[name] = true
		v, ok := lookup(name)
		if !ok {
			continue
		}
		if err := s.scalar(v); err != nil {
			probs = append(probs, Problem{Key: name, Detail: err.Error() + "; the variable is ignored and " + s.key + " stays " + s.current()})
		}
	}
	var names []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "S_HOLE_") && !known[name] && !otherEnv[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if to := renamedEnv[name]; to != "" {
			probs = append(probs, Problem{Key: name, Detail: "was renamed to " + to + " in s-hole 2.0; the old variable is ignored"})
		} else {
			probs = append(probs, Problem{Key: name, Detail: "is not a known s-hole variable; it is ignored"})
		}
	}
	return probs
}

// check validates the settings that depend on more than one value, filters
// the lists, and returns the one fatal error, if any.
func (c *Config) check() ([]Problem, error) {
	var probs []Problem
	if !isHostPort(c.DNS.Listen) {
		return probs, fmt.Errorf("dns.listen %q: must be host:port, such as \":53\"", c.DNS.Listen)
	}
	if !isHostPort(c.Admin.Listen) {
		probs = append(probs, Problem{Key: "admin.listen", Detail: fmt.Sprintf("%q is not host:port; using %q", c.Admin.Listen, defaultAdminListen)})
		c.Admin.Listen = defaultAdminListen
	}

	if len(c.DNS.Upstreams) == 0 {
		c.DNS.Upstreams = append([]string(nil), DefaultUpstreams...)
	} else {
		var dropped []string
		c.DNS.Upstreams, dropped = filterUpstreams(c.DNS.Upstreams)
		for _, u := range dropped {
			probs = append(probs, Problem{Key: "dns.upstreams", Detail: fmt.Sprintf("%q is malformed and is ignored (use IP:port, such as 9.9.9.9:53, or a DoH URL with an IP host and a path, such as https://9.9.9.9/dns-query, with no user name or password)", RedactURL(u))})
		}
		if len(c.DNS.Upstreams) == 0 {
			return probs, errors.New("dns.upstreams: every entry is malformed, so s-hole cannot forward any query (use IP:port, such as 9.9.9.9:53, or a DoH URL such as https://9.9.9.9/dns-query)")
		}
	}

	var badDomains []string
	c.Blocking.Allowlist, badDomains = filterAllowlist(c.Blocking.Allowlist)
	for _, d := range badDomains {
		probs = append(probs, Problem{Key: "blocking.allowlist", Detail: fmt.Sprintf("%q is not a valid domain and is ignored", d)})
	}
	var badKeys []string
	c.QueryLog.ClientNames, badKeys = filterClientNames(c.QueryLog.ClientNames)
	for _, k := range badKeys {
		probs = append(probs, Problem{Key: "query_log.client_names", Detail: fmt.Sprintf("key %q is not an IP address or a CIDR and is ignored", k)})
	}

	if c.DNS.DoTListen != "" {
		if !isHostPort(c.DNS.DoTListen) {
			probs = append(probs, Problem{Key: "dns.dot_listen", Detail: fmt.Sprintf("%q is not host:port; DoT stays off", c.DNS.DoTListen)})
			c.DNS.DoTListen = ""
		} else if err := c.checkDoT(); err != nil {
			return probs, err
		}
	}
	return probs, nil
}

// checkDoT loads the DoT certificate pair. tls.LoadX509KeyPair reads the two
// local files and checks that the key matches the certificate, so
// -check-config catches a bad pair before the service starts. It makes no
// network call.
func (c *Config) checkDoT() error {
	if c.DNS.DoTCert == "" || c.DNS.DoTKey == "" {
		return errors.New("dns.dot_listen is set, so dns.dot_cert and dns.dot_key are required")
	}
	if _, err := tls.LoadX509KeyPair(c.DNS.DoTCert, c.DNS.DoTKey); err != nil {
		return fmt.Errorf("dns.dot_cert/dns.dot_key: cannot load the DoT certificate: %w", err)
	}
	return nil
}

func isHostPort(s string) bool {
	_, port, err := net.SplitHostPort(s)
	return err == nil && port != ""
}

// IsOff reports whether v turns an optional output off: empty or "off".
func IsOff(v string) bool {
	return v == "" || strings.EqualFold(v, Off)
}

// Setting parsers. Each returns a func that parses raw and stores the result
// only when it is valid.

func setString(dst *string, def string) func(string) error {
	return func(raw string) error {
		if raw == "" {
			*dst = def
			return nil
		}
		*dst = raw
		return nil
	}
}

// setPath stores a file path; empty is allowed.
func setPath(dst *string) func(string) error {
	return func(raw string) error { *dst = raw; return nil }
}

// setOptional stores an optional address or path, with "off" (or empty) as
// "turned off".
func setOptional(dst *string) func(string) error {
	return func(raw string) error {
		if IsOff(raw) {
			*dst = ""
			return nil
		}
		*dst = raw
		return nil
	}
}

// setFile stores query_log.file: off, stdout, or a path.
func setFile(dst *string) func(string) error {
	return func(raw string) error {
		switch {
		case IsOff(raw):
			*dst = ""
		case strings.EqualFold(raw, FileStdout):
			*dst = FileStdout
		default:
			*dst = raw
		}
		return nil
	}
}

func setEnum(dst *string, def string, allowed ...string) func(string) error {
	return func(raw string) error {
		if raw == "" {
			*dst = def
			return nil
		}
		for _, a := range allowed {
			if raw == a {
				*dst = raw
				return nil
			}
		}
		return fmt.Errorf("%q is not allowed (use %s)", raw, quoteJoin(allowed))
	}
}

func setInt(dst *int, lowest, def int) func(string) error {
	return func(raw string) error {
		if raw == "" {
			*dst = def
			return nil
		}
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%q is not a whole number", raw)
		}
		if n < lowest {
			return fmt.Errorf("%d is below %d", n, lowest)
		}
		*dst = n
		return nil
	}
}

func setUint32(dst *uint32, def uint32) func(string) error {
	return func(raw string) error {
		if raw == "" {
			*dst = def
			return nil
		}
		n, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 32)
		if err != nil {
			return fmt.Errorf("%q is not a whole number from 0 to 4294967295", raw)
		}
		*dst = uint32(n)
		return nil
	}
}

// setBool accepts true/false, yes/no, and 1/0, in any case.
func setBool(dst *bool, def bool) func(string) error {
	return func(raw string) error {
		if raw == "" {
			*dst = def
			return nil
		}
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "true", "yes", "1":
			*dst = true
		case "false", "no", "0":
			*dst = false
		default:
			return fmt.Errorf("%q is not true or false", raw)
		}
		return nil
	}
}

// setDuration accepts a positive Go duration such as "30s", "5m", or "24h".
// A positive value is required because every duration drives a ticker, and
// time.NewTicker panics on a non-positive one (b/046, b/055).
func setDuration(dst *time.Duration, def time.Duration) func(string) error {
	return func(raw string) error {
		if raw == "" {
			*dst = def
			return nil
		}
		d, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%q is not a duration such as 30s, 5m, or 24h", raw)
		}
		if d <= 0 {
			return fmt.Errorf("%q must be positive", raw)
		}
		*dst = d
		return nil
	}
}

func setList(dst *[]string) func(*yaml.Node) ([]Problem, error) {
	return func(n *yaml.Node) ([]Problem, error) {
		if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
			*dst = nil
			return nil, nil
		}
		if n.Kind != yaml.SequenceNode {
			return nil, errors.New("must be a list")
		}
		out := make([]string, 0, len(n.Content))
		for _, item := range n.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, errors.New("every list entry must be a single value")
			}
			if item.Tag == "!!null" || item.Value == "" {
				continue
			}
			out = append(out, item.Value)
		}
		*dst = out
		return nil, nil
	}
}

func setMap(dst *map[string]string) func(*yaml.Node) ([]Problem, error) {
	return func(n *yaml.Node) ([]Problem, error) {
		if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
			*dst = nil
			return nil, nil
		}
		if n.Kind != yaml.MappingNode {
			return nil, errors.New("must be a map of key: value pairs")
		}
		out := make(map[string]string, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode || v.Kind != yaml.ScalarNode {
				return nil, errors.New("every entry must be key: value")
			}
			out[k.Value] = v.Value
		}
		*dst = out
		return nil, nil
	}
}

// Value printers for the problem messages.

func quoted(p *string) func() string { return func() string { return strconv.Quote(*p) } }

func offOr(p *string) func() string {
	return func() string {
		if *p == "" {
			return Off
		}
		return strconv.Quote(*p)
	}
}

func itoa(p *int) func() string           { return func() string { return strconv.Itoa(*p) } }
func btoa(p *bool) func() string          { return func() string { return strconv.FormatBool(*p) } }
func dtoa(p *time.Duration) func() string { return func() string { return p.String() } }

func quoteJoin(vals []string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = strconv.Quote(v)
	}
	switch len(q) {
	case 0:
		return ""
	case 1:
		return q[0]
	}
	return strings.Join(q[:len(q)-1], ", ") + " or " + q[len(q)-1]
}

// filterClientNames drops entries whose key is neither a valid IP nor a valid
// CIDR, returning the cleaned map and the dropped keys. A malformed key is a
// problem, not a fatal error, because client_names only changes how a client
// is labeled. A nil or empty result reads as "labels off".
func filterClientNames(m map[string]string) (valid map[string]string, dropped []string) {
	if len(m) == 0 {
		return nil, nil
	}
	valid = make(map[string]string, len(m))
	for key, label := range m {
		if net.ParseIP(key) != nil {
			valid[key] = label
			continue
		}
		if _, _, err := net.ParseCIDR(key); err == nil {
			valid[key] = label
			continue
		}
		dropped = append(dropped, key)
	}
	sort.Strings(dropped)
	if len(valid) == 0 {
		valid = nil
	}
	return valid, dropped
}

// filterAllowlist splits entries into those that pass blocklist.ValidDomain
// and those that do not, preserving order. Allowlist matching is
// suffix-based (CL 30), so an invalid entry such as a bare TLD would exempt
// its whole subtree; Load drops the invalid ones (as problems) instead of
// making one typo a fatal startup error. This mirrors the blocklist loader,
// which likewise skips tokens that fail ValidDomain, and uses the same rule
// the REST /api/allowlist handler applies to interactive additions.
func filterAllowlist(entries []string) (valid, dropped []string) {
	for _, d := range entries {
		if blocklist.ValidDomain(d) {
			valid = append(valid, d)
		} else {
			dropped = append(dropped, d)
		}
	}
	return valid, dropped
}

// filterUpstreams splits upstreams into valid and invalid, preserving order. It
// accepts two shapes: a plain "host:port" resolver (checked with
// net.SplitHostPort and a non-empty host and port, so a bare "1.1.1.1" (no
// port), ":53" (no host), and "1.1.1.1:" (no port) are all rejected), and a
// DoH endpoint URL "https://<IP>/dns-query" (checked and normalized by
// normalizeDoHURL). It is a shape check, not a reachability check: a
// well-formed but dead or typo'd address stays a runtime concern that the
// upstream cooldown tracker already handles. It resolves no name and dials
// nothing, so it adds no network call and cannot be turned into an SSRF or
// LAN-scan primitive via the config path.
func filterUpstreams(upstreams []string) (valid, dropped []string) {
	for _, u := range upstreams {
		// A URL-shaped entry (any "scheme://") is validated as a DoH endpoint,
		// so a plain-DNS host:port never contains "://". This also routes a
		// non-https URL (e.g. "http://...") through normalizeDoHURL, which
		// rejects it, instead of letting net.SplitHostPort mis-read it as a
		// host:port. The normalized form goes into the list, because the
		// forwarder picks DoH by the exact "https://" prefix (b/067).
		if strings.Contains(u, "://") {
			if norm, ok := normalizeDoHURL(u); ok {
				valid = append(valid, norm)
			} else {
				dropped = append(dropped, u)
			}
			continue
		}
		host, port, err := net.SplitHostPort(u)
		if err != nil || host == "" || port == "" {
			dropped = append(dropped, u)
			continue
		}
		valid = append(valid, u)
	}
	return valid, dropped
}

// RedactURL hides the parts of a URL that can hold a secret: the user info
// becomes "redacted" and the query string is replaced by "redacted". A URL
// that url.Parse rejects (a bad port, an open IPv6 bracket) can still hold
// user info, so that case is redacted by hand: everything before the last
// "@" in the authority is replaced. A string with neither part is returned
// unchanged. Logs, /metrics, and /api/stats show URLs through it, so a token
// in a private blocklist URL or a DoH path never reaches them.
func RedactURL(u string) string {
	parsed, err := url.Parse(u)
	if err == nil {
		changed := false
		if parsed.User != nil {
			parsed.User = url.User("redacted")
			changed = true
		}
		if parsed.RawQuery != "" {
			parsed.RawQuery = "redacted"
			changed = true
		}
		if !changed {
			return u
		}
		return parsed.String()
	}
	scheme, rest, ok := strings.Cut(u, "://")
	if !ok {
		return u
	}
	authority, path, hasPath := strings.Cut(rest, "/")
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return u
	}
	out := scheme + "://redacted" + authority[at:]
	if hasPath {
		out += "/" + path
	}
	return out
}

// normalizeDoHURL reports whether u is a usable DoH upstream and returns its
// normalized form: an https URL whose host is an IP literal and that has a
// path, e.g. "https://9.9.9.9/dns-query".
// The IP requirement is deliberate. s-hole is often the box's own resolver, so
// resolving a DoH hostname could loop back into s-hole; an IP host removes the
// bootstrap lookup entirely, and the major providers ship certificates with IP
// SANs so TLS still verifies. A hostname DoH URL is rejected here (support for
// it needs a bootstrap resolver, a later CL). Like the host:port check, this
// parses only and dials nothing.
//
// url.Parse lowercases the scheme, so "HTTPS://..." parses as https. The
// caller stores the normalized string, so the forwarder's "https://" prefix
// check sees the same scheme that this check accepted (b/067). User info is
// rejected because the upstream string is a label on the unauthenticated
// /metrics page. A URL with no path is rejected because the DoH endpoint is a
// path on the server (/dns-query for the major providers).
func normalizeDoHURL(u string) (string, bool) {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil {
		return "", false
	}
	if parsed.Path == "" || parsed.Path == "/" {
		return "", false
	}
	if net.ParseIP(parsed.Hostname()) == nil {
		return "", false
	}
	return parsed.String(), true
}

// UpstreamNotes returns informational notes about the upstream list for the
// startup log: a single upstream has no fallback, a DoH-only list stops
// resolving when TLS fails (for example on a wrong system clock), and a plain
// entry is used only after every DoH entry has failed. None of them is a
// mistake, so they are not problems.
func (c *Config) UpstreamNotes() []string {
	var notes []string
	var doh, plain int
	for _, u := range c.DNS.Upstreams {
		if strings.HasPrefix(u, "https://") {
			doh++
		} else {
			plain++
		}
	}
	if len(c.DNS.Upstreams) == 1 {
		notes = append(notes, "single upstream configured; no forwarding fallback if it fails")
	}
	switch {
	case doh > 0 && plain == 0:
		notes = append(notes, "every upstream is DoH; if TLS fails (for example, the system clock is wrong), s-hole cannot resolve names until it works again")
	case doh > 0 && plain > 0:
		notes = append(notes, "plain upstreams are a fallback; s-hole uses one only when every DoH upstream has failed, and warns each time")
	}
	return notes
}
