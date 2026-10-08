package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/lcsabi/s-hole/internal/redact"
)

// Warning is a setting that is less private or less secure than its
// default. s-hole logs every warning at -check-config and at startup, and
// repeats them with each stats line. They cannot be turned off: the operator
// can only change the setting.
type Warning struct {
	Key    string // config key
	Detail string // what the setting does to privacy or security
	Hint   string // how to go back to the default
}

// maxPrivateRetentionDays is the retention default. A longer retention keeps
// history longer than the default does, so it is a warning.
const maxPrivateRetentionDays = defaultRetentionDays

// Warnings returns one Warning for each setting that is less private or
// less secure than its default. A setting that has no effect under the
// others (for example clients "full" while mode is "none") gives no warning.
func (c *Config) Warnings() []Warning {
	var w []Warning
	add := func(key, detail, hint string) {
		w = append(w, Warning{Key: key, Detail: detail, Hint: hint})
	}
	recording := c.QueryLog.Mode != ModeNone

	switch c.QueryLog.Mode {
	case ModeAll:
		add("query_log.mode", "every query is recorded: the history shows each site every device uses",
			`set query_log.mode to "none", or "blocked" to record blocked queries only`)
	case ModeBlocked:
		add("query_log.mode", "blocked queries are recorded: the history shows which trackers and ads each app contacts",
			`set query_log.mode to "none"`)
	}
	if recording {
		switch c.QueryLog.Clients {
		case ClientsFull:
			detail := "the address of each device is recorded, so each query can be traced to a device"
			if len(c.QueryLog.ClientNames) > 0 {
				detail += ", and client_names labels name the devices"
			}
			add("query_log.clients", detail, `set query_log.clients to "drop"`)
		case ClientsSubnet:
			add("query_log.clients", "the subnet of each device is recorded", `set query_log.clients to "drop"`)
		}
		switch c.QueryLog.File {
		case "":
		case FileStdout:
			add("query_log.file", "query lines go to standard output: the system journal or the container log, which retention and purge cannot reach",
				`set query_log.file to "off"`)
		default:
			add("query_log.file", fmt.Sprintf("query lines go to %s, which retention does not shorten", c.QueryLog.File),
				`set query_log.file to "off", or delete the file with s-hole -purge`)
		}
		if c.QueryLog.Database != "" {
			switch {
			case c.QueryLog.RetentionDays == 0:
				add("query_log.retention_days", "the query history is kept forever",
					fmt.Sprintf("set query_log.retention_days to %d", maxPrivateRetentionDays))
			case c.QueryLog.RetentionDays > maxPrivateRetentionDays:
				add("query_log.retention_days", fmt.Sprintf("the query history is kept for %d days", c.QueryLog.RetentionDays),
					fmt.Sprintf("set query_log.retention_days to %d or less", maxPrivateRetentionDays))
			}
		}
	}
	if !isLoopbackListen(c.Admin.Listen) {
		add("admin.listen", fmt.Sprintf("the dashboard and API on %s have no login, and every device that can reach them can read the stored history and change the allowlist", c.Admin.Listen),
			`set admin.listen to "127.0.0.1:8080"`)
	}
	if c.Admin.Pprof {
		add("admin.pprof", "the Go profiler is exposed on the admin address and shows the internal state of the process",
			"set admin.pprof to false when the investigation is done")
	}
	if !c.DNS.LocalPTR {
		add("dns.local_ptr", "reverse lookups for LAN addresses go upstream and tell the upstream which addresses the LAN uses",
			"set dns.local_ptr to true, unless a resolver on the LAN serves those reverse zones")
	}
	encrypted := false
	for _, u := range c.DNS.Upstreams {
		if strings.HasPrefix(u, "https://") {
			encrypted = true
			break
		}
	}
	if !encrypted {
		add("dns.upstreams", "every upstream is plain DNS: the internet provider can read and change every forwarded query",
			"put a DoH upstream first, such as https://9.9.9.9/dns-query")
	}
	for _, u := range c.Blocking.Lists {
		if strings.HasPrefix(strings.ToLower(u), "http://") {
			add("blocking.lists", fmt.Sprintf("%s is downloaded over plain HTTP: anyone on the network path can change the list and unblock trackers", redact.URL(u)),
				"use the https:// URL of the list")
		}
	}
	return w
}

// isLoopbackListen reports whether an address:port binds a loopback address
// only. An empty host (":8080") binds every interface.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
