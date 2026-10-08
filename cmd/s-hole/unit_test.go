package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Tests for the systemd unit (SEC-09, CL 106). The unit ships twice: as
// deploy/s-hole.service and as the heredoc that deploy/install-linux.sh
// writes to /etc/systemd/system/s-hole.service. CLAUDE.md requires the two to
// stay byte-identical; these tests enforce that and pin the sandbox lines.

const unitInstallPath = "/etc/systemd/system/s-hole.service"

// readDeployFile reads a file in deploy/ from the repository root.
func readDeployFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", name))
	if err != nil {
		t.Fatalf("read deploy/%s: %v", name, err)
	}
	return data
}

// installerUnit returns the body of the installer heredoc that writes the
// unit, as bash writes it to disk (each line ends in a newline), and the
// heredoc's opening line.
func installerUnit(t *testing.T) (body []byte, opener string) {
	t.Helper()
	lines := strings.Split(string(readDeployFile(t, "install-linux.sh")), "\n")
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "cat > "+unitInstallPath) {
			if start >= 0 {
				t.Fatalf("install-linux.sh writes %s twice (lines %d and %d)", unitInstallPath, start+1, i+1)
			}
			start = i
		}
	}
	if start < 0 {
		t.Fatalf("install-linux.sh has no heredoc that writes %s", unitInstallPath)
	}
	opener = strings.TrimSuffix(lines[start], "\r")
	var buf bytes.Buffer
	for _, line := range lines[start+1:] {
		if strings.TrimSuffix(line, "\r") == "EOF" {
			return buf.Bytes(), opener
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	t.Fatalf("heredoc for %s has no closing EOF line", unitInstallPath)
	return nil, ""
}

// TestInstallerUnit_MatchesServiceFile pins the CLAUDE.md rule that
// deploy/s-hole.service is byte-identical to the installer heredoc.
func TestInstallerUnit_MatchesServiceFile(t *testing.T) {
	file := readDeployFile(t, "s-hole.service")
	heredoc, _ := installerUnit(t)
	if bytes.Equal(file, heredoc) {
		return
	}
	fl := strings.SplitAfter(string(file), "\n")
	hl := strings.SplitAfter(string(heredoc), "\n")
	for i := 0; i < len(fl) || i < len(hl); i++ {
		var f, h string
		if i < len(fl) {
			f = fl[i]
		}
		if i < len(hl) {
			h = hl[i]
		}
		if f != h {
			t.Fatalf("deploy/s-hole.service and the install-linux.sh heredoc differ at unit line %d:\n service file: %q\n heredoc:      %q\nkeep them byte-identical", i+1, f, h)
		}
	}
	t.Fatal("deploy/s-hole.service and the install-linux.sh heredoc differ; keep them byte-identical")
}

// TestInstallerUnit_HeredocIsQuoted checks that the heredoc delimiter is
// quoted. Without the quotes, bash expands $MAINPID in ExecReload to an empty
// string, and the installed unit differs from deploy/s-hole.service even when
// the two sources are identical.
func TestInstallerUnit_HeredocIsQuoted(t *testing.T) {
	_, opener := installerUnit(t)
	if !strings.HasSuffix(opener, "<< 'EOF'") && !strings.HasSuffix(opener, "<<'EOF'") {
		t.Errorf("heredoc opener = %q, want a quoted 'EOF' delimiter so bash expands nothing", opener)
	}
}

// unitLine is one key=value line of a unit file, with the comment lines just
// above it.
type unitLine struct {
	key, value string
	comment    []string
}

// parseUnit returns the key=value lines of one section, in order. It follows
// the systemd unit syntax that the s-hole unit uses: "[Section]" headers,
// "#" comments, blank lines. A blank line ends a comment block.
func parseUnit(t *testing.T, data []byte, section string) []unitLine {
	t.Helper()
	var out []unitLine
	var current string
	var comment []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "":
			comment = nil
		case strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
			comment = append(comment, line)
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			current = line[1 : len(line)-1]
			comment = nil
		default:
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("unit line %q has no '='", line)
			}
			if current == section {
				out = append(out, unitLine{key: strings.TrimSpace(key), value: strings.TrimSpace(value), comment: comment})
			}
			comment = nil
		}
	}
	return out
}

// unitSources returns the unit as the service file and as the installer
// writes it, so a check that fails names the copy that is wrong.
func unitSources(t *testing.T) map[string][]byte {
	t.Helper()
	heredoc, _ := installerUnit(t)
	return map[string][]byte{
		"deploy/s-hole.service":    readDeployFile(t, "s-hole.service"),
		"install-linux.sh heredoc": heredoc,
	}
}

// requiredServiceLines lists each [Service] key the unit must set and every
// value it must have, in order. The test fails on a missing value, an extra
// assignment (which can reset or override the setting), or an empty
// assignment (which resets a list setting such as RestrictAddressFamilies).
var requiredServiceLines = map[string][]string{
	// Lines from before SEC-09.
	"User":                  {"s-hole"},
	"Group":                 {"s-hole"},
	"ExecReload":            {"/bin/kill -HUP $MAINPID"},
	"AmbientCapabilities":   {"CAP_NET_BIND_SERVICE"},
	"CapabilityBoundingSet": {"CAP_NET_BIND_SERVICE"},
	"NoNewPrivileges":       {"true"},
	"ProtectSystem":         {"strict"},
	"ProtectHome":           {"true"},
	"ReadWritePaths":        {"/var/lib/s-hole"},
	"UMask":                 {"0077"},

	// SEC-09 sandbox lines.
	"PrivateTmp": {"true"},
	// The private /tmp stays read-only, so a query path under /tmp fails to
	// write, as it did before CL 106 (maintainer decision, 2026-10-08).
	"ReadOnlyPaths":           {"/tmp /var/tmp"},
	"PrivateDevices":          {"true"},
	"ProtectKernelTunables":   {"true"},
	"ProtectKernelModules":    {"true"},
	"ProtectKernelLogs":       {"true"},
	"ProtectControlGroups":    {"true"},
	"ProtectClock":            {"true"},
	"ProtectHostname":         {"true"},
	"ProtectProc":             {"invisible"},
	"ProcSubset":              {"pid"},
	"RestrictAddressFamilies": {"AF_UNIX AF_INET AF_INET6 AF_NETLINK"},
	"RestrictNamespaces":      {"true"},
	"RestrictSUIDSGID":        {"true"},
	"RestrictRealtime":        {"true"},
	"LockPersonality":         {"true"},
	"MemoryDenyWriteExecute":  {"true"},
	"RemoveIPC":               {"true"},
	"SystemCallArchitectures": {"native"},
	"SystemCallFilter":        {"@system-service", "~@privileged @resources"},
	"SystemCallErrorNumber":   {"EPERM"},
}

// TestUnit_HardeningLines pins SEC-09: every sandbox line is in [Service]
// with its exact value, and the hardening lines from before SEC-09 stay.
func TestUnit_HardeningLines(t *testing.T) {
	for name, data := range unitSources(t) {
		t.Run(name, func(t *testing.T) {
			got := map[string][]string{}
			for _, l := range parseUnit(t, data, "Service") {
				got[l.key] = append(got[l.key], l.value)
			}
			for key, want := range requiredServiceLines {
				if !reflect.DeepEqual(got[key], want) {
					t.Errorf("[Service] %s = %q, want %q", key, got[key], want)
				}
			}
		})
	}
}

// TestUnit_AddressFamiliesAllowNetlink pins the SEC-09 constraint: the LAN
// check reads the interface subnets through net.InterfaceAddrs, which needs
// AF_NETLINK. Without it, clients on a public IPv6 LAN prefix get REFUSED.
// The line also carries a comment that says why AF_NETLINK is there, so a
// later "tightening" does not remove it.
func TestUnit_AddressFamiliesAllowNetlink(t *testing.T) {
	for name, data := range unitSources(t) {
		t.Run(name, func(t *testing.T) {
			var found *unitLine
			for _, l := range parseUnit(t, data, "Service") {
				if l.key == "RestrictAddressFamilies" {
					found = &l
				}
			}
			if found == nil {
				t.Fatal("[Service] has no RestrictAddressFamilies line")
			}
			if strings.HasPrefix(found.value, "~") {
				t.Fatalf("RestrictAddressFamilies = %q is a deny list, want an allow list", found.value)
			}
			families := map[string]bool{}
			for _, f := range strings.Fields(found.value) {
				families[f] = true
			}
			for _, want := range []string{"AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"} {
				if !families[want] {
					t.Errorf("RestrictAddressFamilies = %q, missing %s", found.value, want)
				}
			}
			comment := strings.Join(found.comment, "\n")
			if !strings.Contains(comment, "AF_NETLINK") || !strings.Contains(comment, "LAN") {
				t.Errorf("comment above RestrictAddressFamilies = %q, want one that says AF_NETLINK is needed for the LAN check", comment)
			}
		})
	}
}
