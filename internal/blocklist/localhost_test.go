package blocklist

import (
	"strings"
	"testing"
)

// CL 94 R14: parseHostsFormat never loads a localhost name into the block
// set: "localhost", a name under ".localhost", or "localhost.localdomain".

// localhostNames are spellings of names that the parser must skip.
var localhostNames = []string{
	"localhost",
	"LOCALHOST",
	"localhost.",
	"app.localhost",
	"a.b.LocalHost",
	"app.localhost.",
	"localhost.localdomain",
	"LocalHost.LocalDomain",
	"localhost.localdomain.",
}

func TestParseHostsFormat_SkipsLocalhostNames(t *testing.T) {
	// CL 94 R14: in a hosts line with 0.0.0.0, 127.0.0.1, or ::, in a plain
	// one-domain line, and in a "*." wildcard line, a localhost name is not
	// loaded and counts as a skipped line.
	formats := map[string]func(string) string{
		"0.0.0.0 hosts line":   func(d string) string { return "0.0.0.0 " + d },
		"127.0.0.1 hosts line": func(d string) string { return "127.0.0.1 " + d },
		":: hosts line":        func(d string) string { return ":: " + d },
		"plain line":           func(d string) string { return d },
		"wildcard line":        func(d string) string { return "*." + d },
	}
	for format, line := range formats {
		for _, name := range localhostNames {
			input := line(name) + "\n"
			got, skipped := parseOne(t, input)
			if len(got) != 0 {
				t.Errorf("%s %q: loaded %v, want nothing", format, input, got)
			}
			if skipped != 1 {
				t.Errorf("%s %q: skipped = %d, want 1", format, input, skipped)
			}
		}
	}
}

func TestParseHostsFormat_LocalhostLinesInAList(t *testing.T) {
	// CL 94 R14: a typical hosts file starts with localhost lines. They are
	// skipped, and the other names in the list still load.
	input := strings.Join([]string{
		"# hosts file",
		"127.0.0.1 localhost",
		"127.0.0.1 localhost.localdomain",
		"::1 localhost",
		"0.0.0.0 ads.example.com",
		"0.0.0.0 app.localhost",
		"tracker.example.net",
		"localhost.localdomain",
		"*.metrics.example.org",
		"*.localhost",
		"0.0.0.0 localhost.example.com",
		"0.0.0.0 notlocalhost.example",
		"mylocalhost.localdomain",
		"",
	}, "\n")
	got, skipped := parseOne(t, input)
	want := []string{"ads.example.com", "tracker.example.net", "metrics.example.org", "localhost.example.com", "notlocalhost.example", "mylocalhost.localdomain"}
	if !equalSlices(got, want) {
		t.Errorf("loaded %v, want %v", got, want)
	}
	// "::1 localhost" is skipped because ::1 is not a sinkhole address; the
	// other 5 localhost lines are skipped as localhost names.
	if skipped != 6 {
		t.Errorf("skipped = %d, want 6", skipped)
	}
}
