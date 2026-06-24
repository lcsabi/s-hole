package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestString_ContainsAllFields(t *testing.T) {
	s := String()
	for _, want := range []string{
		"s-hole",
		"commit:",
		"built:",
		"go:",
		"os/arch:",
		runtime.GOOS,
		runtime.GOARCH,
		runtime.Version(),
	} {
		if !strings.Contains(s, want) {
			t.Errorf("String() missing %q\nfull output:\n%s", want, s)
		}
	}
}

func TestShort_ReturnsAllThreeFields(t *testing.T) {
	v, c, d := Short()
	if v == "" {
		t.Error("Short returned empty Version")
	}
	if c == "" {
		t.Error("Short returned empty Commit")
	}
	if d == "" {
		t.Error("Short returned empty BuildDate")
	}
}

func TestDefaults_AreSafePlaceholders(t *testing.T) {
	// When the binary is built via `go build` without -ldflags, the three
	// fields must default to non-empty strings — empty values would break
	// the slog startup line and the -version output.
	if Version == "" || Commit == "" || BuildDate == "" {
		t.Errorf("placeholder vars empty: version=%q commit=%q date=%q",
			Version, Commit, BuildDate)
	}
}
