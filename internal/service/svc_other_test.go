//go:build !windows

package service

import (
	"errors"
	"testing"
)

// TestRun_StubReturnsFnError pins the non-Windows Run stub: it calls fn once,
// returns its error unchanged, and never calls stop (no SCM exists to send a
// stop control).
func TestRun_StubReturnsFnError(t *testing.T) {
	want := errors.New("serve failed")
	cases := map[string]error{"error": want, "nil": nil}
	for name, fnErr := range cases {
		t.Run(name, func(t *testing.T) {
			calls, stops := 0, 0
			got := Run(func() error { calls++; return fnErr }, func() { stops++ })
			if !errors.Is(got, fnErr) || (fnErr == nil && got != nil) {
				t.Errorf("Run = %v, want %v", got, fnErr)
			}
			if calls != 1 {
				t.Errorf("fn called %d times, want 1", calls)
			}
			if stops != 0 {
				t.Errorf("stop called %d times, want 0", stops)
			}
		})
	}
}
