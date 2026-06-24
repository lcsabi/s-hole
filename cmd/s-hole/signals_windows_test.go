//go:build windows

package main

import (
	"os"
	"testing"
)

func TestReloadSignals_EmptyOnWindows(t *testing.T) {
	if len(reloadSignals()) != 0 {
		t.Errorf("reloadSignals() on Windows = %v, want empty (SCM is the lifecycle gesture)", reloadSignals())
	}
}

func TestIsReloadSignal_FalseOnWindows(t *testing.T) {
	if isReloadSignal(os.Interrupt) {
		t.Error("isReloadSignal(os.Interrupt) = true on Windows; reload via /api/reload only")
	}
}
