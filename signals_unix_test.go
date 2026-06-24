//go:build !windows

package main

import (
	"syscall"
	"testing"
)

func TestReloadSignals_IncludesSIGHUP(t *testing.T) {
	sigs := reloadSignals()
	found := false
	for _, s := range sigs {
		if s == syscall.SIGHUP {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("reloadSignals() = %v, want SIGHUP to be included", sigs)
	}
}

func TestIsReloadSignal(t *testing.T) {
	if !isReloadSignal(syscall.SIGHUP) {
		t.Error("isReloadSignal(SIGHUP) = false, want true")
	}
	if isReloadSignal(syscall.SIGINT) {
		t.Error("isReloadSignal(SIGINT) = true, want false")
	}
	if isReloadSignal(syscall.SIGTERM) {
		t.Error("isReloadSignal(SIGTERM) = true, want false")
	}
}
