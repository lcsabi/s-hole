//go:build windows

// Package service integrates s-hole with the Windows Service Control
// Manager (SCM). It exposes install/uninstall/start/stop subcommands and
// the in-process SCM event loop. A no-op stub for non-Windows targets
// lives in svc_other.go so cmd/s-hole/main.go can call into the package without
// build tags.
package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	svcName = "s-hole"
	svcDesc = "Network-level DNS sinkhole for ad blocking."
)

// IsWindowsService reports whether the process was launched by the Windows SCM.
func IsWindowsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

// exitServeFailed is the service-specific exit code that s-hole reports to
// the SCM when the DNS server stops without a stop request. A non-zero code
// makes the SCM apply the recovery actions that Install sets.
const exitServeFailed = 1

// Run starts fn (the DNS server) in a goroutine and blocks in the Windows SCM
// event loop. stop (the ordered teardown) is called when the SCM sends a
// Stop or Shutdown control code, or when fn returns first.
func Run(fn func() error, stop func()) error {
	return svc.Run(svcName, &handler{fn: fn, stop: stop})
}

type handler struct {
	fn   func() error
	stop func()
}

func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}
	served := make(chan error, 1)
	go func() { served <- h.fn() }()
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				// doStop runs the ordered teardown and returns; it no longer
				// calls os.Exit (b/043). Report Stopped so the SCM does not
				// hang in StopPending, then return. After Execute returns,
				// svc.Run returns and main exits (b/044).
				h.stop()
				s <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case err := <-served:
			// The DNS server stopped without an SCM stop request, so the
			// service answers no queries. Before, the service still reported
			// Running (b/065). Run the teardown (a no-op if it already ran).
			s <- svc.Status{State: svc.StopPending}
			h.stop()
			if err == nil {
				// Only Shutdown makes Start return nil, so doStop already ran
				// outside the SCM loop: Go can deliver a Windows shutdown
				// event to main's signal handler as SIGTERM. A clean stop.
				return false, 0
			}
			// Return a failure code: svc.Run reports Stopped with it, and the
			// SCM restarts the service through the recovery actions that
			// Install sets.
			return true, exitServeFailed
		}
	}
}

// Install registers the binary as an auto-start Windows Service.
// configPath must be an absolute path.
func Install(configPath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(svcName); err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists. Run -service uninstall first", svcName)
	}

	s, err := m.CreateService(svcName, exePath, mgr.Config{
		DisplayName: "s-hole DNS Sinkhole",
		Description: svcDesc,
		StartType:   mgr.StartAutomatic,
	}, "-config", configPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	// Restart the service when it fails, like Restart=on-failure in the
	// systemd unit. By default the SCM applies recovery actions only when
	// the process crashes; the non-crash flag also applies them when the
	// service stops with a non-zero exit code, which is how Execute reports
	// a DNS server failure (b/065). The service runs without these actions,
	// so a failure to set them is a warning, not a failed install.
	if err := setRecovery(s); err != nil {
		fmt.Printf("warning: could not set restart-on-failure for service %q: %v\n", svcName, err)
	}
	s.Close()

	// Register an event-log source so Event Viewer renders s-hole's messages
	// without the "description cannot be found" preamble. The service still
	// runs and logs without this (against the default application source), so
	// a registration failure is a warning, not a fatal install error. An
	// already-registered source (a reinstall) is not an error.
	if err := eventlog.InstallAsEventCreate(svcName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		fmt.Printf("warning: could not register event-log source %q: %v\n", svcName, err)
	}

	fmt.Printf("service %q installed (auto-start)\n  binary: %s\n  config: %s\n", svcName, exePath, configPath)
	return nil
}

// recoveryResetSeconds is the time without a failure after which the SCM
// resets its failure count, so the next failure starts again at the first
// action.
const recoveryResetSeconds = 24 * 60 * 60

// setRecovery sets three restart actions, 5 seconds apart like the systemd
// unit's RestartSec, and turns them on for a non-zero exit code.
func setRecovery(s *mgr.Service) error {
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, recoveryResetSeconds); err != nil {
		return err
	}
	return s.SetRecoveryActionsOnNonCrashFailures(true)
}

// Uninstall removes the Windows Service registration.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %q not found: %w", svcName, err)
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	// Deregister the event-log source registered by Install. A missing source
	// (never registered, or a partial install) is not an error, so removal
	// stays idempotent.
	if err := eventlog.Remove(svcName); err != nil && !strings.Contains(err.Error(), "cannot find") {
		fmt.Printf("warning: could not remove event-log source %q: %v\n", svcName, err)
	}

	fmt.Printf("service %q uninstalled\n", svcName)
	return nil
}

// Start asks the SCM to start the service.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %q not found: %w", svcName, err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Printf("service %q started\n", svcName)
	return nil
}

// Stop sends a stop control to the running service.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %q not found: %w", svcName, err)
	}
	defer s.Close()

	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	fmt.Printf("service %q stop requested\n", svcName)
	return nil
}
